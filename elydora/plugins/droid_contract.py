"""Factory Droid hook schema, command construction, and ownership rules."""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import os
import shutil
import subprocess  # nosec B404
import sys
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple


AGENT_KEY = "droid"
GUARD_SCRIPT = "guard.py"
AUDIT_SCRIPT = "hook.py"
HOOK_TIMEOUT_SECONDS = 10
TOOL_EVENTS = ("PreToolUse", "PostToolUse")

_EVENT_NAMES = {
    "PreToolUse",
    "PostToolUse",
    "Notification",
    "UserPromptSubmit",
    "Stop",
    "SubagentStop",
    "PreCompact",
    "SessionStart",
    "SessionEnd",
}
_FLAG_NAMES = {"hooksDisabled", "showHookOutput"}
_HANDLER_KEYS = {"command", "timeout", "type"}
_GROUP_KEYS = {"hooks", "matcher"}
_REGEX_TIMEOUT_SECONDS = 10
_REGEX_VALIDATOR = """import fs from 'node:fs';
const entries = JSON.parse(fs.readFileSync(0, 'utf8'));
for (const entry of entries) {
  try {
    new RegExp(entry.pattern);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(entry.label + ': ' + message);
    process.exit(1);
  }
}
"""

JsonObject = Dict[str, Any]
DroidHookSettings = Dict[str, Any]


@dataclass(frozen=True)
class RuntimeContract:
    agent_id: str
    guard_path: str
    audit_path: str


@dataclass(frozen=True)
class ManagedRemoval:
    event: str
    group_index: int
    handler_indexes: Tuple[int, ...]
    remove_group: bool


def is_object(value: Any) -> bool:
    return isinstance(value, dict)


def has_own(value: JsonObject, key: str) -> bool:
    return key in value


def elydora_dir() -> str:
    return os.path.join(os.path.expanduser("~"), ".elydora")


def _quote_windows(value: str) -> str:
    return '"' + value.replace('"', '\\"') + '"'


def _quote_posix(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def build_command(script_path: str) -> str:
    quote = _quote_windows if os.name == "nt" else _quote_posix
    return f"{quote(sys.executable)} {quote(script_path)}"


def build_group(script_path: str) -> JsonObject:
    return {
        "matcher": "*",
        "hooks": [{
            "type": "command",
            "command": build_command(script_path),
            "timeout": HOOK_TIMEOUT_SECONDS,
        }],
    }


def _validate_handler(value: Any, label: str) -> JsonObject:
    if not is_object(value):
        raise ValueError(f"{label} must be an object")
    handler = dict(value)
    if handler.get("type") != "command":
        raise ValueError(f'{label} type must be "command"')
    if not isinstance(handler.get("command"), str):
        raise ValueError(f"{label} command must be a string")
    timeout = handler.get("timeout")
    if timeout is not None and (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
    ):
        raise ValueError(f"{label} timeout must be a finite number")
    return handler


def _validate_group(value: Any, label: str) -> JsonObject:
    if not is_object(value):
        raise ValueError(f"{label} must be an object")
    group = dict(value)
    matcher = group.get("matcher")
    if "matcher" in group and not isinstance(matcher, str):
        raise ValueError(f"{label} matcher must be a string")
    command_regex = group.get("commandRegex")
    if "commandRegex" in group and not isinstance(command_regex, str):
        raise ValueError(f"{label} commandRegex must be a string")
    handlers = group.get("hooks")
    if not isinstance(handlers, list):
        raise ValueError(f"{label} must contain a hooks array")
    group["hooks"] = [
        _validate_handler(handler, f"{label}.hooks[{index}]")
        for index, handler in enumerate(handlers)
    ]
    return group


def read_hook_settings(value: Any, label: str) -> DroidHookSettings:
    if not is_object(value):
        raise ValueError(f"{label} must contain a JSON object")
    settings: DroidHookSettings = dict(value)
    for key, item in value.items():
        if key in _FLAG_NAMES:
            if not isinstance(item, bool):
                raise ValueError(f'{label} field "{key}" must be a boolean')
            continue
        if key not in _EVENT_NAMES:
            raise ValueError(f'{label} contains unsupported field "{key}"')
        if not isinstance(item, list):
            raise ValueError(f'{label} field "{key}" must be an array')
        settings[key] = [
            _validate_group(group, f'{label} field "{key}"[{index}]')
            for index, group in enumerate(item)
        ]
    return settings


def _regex_entries(settings: DroidHookSettings) -> List[JsonObject]:
    entries: List[JsonObject] = []
    for event, groups in settings.items():
        if event in _FLAG_NAMES:
            continue
        for index, group in enumerate(groups):
            matcher = group.get("matcher")
            if isinstance(matcher, str) and matcher not in {"", "*"}:
                entries.append({
                    "label": f'Factory Droid hooks field "{event}"[{index}] matcher',
                    "pattern": matcher,
                })
            command_regex = group.get("commandRegex")
            if isinstance(command_regex, str):
                entries.append({
                    "label": (
                        f'Factory Droid hooks field "{event}"[{index}] commandRegex'
                    ),
                    "pattern": command_regex,
                })
    return entries


def validate_javascript_regexes(settings: Sequence[DroidHookSettings]) -> None:
    entries = [entry for source in settings for entry in _regex_entries(source)]
    if not entries:
        return
    node_path = shutil.which("node")
    if node_path is None:
        raise FileNotFoundError(
            "Node.js runtime is required to validate Factory Droid hook expressions"
        )
    try:
        result = subprocess.run(  # nosec B603
            [node_path, "--input-type=module", "--eval", _REGEX_VALIDATOR],
            input=json.dumps(entries),
            text=True,
            capture_output=True,
            check=False,
            timeout=_REGEX_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise TimeoutError(
            "Factory Droid hook expression validation timed out after "
            f"{_REGEX_TIMEOUT_SECONDS} seconds"
        ) from error
    except OSError as error:
        raise OSError(f"Run Node.js Factory Droid matcher validator: {error}") from error
    if result.returncode == 0:
        return
    message = (
        result.stderr.strip()
        or result.stdout.strip()
        or f"Node.js exited with code {result.returncode}"
    )
    raise ValueError(
        "Factory Droid matcher must be a valid JavaScript regular expression: "
        f"{message}"
    )


def _read_windows_argument(command: str, start: int) -> Optional[Tuple[str, int]]:
    if start >= len(command) or command[start] != '"':
        return None
    value = ""
    index = start + 1
    while index < len(command):
        if command[index:index + 2] == '\\"':
            value += '"'
            index += 2
            continue
        if command[index] == '"':
            return value, index + 1
        value += command[index]
        index += 1
    return None


_POSIX_APOSTROPHE = "'\"'\"'"


def _read_posix_argument(command: str, start: int) -> Optional[Tuple[str, int]]:
    if start >= len(command) or command[start] != "'":
        return None
    value = ""
    index = start + 1
    while index < len(command):
        if command.startswith(_POSIX_APOSTROPHE, index):
            value += "'"
            index += len(_POSIX_APOSTROPHE)
            continue
        if command[index] == "'":
            return value, index + 1
        value += command[index]
        index += 1
    return None


def _parse_generated_command(command: str) -> Optional[Tuple[str, str]]:
    reader = _read_windows_argument if os.name == "nt" else _read_posix_argument
    executable = reader(command, 0)
    if executable is None or executable[1] >= len(command):
        return None
    if command[executable[1]] != " ":
        return None
    script = reader(command, executable[1] + 1)
    if script is None or script[1] != len(command):
        return None
    if not executable[0] or not script[0]:
        return None
    return executable[0], script[0]


def _same_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(
        os.path.abspath(right)
    )


def same_agent_id(left: str, right: str) -> bool:
    return os.path.normcase(left) == os.path.normcase(right)


def managed_agent_id(handler: JsonObject, script_name: str) -> Optional[str]:
    if set(handler) != _HANDLER_KEYS:
        return None
    if handler.get("type") != "command" or handler.get("timeout") != 10:
        return None
    command = handler.get("command")
    if not isinstance(command, str):
        return None
    parsed = _parse_generated_command(command)
    if parsed is None or not _same_path(parsed[0], sys.executable):
        return None
    script_path = parsed[1]
    if os.path.basename(script_path) != script_name:
        return None
    agent_directory = os.path.dirname(script_path)
    if not _same_path(os.path.dirname(agent_directory), elydora_dir()):
        return None
    agent_id = os.path.basename(agent_directory)
    return agent_id if agent_id not in {"", ".", ".."} else None


def _exact_owned_group(group: JsonObject, indexes: Tuple[int, ...]) -> bool:
    hooks = group["hooks"]
    return (
        set(group) == _GROUP_KEYS
        and group.get("matcher") == "*"
        and bool(indexes)
        and len(indexes) == len(hooks)
    )


def managed_removals(
    settings: DroidHookSettings,
    agent_id: Optional[str] = None,
) -> List[ManagedRemoval]:
    removals: List[ManagedRemoval] = []
    for event, script_name in (
        ("PreToolUse", GUARD_SCRIPT),
        ("PostToolUse", AUDIT_SCRIPT),
    ):
        for group_index, group in enumerate(settings.get(event, [])):
            indexes = tuple(
                index
                for index, handler in enumerate(group["hooks"])
                if (
                    (managed_id := managed_agent_id(handler, script_name)) is not None
                    and (agent_id is None or same_agent_id(managed_id, agent_id))
                )
            )
            if indexes:
                removals.append(ManagedRemoval(
                    event,
                    group_index,
                    indexes,
                    _exact_owned_group(group, indexes),
                ))
    return removals


def _managed_ids(groups: List[JsonObject], script_name: str) -> Set[str]:
    return {
        agent_id
        for group in groups
        for handler in group["hooks"]
        if (agent_id := managed_agent_id(handler, script_name)) is not None
    }


def runtime_contracts(settings: DroidHookSettings) -> List[RuntimeContract]:
    guards = _managed_ids(settings.get("PreToolUse", []), GUARD_SCRIPT)
    audits = _managed_ids(settings.get("PostToolUse", []), AUDIT_SCRIPT)
    contracts = []
    for agent_id in sorted(guards):
        if not any(same_agent_id(agent_id, audit_id) for audit_id in audits):
            continue
        root = os.path.join(elydora_dir(), agent_id)
        contracts.append(RuntimeContract(
            agent_id,
            os.path.join(root, GUARD_SCRIPT),
            os.path.join(root, AUDIT_SCRIPT),
        ))
    return contracts


def merge_hook_settings(
    primary: Optional[DroidHookSettings],
    fallback: Optional[DroidHookSettings],
) -> DroidHookSettings:
    return {**(fallback or {}), **(primary or {})}
