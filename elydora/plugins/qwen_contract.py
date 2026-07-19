"""Qwen Code hook schema, commands, and exact ownership rules."""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import os
import shutil
import subprocess  # nosec B404
import sys
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple


AGENT_KEY = "qwen"
GUARD_SCRIPT = "guard.py"
AUDIT_SCRIPT = "hook.py"
HOOK_TIMEOUT_MILLISECONDS = 10_000
TOOL_EVENTS = ("PreToolUse", "PostToolUse")

_EVENT_NAMES = {
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "PostToolBatch",
    "Notification",
    "UserPromptSubmit",
    "UserPromptExpansion",
    "SessionStart",
    "Stop",
    "MessageDisplay",
    "SubagentStart",
    "SubagentStop",
    "PreCompact",
    "PostCompact",
    "SessionEnd",
    "PermissionRequest",
    "PermissionDenied",
    "StopFailure",
    "TodoCreated",
    "TodoCompleted",
    "InstructionsLoaded",
}
_CONFIG_FIELDS = {"enabled", "disabled", "notifications"}
_HANDLER_KEYS = {"command", "shell", "timeout", "type"}
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
QwenHookSettings = Dict[str, Any]


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


def elydora_dir() -> str:
    return os.path.join(os.path.expanduser("~"), ".elydora")


def _quote_posix(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _quote_powershell(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def build_command(script_path: str) -> str:
    if os.name == "nt":
        invocation = (
            f"{_quote_powershell(sys.executable)} {_quote_powershell(script_path)}"
        )
        return f"& {invocation}; exit $LASTEXITCODE"
    return f"{_quote_posix(sys.executable)} {_quote_posix(script_path)}"


def build_group(script_path: str) -> JsonObject:
    return {
        "matcher": "*",
        "hooks": [
            {
                "type": "command",
                "command": build_command(script_path),
                "shell": "powershell" if os.name == "nt" else "bash",
                "timeout": HOOK_TIMEOUT_MILLISECONDS,
            }
        ],
    }


def _optional_string(value: JsonObject, key: str, label: str) -> None:
    if key in value and not isinstance(value[key], str):
        raise ValueError(f'{label} field "{key}" must be a string')


def _optional_boolean(value: JsonObject, key: str, label: str) -> None:
    if key in value and not isinstance(value[key], bool):
        raise ValueError(f'{label} field "{key}" must be a boolean')


def _optional_string_map(value: JsonObject, key: str, label: str) -> None:
    if key not in value:
        return
    item = value[key]
    if not isinstance(item, dict) or any(
        not isinstance(entry, str) for entry in item.values()
    ):
        raise ValueError(f'{label} field "{key}" must contain string values')


def _validate_timeout(value: JsonObject, label: str) -> None:
    if "timeout" not in value:
        return
    timeout = value["timeout"]
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout < 0
    ):
        raise ValueError(f"{label} timeout must be a non-negative finite number")


def _validate_handler(value: Any, label: str) -> JsonObject:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    handler = dict(value)
    kind = handler.get("type")
    if kind not in {"command", "http", "prompt"}:
        raise ValueError(f'{label} type must be "command", "http", or "prompt"')
    _validate_timeout(handler, label)
    for key in ("name", "description", "statusMessage", "source"):
        _optional_string(handler, key, label)
    if kind == "command":
        if not isinstance(handler.get("command"), str) or not handler["command"]:
            raise ValueError(f"{label} command must be a non-empty string")
        _optional_string_map(handler, "env", label)
        _optional_boolean(handler, "async", label)
        if "shell" in handler and handler["shell"] not in {"bash", "powershell"}:
            raise ValueError(f'{label} shell must be "bash" or "powershell"')
    elif kind == "http":
        if not isinstance(handler.get("url"), str) or not handler["url"]:
            raise ValueError(f"{label} url must be a non-empty string")
        _optional_string_map(handler, "headers", label)
        _optional_boolean(handler, "once", label)
        _optional_string(handler, "if", label)
        allowed = handler.get("allowedEnvVars")
        if "allowedEnvVars" in handler and (
            not isinstance(allowed, list)
            or any(not isinstance(item, str) for item in allowed)
        ):
            raise ValueError(f"{label} allowedEnvVars must be an array of strings")
    else:
        if not isinstance(handler.get("prompt"), str) or not handler["prompt"]:
            raise ValueError(f"{label} prompt must be a non-empty string")
        _optional_string(handler, "model", label)
    return handler


def _validate_group(value: Any, label: str) -> JsonObject:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    group = dict(value)
    if "matcher" in group and not isinstance(group["matcher"], str):
        raise ValueError(f"{label} matcher must be a string")
    if "sequential" in group and not isinstance(group["sequential"], bool):
        raise ValueError(f"{label} sequential must be a boolean")
    handlers = group.get("hooks")
    if not isinstance(handlers, list):
        raise ValueError(f"{label} must contain a hooks array")
    group["hooks"] = [
        _validate_handler(handler, f"{label}.hooks[{index}]")
        for index, handler in enumerate(handlers)
    ]
    return group


def read_hook_settings(value: Any, label: str) -> QwenHookSettings:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    settings = dict(value)
    for event, groups in value.items():
        if event in _CONFIG_FIELDS:
            continue
        if event not in _EVENT_NAMES:
            raise ValueError(f'{label} contains unsupported field "{event}"')
        if not isinstance(groups, list):
            raise ValueError(f'{label} field "{event}" must be an array')
        settings[event] = [
            _validate_group(group, f'{label} field "{event}"[{index}]')
            for index, group in enumerate(groups)
        ]
    return settings


def _regex_entries(settings: QwenHookSettings) -> List[JsonObject]:
    entries = []
    for event, groups in settings.items():
        if event in _CONFIG_FIELDS:
            continue
        for index, group in enumerate(groups):
            matcher = group.get("matcher")
            if isinstance(matcher, str) and matcher.strip() not in {"", "*"}:
                entries.append(
                    {
                        "label": f'Qwen Code hooks field "{event}"[{index}] matcher',
                        "pattern": matcher,
                    }
                )
    return entries


def validate_javascript_regexes(settings: Sequence[QwenHookSettings]) -> None:
    entries = [entry for source in settings for entry in _regex_entries(source)]
    if not entries:
        return
    node_path = shutil.which("node")
    if node_path is None:
        raise FileNotFoundError(
            "Node.js runtime is required to validate Qwen Code hook expressions"
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
            "Qwen Code matcher validation timed out after "
            f"{_REGEX_TIMEOUT_SECONDS} seconds"
        ) from error
    except OSError as error:
        raise OSError(f"Run Node.js Qwen Code matcher validator: {error}") from error
    if result.returncode == 0:
        return
    message = (
        result.stderr.strip()
        or result.stdout.strip()
        or f"Node.js exited with code {result.returncode}"
    )
    raise ValueError(
        f"Qwen Code matcher must be a valid JavaScript regular expression: {message}"
    )


def _read_quoted_argument(command: str, start: int) -> Optional[Tuple[str, int]]:
    if start >= len(command) or command[start] != "'":
        return None
    value = ""
    index = start + 1
    while index < len(command):
        if os.name == "nt" and command[index : index + 2] == "''":
            value += "'"
            index += 2
            continue
        if os.name != "nt" and command[index : index + 5] == "'\"'\"'":
            value += "'"
            index += 5
            continue
        if command[index] == "'":
            return value, index + 1
        value += command[index]
        index += 1
    return None


def _parse_generated_command(command: str) -> Optional[Tuple[str, str]]:
    if os.name == "nt" and not command.startswith("& "):
        return None
    start = 2 if os.name == "nt" else 0
    executable = _read_quoted_argument(command, start)
    if executable is None or executable[1] >= len(command):
        return None
    if command[executable[1]] != " ":
        return None
    script = _read_quoted_argument(command, executable[1] + 1)
    if script is None:
        return None
    suffix = "; exit $LASTEXITCODE" if os.name == "nt" else ""
    if command[script[1] :] != suffix or not executable[0] or not script[0]:
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
    expected_shell = "powershell" if os.name == "nt" else "bash"
    if (
        handler.get("type") != "command"
        or handler.get("timeout") != HOOK_TIMEOUT_MILLISECONDS
        or handler.get("shell") != expected_shell
        or not isinstance(handler.get("command"), str)
    ):
        return None
    parsed = _parse_generated_command(handler["command"])
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
    return (
        set(group) == _GROUP_KEYS
        and group.get("matcher") == "*"
        and bool(indexes)
        and len(indexes) == len(group["hooks"])
    )


def managed_removals(
    settings: QwenHookSettings,
    agent_id: Optional[str] = None,
) -> List[ManagedRemoval]:
    removals = []
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
                removals.append(
                    ManagedRemoval(
                        event,
                        group_index,
                        indexes,
                        _exact_owned_group(group, indexes),
                    )
                )
    return removals


def _managed_ids(groups: List[JsonObject], script_name: str) -> Set[str]:
    return {
        agent_id
        for group in groups
        for handler in group["hooks"]
        if (agent_id := managed_agent_id(handler, script_name)) is not None
    }


def runtime_contracts(settings: QwenHookSettings) -> List[RuntimeContract]:
    guards = _managed_ids(settings.get("PreToolUse", []), GUARD_SCRIPT)
    audits = _managed_ids(settings.get("PostToolUse", []), AUDIT_SCRIPT)
    contracts = []
    for agent_id in sorted(guards, key=os.path.normcase):
        if any(same_agent_id(agent_id, audit_id) for audit_id in audits):
            root = os.path.join(elydora_dir(), agent_id)
            contracts.append(
                RuntimeContract(
                    agent_id,
                    os.path.join(root, GUARD_SCRIPT),
                    os.path.join(root, AUDIT_SCRIPT),
                )
            )
    return contracts
