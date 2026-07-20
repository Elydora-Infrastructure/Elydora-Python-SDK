"""Qwen Code 0.20 hook schema and exact ownership rules."""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import os
import shutil
import subprocess  # nosec B404
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .qwen_command import (
    QwenRuntimeReference,
    build_qwen_command,
    qwen_runtime_reference,
    same_qwen_agent_id,
    same_qwen_path,
)


AGENT_KEY = "qwen"
GUARD_SCRIPT = "guard.py"
AUDIT_SCRIPT = "hook.py"
GUARD_HOOK_NAME = "elydora-guard"
AUDIT_HOOK_NAME = "elydora-audit"
HOOK_TIMEOUT_MILLISECONDS = 10_000
MANAGED_EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure")

KNOWN_EVENTS = {
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

REGEX_MATCHER_EVENTS = {
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "PermissionRequest",
    "PermissionDenied",
    "SubagentStart",
    "SubagentStop",
    "PreCompact",
    "PostCompact",
    "SessionStart",
    "SessionEnd",
    "StopFailure",
    "Notification",
    "InstructionsLoaded",
    "UserPromptExpansion",
}

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
QwenHooks = Dict[str, Any]


@dataclass(frozen=True)
class QwenRuntimeContract:
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


def _optional_string(value: JsonObject, field: str, label: str) -> None:
    if field in value and not isinstance(value[field], str):
        raise ValueError(f'{label} field "{field}" must be a string')


def _optional_boolean(value: JsonObject, field: str, label: str) -> None:
    if field in value and not isinstance(value[field], bool):
        raise ValueError(f'{label} field "{field}" must be a boolean')


def _optional_string_map(value: JsonObject, field: str, label: str) -> None:
    if field not in value:
        return
    item = value[field]
    if not isinstance(item, dict) or any(
        not isinstance(entry, str) for entry in item.values()
    ):
        raise ValueError(f'{label} field "{field}" must map names to strings')


def _validate_timeout(value: JsonObject, label: str) -> None:
    if "timeout" not in value:
        return
    timeout = value["timeout"]
    try:
        finite = math.isfinite(timeout)
    except (TypeError, OverflowError):
        finite = False
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not finite:
        raise ValueError(f"{label} timeout must be a non-negative finite number")
    if timeout < 0:
        raise ValueError(f"{label} timeout must be a non-negative finite number")


def _validate_handler(value: Any, label: str) -> JsonObject:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    handler = dict(value)
    kind = handler.get("type")
    if kind not in {"command", "http", "prompt"}:
        raise ValueError(f'{label} has unsupported type "{kind}"')
    _validate_timeout(handler, label)
    for field in ("name", "description", "statusMessage", "source"):
        _optional_string(handler, field, label)
    if kind == "command":
        if not isinstance(handler.get("command"), str) or not handler["command"]:
            raise ValueError(f"{label} requires a non-empty command")
        _optional_string_map(handler, "env", label)
        _optional_boolean(handler, "async", label)
        if "shell" in handler and handler["shell"] not in {"bash", "powershell"}:
            raise ValueError(f'{label} shell must be "bash" or "powershell"')
    elif kind == "http":
        if not isinstance(handler.get("url"), str) or not handler["url"]:
            raise ValueError(f"{label} requires a non-empty url")
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
            raise ValueError(f"{label} requires a non-empty prompt")
        _optional_string(handler, "model", label)
    return handler


def _validate_group(value: Any, event: str, index: int) -> JsonObject:
    label = f"Qwen Code settings group hooks.{event}[{index}]"
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
        _validate_handler(handler, f"{label}.hooks[{handler_index}]")
        for handler_index, handler in enumerate(handlers)
    ]
    return group


def read_qwen_hooks(value: Any) -> QwenHooks:
    if not isinstance(value, dict):
        raise ValueError('Qwen Code settings field "hooks" must be an object')
    hooks: QwenHooks = {}
    for event, groups in value.items():
        if event not in KNOWN_EVENTS:
            hooks[event] = groups
            continue
        if not isinstance(groups, list):
            raise ValueError(
                f'Qwen Code settings field "hooks.{event}" must be an array'
            )
        hooks[event] = [
            _validate_group(group, event, index)
            for index, group in enumerate(groups)
        ]
    return hooks


def _matcher_entries(sources: Sequence[QwenHooks]) -> List[JsonObject]:
    entries: List[JsonObject] = []
    for hooks in sources:
        for event in REGEX_MATCHER_EVENTS:
            for index, group in enumerate(hooks.get(event, [])):
                matcher = group.get("matcher")
                if isinstance(matcher, str) and matcher.strip() not in {"", "*"}:
                    entries.append({
                        "label": f"Qwen Code settings group hooks.{event}[{index}]",
                        "pattern": matcher,
                    })
    return entries


def validate_javascript_matchers(sources: Sequence[QwenHooks]) -> None:
    entries = _matcher_entries(sources)
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
        "Qwen Code matcher must be a valid JavaScript regular expression: "
        + message
    )


def build_qwen_group(script_path: str, name: str) -> JsonObject:
    return {
        "hooks": [{
            "type": "command",
            "name": name,
            "command": build_qwen_command(script_path),
            "shell": "powershell" if os.name == "nt" else "bash",
            "timeout": HOOK_TIMEOUT_MILLISECONDS,
        }]
    }


def _exact_current_group(group: JsonObject) -> bool:
    return set(group) == {"hooks"}


def _exact_legacy_group(group: JsonObject) -> bool:
    return set(group) == {"hooks", "matcher"} and group.get("matcher") == "*"


def _current_reference(
    handler: JsonObject, script_name: str, hook_name: str
) -> Optional[QwenRuntimeReference]:
    if (
        set(handler) == {"command", "name", "shell", "timeout", "type"}
        and handler.get("type") == "command"
        and handler.get("name") == hook_name
        and handler.get("shell") == ("powershell" if os.name == "nt" else "bash")
        and handler.get("timeout") == HOOK_TIMEOUT_MILLISECONDS
        and isinstance(handler.get("command"), str)
    ):
        return qwen_runtime_reference(handler["command"], script_name)
    return None


def _legacy_reference(
    handler: JsonObject, script_name: str
) -> Optional[QwenRuntimeReference]:
    if (
        set(handler) == {"command", "shell", "timeout", "type"}
        and handler.get("type") == "command"
        and handler.get("shell") == ("powershell" if os.name == "nt" else "bash")
        and handler.get("timeout") == HOOK_TIMEOUT_MILLISECONDS
        and isinstance(handler.get("command"), str)
    ):
        return qwen_runtime_reference(handler["command"], script_name)
    return None


def _managed_reference(
    handler: JsonObject,
    script_name: str,
    hook_name: str,
    include_legacy: bool,
) -> Optional[QwenRuntimeReference]:
    current = _current_reference(handler, script_name, hook_name)
    if current is not None or not include_legacy:
        return current
    return _legacy_reference(handler, script_name)


_EVENT_CONTRACTS = (
    ("PreToolUse", GUARD_SCRIPT, GUARD_HOOK_NAME),
    ("PostToolUse", AUDIT_SCRIPT, AUDIT_HOOK_NAME),
    ("PostToolUseFailure", AUDIT_SCRIPT, AUDIT_HOOK_NAME),
)


def managed_qwen_removals(
    hooks: QwenHooks, agent_id: Optional[str] = None
) -> List[ManagedRemoval]:
    removals: List[ManagedRemoval] = []
    for event, script_name, hook_name in _EVENT_CONTRACTS:
        for group_index, group in enumerate(hooks.get(event, [])):
            handlers = group["hooks"]
            indexes = tuple(
                index
                for index, handler in enumerate(handlers)
                if (
                    reference := _managed_reference(
                        handler, script_name, hook_name, True
                    )
                )
                is not None
                and (
                    agent_id is None
                    or same_qwen_agent_id(reference.agent_id, agent_id)
                )
            )
            if indexes:
                removals.append(ManagedRemoval(
                    event,
                    group_index,
                    indexes,
                    (_exact_current_group(group) or _exact_legacy_group(group))
                    and len(indexes) == len(handlers),
                ))
    return removals


def _references_for_event(
    groups: List[JsonObject], script_name: str, hook_name: str
) -> Dict[str, List[QwenRuntimeReference]]:
    references: Dict[str, List[QwenRuntimeReference]] = {}
    for group in groups:
        if not _exact_current_group(group):
            continue
        for handler in group["hooks"]:
            reference = _current_reference(handler, script_name, hook_name)
            if reference is None:
                continue
            key = os.path.normcase(reference.agent_id)
            references.setdefault(key, []).append(reference)
    return references


def qwen_runtime_contracts(hooks: QwenHooks) -> List[QwenRuntimeContract]:
    guards = _references_for_event(
        hooks.get("PreToolUse", []), GUARD_SCRIPT, GUARD_HOOK_NAME
    )
    posts = _references_for_event(
        hooks.get("PostToolUse", []), AUDIT_SCRIPT, AUDIT_HOOK_NAME
    )
    failures = _references_for_event(
        hooks.get("PostToolUseFailure", []), AUDIT_SCRIPT, AUDIT_HOOK_NAME
    )
    contracts: List[QwenRuntimeContract] = []
    for key, guard in guards.items():
        post = posts.get(key, [])
        failure = failures.get(key, [])
        if len(guard) != 1 or len(post) != 1 or len(failure) != 1:
            continue
        if not same_qwen_path(post[0].script_path, failure[0].script_path):
            continue
        contracts.append(QwenRuntimeContract(
            guard[0].agent_id,
            guard[0].script_path,
            post[0].script_path,
        ))
    return contracts
