"""Claude Code hook schema, ownership, and rendering."""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse

from ._strict_json import JsonObject, parse_json_object


AGENT_KEY = "claudecode"
CONFIG_FILE = "settings.json"
GUARD_SCRIPT = "guard.py"
AUDIT_SCRIPT = "hook.py"
HOOK_TIMEOUT_SECONDS = 10
GUARD_STATUS = "Checking Elydora agent state"
AUDIT_STATUS = "Recording Elydora tool use"

HOOK_EVENTS = frozenset({
    "SessionStart", "Setup", "InstructionsLoaded", "UserPromptSubmit",
    "UserPromptExpansion", "MessageDisplay", "PreToolUse",
    "PermissionRequest", "PostToolUse", "PostToolUseFailure",
    "PostToolBatch", "PermissionDenied", "Notification", "SubagentStart",
    "SubagentStop", "TaskCreated", "TaskCompleted", "Stop", "StopFailure",
    "TeammateIdle", "ConfigChange", "CwdChanged", "FileChanged",
    "WorktreeCreate", "WorktreeRemove", "PreCompact", "PostCompact",
    "SessionEnd", "Elicitation", "ElicitationResult",
})
COMMON_HANDLER_KEYS = frozenset({"if", "once", "statusMessage", "timeout"})
HANDLER_KEYS = {
    "command": COMMON_HANDLER_KEYS | {
        "args", "async", "asyncRewake", "command", "shell", "type",
    },
    "prompt": COMMON_HANDLER_KEYS | {
        "continueOnBlock", "model", "prompt", "type",
    },
    "agent": COMMON_HANDLER_KEYS | {"model", "prompt", "type"},
    "http": COMMON_HANDLER_KEYS | {
        "allowedEnvVars", "headers", "type", "url",
    },
    "mcp_tool": COMMON_HANDLER_KEYS | {"input", "server", "tool", "type"},
}
_UNSET = object()

ClaudeHooks = Dict[str, List[JsonObject]]


@dataclass(frozen=True)
class ClaudeDocument:
    exists: bool
    file_path: str
    root: JsonObject
    hooks: ClaudeHooks
    hooks_disabled: bool
    raw: Optional[str] = None


@dataclass(frozen=True)
class RenderedClaudeDocument:
    document: ClaudeDocument
    changed: bool
    next_source: Optional[str] = None


@dataclass(frozen=True)
class ClaudeRuntimeContract:
    agent_id: str
    guard_path: str
    audit_path: str


@dataclass(frozen=True)
class _RuntimeReference:
    agent_id: str
    script_path: str


def runtime_root() -> str:
    return os.path.join(os.path.expanduser("~"), ".elydora")


def same_claude_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(
        os.path.abspath(right)
    )


def same_claude_agent_id(left: str, right: str) -> bool:
    return os.path.normcase(left) == os.path.normcase(right)


def _require_known_keys(
    value: JsonObject, allowed: frozenset[str], label: str
) -> None:
    extra = next((key for key in value if key not in allowed), None)
    if extra is not None:
        raise ValueError(f'{label} contains unsupported field "{extra}"')


def _require_non_empty_string(value: Any, field: str, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f'{label} field "{field}" must be a non-empty string')
    return value


def _optional_string(value: JsonObject, field: str, label: str) -> None:
    if field in value and not isinstance(value[field], str):
        raise ValueError(f'{label} field "{field}" must be a string')


def _optional_boolean(value: JsonObject, field: str, label: str) -> None:
    if field in value and type(value[field]) is not bool:
        raise ValueError(f'{label} field "{field}" must be a boolean')


def _validate_common_fields(value: JsonObject, label: str) -> None:
    _optional_string(value, "if", label)
    _optional_string(value, "statusMessage", label)
    _optional_boolean(value, "once", label)
    timeout = value.get("timeout")
    if "timeout" in value and (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(float(timeout))
        or float(timeout) <= 0
    ):
        raise ValueError(f"{label} timeout must be a positive finite number")


def _string_array(value: Any, field: str, label: str) -> List[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) for item in value
    ):
        raise ValueError(f'{label} field "{field}" must be an array of strings')
    return value


def _validate_handler(
    value: Any, event: str, group_index: int, handler_index: int
) -> JsonObject:
    label = (
        f"Claude Code settings handler hooks.{event}[{group_index}]"
        f".hooks[{handler_index}]"
    )
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    handler = dict(value)
    handler_type = handler.get("type")
    if not isinstance(handler_type, str) or handler_type not in HANDLER_KEYS:
        raise ValueError(f'{label} has unsupported type "{handler_type}"')
    _require_known_keys(handler, HANDLER_KEYS[handler_type], label)
    _validate_common_fields(handler, label)
    if handler_type == "command":
        _require_non_empty_string(handler.get("command"), "command", label)
        if "args" in handler:
            _string_array(handler["args"], "args", label)
        _optional_boolean(handler, "async", label)
        _optional_boolean(handler, "asyncRewake", label)
        if "shell" in handler and handler["shell"] not in ("bash", "powershell"):
            raise ValueError(
                f'{label} field "shell" must be "bash" or "powershell"'
            )
    elif handler_type in ("prompt", "agent"):
        _require_non_empty_string(handler.get("prompt"), "prompt", label)
        _optional_string(handler, "model", label)
        if handler_type == "prompt":
            _optional_boolean(handler, "continueOnBlock", label)
    elif handler_type == "http":
        raw_url = _require_non_empty_string(handler.get("url"), "url", label)
        try:
            parsed = urllib.parse.urlsplit(raw_url)
            hostname = parsed.hostname
            parsed.port
        except ValueError as error:
            raise ValueError(f'{label} field "url" must be a valid URL') from error
        if parsed.scheme not in ("http", "https") or hostname is None:
            raise ValueError(f'{label} field "url" must use HTTP or HTTPS')
        headers = handler.get("headers")
        if "headers" in handler and (
            not isinstance(headers, dict)
            or any(not isinstance(item, str) for item in headers.values())
        ):
            raise ValueError(f'{label} field "headers" must map names to strings')
        if "allowedEnvVars" in handler:
            allowed = _string_array(
                handler["allowedEnvVars"], "allowedEnvVars", label
            )
            if any(not item for item in allowed):
                raise ValueError(
                    f'{label} field "allowedEnvVars" must contain non-empty strings'
                )
    else:
        _require_non_empty_string(handler.get("server"), "server", label)
        _require_non_empty_string(handler.get("tool"), "tool", label)
        if "input" in handler and not isinstance(handler["input"], dict):
            raise ValueError(f'{label} field "input" must be an object')
    return handler


def _validate_group(value: Any, event: str, index: int) -> JsonObject:
    label = f"Claude Code settings matcher group hooks.{event}[{index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    group = dict(value)
    _require_known_keys(group, frozenset({"hooks", "matcher"}), label)
    if "matcher" in group and not isinstance(group["matcher"], str):
        raise ValueError(f"{label} matcher must be a string")
    handlers = group.get("hooks")
    if not isinstance(handlers, list):
        raise ValueError(f"{label} must contain a hooks array")
    group["hooks"] = [
        _validate_handler(handler, event, index, handler_index)
        for handler_index, handler in enumerate(handlers)
    ]
    return group


def _read_hooks(value: Any) -> ClaudeHooks:
    if value is _UNSET:
        return {}
    if not isinstance(value, dict):
        raise ValueError('Claude Code settings field "hooks" must be an object')
    hooks: ClaudeHooks = {}
    for event, groups in value.items():
        if event not in HOOK_EVENTS:
            raise ValueError(
                f'Claude Code settings contains unsupported hook event "{event}"'
            )
        if not isinstance(groups, list):
            raise ValueError(
                f'Claude Code settings field "hooks.{event}" must be an array'
            )
        hooks[event] = [
            _validate_group(group, event, index)
            for index, group in enumerate(groups)
        ]
    return hooks


def parse_claude_document(file_path: str, raw: str) -> ClaudeDocument:
    root = parse_json_object(raw, f"Claude Code user settings at {file_path}")
    disabled = root.get("disableAllHooks")
    if "disableAllHooks" in root and type(disabled) is not bool:
        raise ValueError(
            'Claude Code settings field "disableAllHooks" must be a boolean'
        )
    return ClaudeDocument(
        True,
        file_path,
        root,
        _read_hooks(root.get("hooks", _UNSET)),
        disabled is True,
        raw,
    )


def create_claude_document(file_path: str) -> ClaudeDocument:
    return ClaudeDocument(False, file_path, {}, {}, False)


def build_claude_group(script_path: str, status_message: str) -> JsonObject:
    return {
        "hooks": [{
            "type": "command",
            "command": sys.executable,
            "args": [script_path],
            "timeout": HOOK_TIMEOUT_SECONDS,
            "statusMessage": status_message,
        }]
    }


def _exact_managed_group(group: JsonObject) -> bool:
    return set(group) == {"hooks"}


def _runtime_reference(
    script_path: str, script_name: str
) -> Optional[_RuntimeReference]:
    if not os.path.isabs(script_path) or os.path.basename(script_path) != script_name:
        return None
    agent_directory = os.path.dirname(script_path)
    if not same_claude_path(os.path.dirname(agent_directory), runtime_root()):
        return None
    agent_id = os.path.basename(agent_directory)
    if agent_id in ("", ".", ".."):
        return None
    return _RuntimeReference(agent_id, script_path)


def _legacy_reference(
    command: Any, script_name: str
) -> Optional[_RuntimeReference]:
    if not isinstance(command, str):
        return None
    if script_name == AUDIT_SCRIPT:
        return _runtime_reference(command, script_name)
    match = re.fullmatch(r'"([^"\r\n]+)" ([^\r\n]+)', command)
    if (
        match is None
        or not os.path.isabs(match.group(1))
        or not same_claude_path(match.group(1), sys.executable)
    ):
        return None
    return _runtime_reference(match.group(2), script_name)


def _managed_reference(
    handler: JsonObject,
    script_name: str,
    status_message: str,
    include_legacy: bool = False,
) -> Optional[_RuntimeReference]:
    if (
        set(handler) == {"args", "command", "statusMessage", "timeout", "type"}
        and handler.get("type") == "command"
        and type(handler.get("timeout")) is int
        and handler.get("timeout") == HOOK_TIMEOUT_SECONDS
        and handler.get("statusMessage") == status_message
        and isinstance(handler.get("command"), str)
        and os.path.isabs(str(handler["command"]))
        and same_claude_path(str(handler["command"]), sys.executable)
        and isinstance(handler.get("args"), list)
        and len(handler["args"]) == 1
        and isinstance(handler["args"][0], str)
    ):
        return _runtime_reference(handler["args"][0], script_name)
    if (
        include_legacy
        and set(handler) == {"command", "type"}
        and handler.get("type") == "command"
    ):
        return _legacy_reference(handler.get("command"), script_name)
    return None


def _remove_from_groups(
    groups: List[JsonObject],
    script_name: str,
    status_message: str,
    agent_id: str,
) -> Tuple[List[JsonObject], bool]:
    result: List[JsonObject] = []
    removed = False
    for group in groups:
        kept = []
        for handler in group["hooks"]:
            reference = _managed_reference(
                handler, script_name, status_message, True
            )
            owned = reference is not None and (
                not agent_id
                or same_claude_agent_id(reference.agent_id, agent_id)
            )
            if owned:
                removed = True
            else:
                kept.append(handler)
        if kept:
            result.append({**group, "hooks": kept})
        elif not _exact_managed_group(group):
            result.append({**group, "hooks": []})
    return result, removed


def remove_managed_claude_hooks(
    hooks: ClaudeHooks, agent_id: str = ""
) -> ClaudeHooks:
    result = {event: list(groups) for event, groups in hooks.items()}
    for event, script_name, status_message in (
        ("PreToolUse", GUARD_SCRIPT, GUARD_STATUS),
        ("PostToolUse", AUDIT_SCRIPT, AUDIT_STATUS),
        ("PostToolUseFailure", AUDIT_SCRIPT, AUDIT_STATUS),
    ):
        groups, removed = _remove_from_groups(
            result.get(event, []), script_name, status_message, agent_id
        )
        if not removed:
            continue
        if groups:
            result[event] = groups
        else:
            result.pop(event, None)
    return result


def _managed_event(event: str) -> Optional[Tuple[str, str]]:
    if event == "PreToolUse":
        return GUARD_SCRIPT, GUARD_STATUS
    if event in ("PostToolUse", "PostToolUseFailure"):
        return AUDIT_SCRIPT, AUDIT_STATUS
    return None


def _entirely_managed(document: ClaudeDocument) -> bool:
    if not document.exists or set(document.root) != {"hooks"} or not document.hooks:
        return False
    handlers = 0
    for event, groups in document.hooks.items():
        contract = _managed_event(event)
        if contract is None or not groups:
            return False
        for group in groups:
            if (
                not _exact_managed_group(group)
                or not group["hooks"]
                or any(
                    _managed_reference(handler, contract[0], contract[1], True)
                    is None
                    for handler in group["hooks"]
                )
            ):
                return False
            handlers += len(group["hooks"])
    return handlers > 0


def render_claude_document(
    document: ClaudeDocument, hooks: ClaudeHooks
) -> RenderedClaudeDocument:
    if hooks == document.hooks:
        return RenderedClaudeDocument(document, False)
    if not document.exists and not hooks:
        return RenderedClaudeDocument(document, False)
    if not hooks and _entirely_managed(document):
        return RenderedClaudeDocument(document, True)
    root = dict(document.root)
    if hooks:
        root["hooks"] = hooks
    else:
        root.pop("hooks", None)
    next_source = json.dumps(root, indent=2, ensure_ascii=False) + "\n"
    parse_claude_document(document.file_path, next_source)
    return RenderedClaudeDocument(
        document, next_source != document.raw, next_source
    )


def _references_for_event(
    groups: List[JsonObject], script_name: str, status_message: str
) -> Dict[str, List[_RuntimeReference]]:
    result: Dict[str, List[_RuntimeReference]] = {}
    for group in groups:
        if not _exact_managed_group(group):
            continue
        for handler in group["hooks"]:
            reference = _managed_reference(handler, script_name, status_message)
            if reference is not None:
                result.setdefault(
                    os.path.normcase(reference.agent_id), []
                ).append(reference)
    return result


def claude_runtime_contracts(
    hooks: ClaudeHooks,
) -> List[ClaudeRuntimeContract]:
    guards = _references_for_event(
        hooks.get("PreToolUse", []), GUARD_SCRIPT, GUARD_STATUS
    )
    successes = _references_for_event(
        hooks.get("PostToolUse", []), AUDIT_SCRIPT, AUDIT_STATUS
    )
    failures = _references_for_event(
        hooks.get("PostToolUseFailure", []), AUDIT_SCRIPT, AUDIT_STATUS
    )
    contracts = []
    for key, guard in guards.items():
        success = successes.get(key, [])
        failure = failures.get(key, [])
        if len(guard) != 1 or len(success) != 1 or len(failure) != 1:
            continue
        if not same_claude_path(success[0].script_path, failure[0].script_path):
            continue
        contracts.append(ClaudeRuntimeContract(
            guard[0].agent_id,
            guard[0].script_path,
            success[0].script_path,
        ))
    return contracts
