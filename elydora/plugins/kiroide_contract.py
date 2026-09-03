"""Kiro IDE v1 hook schema, ownership, and rendering."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from typing import Any, Callable, Dict, List, Optional, Tuple

from ._managed_files import FileSnapshot
from ._runtime import same_agent_id, same_path
from ._strict_json import JsonObject, parse_json_object
from .kiroide_command import (
    KiroIdeRuntimeReference,
    build_kiroide_command,
    kiroide_runtime_reference,
    legacy_audit_reference,
    legacy_guard_reference,
    owned_kiroide_runtime_reference,
)


AGENT_KEY = "kiroide"
AUDIT_SCRIPT = "hook.py"
CONFIG_FILE = "elydora-audit.json"
GUARD_SCRIPT = "guard.py"
LEGACY_CONFIG_FILE = "elydora-audit.kiro.hook"
HOOK_TIMEOUT_SECONDS = 10

GUARD_NAME = "elydora-guard"
AUDIT_NAME = "elydora-audit"
GUARD_DESCRIPTION = "Block tool use when the Elydora agent is frozen"
AUDIT_DESCRIPTION = "Record tool use in the Elydora audit trail"
KIRO_TRIGGERS = frozenset(
    {
        "SessionStart",
        "Stop",
        "PreToolUse",
        "PostToolUse",
        "PreTaskExec",
        "PostTaskExec",
        "UserPromptSubmit",
        "PostFileCreate",
        "PostFileSave",
        "PostFileDelete",
    }
)


@dataclass(frozen=True)
class KiroIdeDocument:
    exists: bool
    file_path: str
    root: JsonObject
    hooks: List[JsonObject]
    raw: Optional[str] = None
    snapshot: Optional[FileSnapshot] = None


@dataclass(frozen=True)
class RenderedKiroIdeDocument:
    document: KiroIdeDocument
    changed: bool
    next_source: Optional[str] = None


@dataclass(frozen=True)
class KiroIdeRuntimeContract:
    agent_id: str
    guard_path: str
    audit_path: str


def _validate_action(value: Any, label: str) -> JsonObject:
    if not isinstance(value, dict):
        raise ValueError(f"{label} action must be an object")
    action = dict(value)
    action_type = action.get("type")
    if action_type == "command":
        if not isinstance(action.get("command"), str) or not action["command"]:
            raise ValueError(f"{label} command action requires a non-empty command")
        return action
    if action_type == "agent":
        if not isinstance(action.get("prompt"), str) or not action["prompt"]:
            raise ValueError(f"{label} agent action requires a non-empty prompt")
        return action
    raise ValueError(f'{label} action has unsupported type "{action_type}"')


def _validate_hook(value: Any, index: int, document_label: str) -> JsonObject:
    label = f"{document_label} hooks[{index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    hook = dict(value)
    if not isinstance(hook.get("name"), str) or not hook["name"]:
        raise ValueError(f"{label} requires a name")
    trigger = hook.get("trigger")
    if not isinstance(trigger, str) or trigger not in KIRO_TRIGGERS:
        raise ValueError(f'{label} has unsupported trigger "{trigger}"')
    if "description" in hook and not isinstance(hook["description"], str):
        raise ValueError(f"{label} description must be a string")
    if "matcher" in hook and not isinstance(hook["matcher"], str):
        raise ValueError(f"{label} matcher must be a string")
    if "timeout" in hook and (
        type(hook["timeout"]) is not int or hook["timeout"] < 0
    ):
        raise ValueError(f"{label} timeout must be a non-negative integer")
    if "enabled" in hook and not isinstance(hook["enabled"], bool):
        raise ValueError(f"{label} enabled must be a boolean")
    hook["action"] = _validate_action(hook.get("action"), label)
    return hook


def parse_kiroide_document(
    file_path: str,
    raw: str,
    snapshot: Optional[FileSnapshot] = None,
    document_label: str = "Kiro IDE hooks",
) -> KiroIdeDocument:
    root = parse_json_object(raw, f"{document_label} at {file_path}")
    if root.get("version") != "v1":
        raise ValueError(f'{document_label} version must be "v1": {file_path}')
    hooks = root.get("hooks")
    if not isinstance(hooks, list):
        raise ValueError(
            f'{document_label} field "hooks" must be an array: {file_path}'
        )
    return KiroIdeDocument(
        True,
        file_path,
        root,
        [_validate_hook(hook, index, document_label) for index, hook in enumerate(hooks)],
        raw,
        snapshot,
    )


def create_kiroide_document(file_path: str) -> KiroIdeDocument:
    return KiroIdeDocument(False, file_path, {}, [])


def _managed_specification(name: object) -> Optional[Tuple[str, str, str]]:
    if name == GUARD_NAME:
        return GUARD_DESCRIPTION, "PreToolUse", GUARD_SCRIPT
    if name == AUDIT_NAME:
        return AUDIT_DESCRIPTION, "PostToolUse", AUDIT_SCRIPT
    return None


def _command_reference(
    hook: JsonObject, current_executable: bool
) -> Optional[KiroIdeRuntimeReference]:
    specification = _managed_specification(hook.get("name"))
    action = hook.get("action")
    if (
        specification is None
        or not isinstance(action, dict)
        or action.get("type") != "command"
        or not isinstance(action.get("command"), str)
    ):
        return None
    reader = (
        kiroide_runtime_reference
        if current_executable
        else owned_kiroide_runtime_reference
    )
    return reader(action["command"], specification[2])


def _owned_reference(hook: JsonObject) -> Optional[KiroIdeRuntimeReference]:
    return _command_reference(hook, False)


def _exact_reference(
    hook: JsonObject, current_executable: bool
) -> Optional[KiroIdeRuntimeReference]:
    specification = _managed_specification(hook.get("name"))
    reference = _command_reference(hook, current_executable)
    action = hook.get("action")
    if (
        specification is None
        or reference is None
        or set(hook)
        != {
            "name",
            "description",
            "trigger",
            "matcher",
            "action",
            "timeout",
            "enabled",
        }
        or hook.get("description") != specification[0]
        or hook.get("trigger") != specification[1]
        or hook.get("matcher") != ".*"
        or hook.get("timeout") != HOOK_TIMEOUT_SECONDS
        or hook.get("enabled") is not True
        or not isinstance(action, dict)
        or set(action) != {"type", "command"}
    ):
        return None
    return reference


def _managed_reference(hook: JsonObject) -> Optional[KiroIdeRuntimeReference]:
    return _exact_reference(hook, True)


def _portable_managed_reference(
    hook: JsonObject,
) -> Optional[KiroIdeRuntimeReference]:
    return _exact_reference(hook, False)


_ReferenceReader = Callable[
    [JsonObject], Optional[KiroIdeRuntimeReference]
]


def _managed_pair(
    hooks: List[JsonObject], reader: _ReferenceReader
) -> Optional[
    Tuple[
        Tuple[int, KiroIdeRuntimeReference],
        Tuple[int, KiroIdeRuntimeReference],
    ]
]:
    managed = [
        (index, hook)
        for index, hook in enumerate(hooks)
        if _managed_specification(hook.get("name")) is not None
    ]
    guards = [item for item in managed if item[1].get("name") == GUARD_NAME]
    audits = [item for item in managed if item[1].get("name") == AUDIT_NAME]
    if len(managed) != 2 or len(guards) != 1 or len(audits) != 1:
        return None
    guard = reader(guards[0][1])
    audit = reader(audits[0][1])
    if (
        guard is None
        or audit is None
        or not same_agent_id(guard.agent_id, audit.agent_id)
    ):
        return None
    return (guards[0][0], guard), (audits[0][0], audit)


def _owned_references(
    hooks: List[JsonObject],
) -> Dict[int, KiroIdeRuntimeReference]:
    return {
        index: reference
        for index, hook in enumerate(hooks)
        if (reference := _owned_reference(hook)) is not None
    }


def require_available_kiroide_hooks(hooks: List[JsonObject]) -> None:
    owned = _owned_references(hooks)
    for index, hook in enumerate(hooks):
        if _managed_specification(hook.get("name")) and index not in owned:
            raise ValueError(
                f'Kiro IDE hook name "{hook.get("name")}" conflicts with '
                "the Elydora contract"
            )


def build_kiroide_hook(name: str, script_path: str) -> JsonObject:
    specification = _managed_specification(name)
    if specification is None:
        raise ValueError(f"Unsupported managed Kiro IDE hook name: {name}")
    return {
        "name": name,
        "description": specification[0],
        "trigger": specification[1],
        "matcher": ".*",
        "action": {"type": "command", "command": build_kiroide_command(script_path)},
        "timeout": HOOK_TIMEOUT_SECONDS,
        "enabled": True,
    }


def without_managed_kiroide_hooks(
    hooks: List[JsonObject], agent_id: str = ""
) -> List[JsonObject]:
    owned = _owned_references(hooks)
    result = []
    for index, hook in enumerate(hooks):
        reference = owned.get(index)
        remove = reference is not None and (
            not agent_id or same_agent_id(reference.agent_id, agent_id)
        )
        if not remove:
            result.append(hook)
    return result


def _entirely_managed(document: KiroIdeDocument) -> bool:
    return (
        document.exists
        and set(document.root) == {"version", "hooks"}
        and len(document.hooks) == 2
        and _managed_pair(document.hooks, _portable_managed_reference)
        is not None
    )


def render_kiroide_document(
    document: KiroIdeDocument, hooks: List[JsonObject]
) -> RenderedKiroIdeDocument:
    if not document.exists and not hooks:
        return RenderedKiroIdeDocument(document, False)
    if len(hooks) == len(document.hooks) and all(
        hook is document.hooks[index] for index, hook in enumerate(hooks)
    ):
        return RenderedKiroIdeDocument(document, False)
    if not hooks and _entirely_managed(document):
        return RenderedKiroIdeDocument(document, True)
    root = {**document.root, "version": "v1", "hooks": hooks}
    next_source = json.dumps(root, indent=2, ensure_ascii=False) + "\n"
    parse_kiroide_document(document.file_path, next_source)
    return RenderedKiroIdeDocument(
        document,
        next_source != document.raw,
        next_source,
    )


def kiroide_runtime_contracts(
    hooks: List[JsonObject],
) -> List[KiroIdeRuntimeContract]:
    pair = _managed_pair(hooks, _managed_reference)
    if pair is None:
        return []
    guard = pair[0][1]
    audit = pair[1][1]
    return [
        KiroIdeRuntimeContract(
            guard.agent_id,
            guard.script_path,
            audit.script_path,
        )
    ]


def managed_kiroide_hooks_present(hooks: List[JsonObject]) -> bool:
    return any(
        _managed_specification(hook.get("name")) is not None for hook in hooks
    )


def legacy_kiroide_runtime_contract(
    raw: str, file_path: str
) -> Optional[KiroIdeRuntimeContract]:
    root = parse_json_object(raw, f"legacy Kiro IDE hook at {file_path}")
    if (
        set(root) != {"name", "description", "version", "hooks"}
        or root.get("name") != "Elydora Audit"
        or root.get("description")
        != "Sends tool-use events to the Elydora tamper-evident audit platform"
        or root.get("version") != "1.0.0"
        or not isinstance(root.get("hooks"), dict)
    ):
        return None
    hooks = root["hooks"]
    if set(hooks) != {"pre_tool_use", "post_tool_use"}:
        return None
    guard_hook = hooks["pre_tool_use"]
    audit_hook = hooks["post_tool_use"]
    if (
        not isinstance(guard_hook, dict)
        or not isinstance(audit_hook, dict)
        or set(guard_hook) != {"command", "timeout_ms"}
        or set(audit_hook) != {"command", "timeout_ms"}
        or guard_hook.get("timeout_ms") != 5000
        or audit_hook.get("timeout_ms") != 5000
    ):
        return None
    guard = legacy_guard_reference(guard_hook.get("command"), GUARD_SCRIPT)
    audit = legacy_audit_reference(audit_hook.get("command"), AUDIT_SCRIPT)
    if (
        guard is None
        or audit is None
        or not same_agent_id(guard.agent_id, audit.agent_id)
        or not same_path(
            os.path.dirname(guard.script_path), os.path.dirname(audit.script_path)
        )
    ):
        return None
    return KiroIdeRuntimeContract(
        guard.agent_id,
        guard.script_path,
        audit.script_path,
    )
