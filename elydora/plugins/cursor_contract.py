"""Cursor hook contract, ownership, and rendering."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

from elydora._runtime_paths import runtime_root

from ._runtime import managed_script_reference, same_agent_id, same_path
from ._shell_command import (
    parse_posix_command,
    parse_powershell_source,
    posix_source,
    powershell_source,
)
from ._strict_json import JsonObject, parse_json_object


AGENT_KEY = "cursor"
GUARD_SCRIPT = "guard.py"
AUDIT_SCRIPT = "hook.py"
HOOK_TIMEOUT_SECONDS = 10

CursorHooks = Dict[str, List[JsonObject]]


@dataclass(frozen=True)
class CursorDocument:
    exists: bool
    file_path: str
    root: JsonObject
    hooks: CursorHooks
    raw: Optional[str] = None


@dataclass(frozen=True)
class RenderedDocument:
    document: CursorDocument
    changed: bool
    next_source: Optional[str] = None


@dataclass(frozen=True)
class RuntimeContract:
    agent_id: str
    guard_path: str
    audit_path: str


def build_handler(script_path: str) -> JsonObject:
    command = powershell_source(script_path) if os.name == "nt" else posix_source(script_path)
    return {
        "command": command,
        "timeout": HOOK_TIMEOUT_SECONDS,
        "failClosed": True,
    }


def _legacy_script_path(command: str) -> Optional[str]:
    quoted = re.fullmatch(r'"([^"\r\n]+)" ([^\r\n]+)', command)
    if quoted and same_path(quoted.group(1), sys.executable):
        return quoted.group(2)
    return command if os.path.isabs(command) else None


def _managed_script_path(handler: JsonObject) -> Optional[str]:
    if (
        set(handler) == {"command", "timeout", "failClosed"}
        and isinstance(handler.get("command"), str)
        and type(handler.get("timeout")) is int
        and handler.get("timeout") == HOOK_TIMEOUT_SECONDS
        and handler.get("failClosed") is True
    ):
        parsed = (
            parse_powershell_source(handler["command"])
            if os.name == "nt"
            else parse_posix_command(handler["command"])
        )
        if (
            parsed is not None
            and os.path.isabs(parsed[0])
            and os.path.isabs(parsed[1])
            and same_path(parsed[0], sys.executable)
        ):
            return parsed[1]
    if set(handler) != {"command"} or not isinstance(handler.get("command"), str):
        return None
    return _legacy_script_path(handler["command"])


def _managed_agent_id(handler: JsonObject, script_name: str) -> Optional[str]:
    script_path = _managed_script_path(handler)
    if script_path is None:
        return None
    reference = managed_script_reference(script_path, script_name)
    return None if reference is None else reference[0]


def _read_hooks(value: Any, label: str) -> CursorHooks:
    if value is None:
        raise ValueError(f'{label} field "hooks" must be an object')
    if not isinstance(value, dict):
        raise ValueError(f'{label} field "hooks" must be an object')
    hooks: CursorHooks = {}
    for event, handlers in value.items():
        if not isinstance(handlers, list):
            raise ValueError(f'{label} field "hooks.{event}" must be an array')
        if not all(isinstance(handler, dict) for handler in handlers):
            raise ValueError(f'{label} field "hooks.{event}" must contain objects')
        hooks[event] = list(handlers)
    return hooks


def _contains_managed_hook(hooks: CursorHooks) -> bool:
    return any(
        _managed_agent_id(handler, script_name) is not None
        for event, script_name in (
            ("preToolUse", GUARD_SCRIPT),
            ("postToolUse", AUDIT_SCRIPT),
            ("postToolUseFailure", AUDIT_SCRIPT),
        )
        for handler in hooks.get(event, [])
    )


def parse_document(file_path: str, raw: str) -> CursorDocument:
    label = f"Cursor user hooks at {file_path}"
    root = parse_json_object(raw, label)
    hooks = _read_hooks(root.get("hooks", {}), label)
    version = root.get("version")
    current = type(version) is int and version == 1
    legacy_owned = "version" not in root and _contains_managed_hook(hooks)
    if not current and not legacy_owned:
        raise ValueError(f"{label} must declare version 1")
    return CursorDocument(True, file_path, root, hooks, raw)


def create_document(file_path: str) -> CursorDocument:
    return CursorDocument(False, file_path, {}, {})


def remove_managed_hooks(
    hooks: CursorHooks,
    agent_id: str = "",
) -> CursorHooks:
    result = {event: list(handlers) for event, handlers in hooks.items()}
    for event, script_name in (
        ("preToolUse", GUARD_SCRIPT),
        ("postToolUse", AUDIT_SCRIPT),
        ("postToolUseFailure", AUDIT_SCRIPT),
    ):
        handlers = []
        for handler in result.get(event, []):
            managed_id = _managed_agent_id(handler, script_name)
            remove = managed_id is not None and (
                not agent_id or same_agent_id(managed_id, agent_id)
            )
            if not remove:
                handlers.append(handler)
        if handlers:
            result[event] = handlers
        else:
            result.pop(event, None)
    return result


def _entirely_managed(document: CursorDocument) -> bool:
    if not document.exists or not set(document.root).issubset({"version", "hooks"}):
        return False
    if not document.hooks:
        return False
    handler_count = 0
    for event, handlers in document.hooks.items():
        script_name = {
            "preToolUse": GUARD_SCRIPT,
            "postToolUse": AUDIT_SCRIPT,
            "postToolUseFailure": AUDIT_SCRIPT,
        }.get(event)
        if script_name is None or not handlers:
            return False
        handler_count += len(handlers)
        if any(_managed_agent_id(handler, script_name) is None for handler in handlers):
            return False
    return handler_count > 0


def render_document(
    document: CursorDocument,
    hooks: CursorHooks,
) -> RenderedDocument:
    if not document.exists and not hooks:
        return RenderedDocument(document, False)
    if document.exists and hooks == document.hooks:
        return RenderedDocument(document, False)
    if not hooks and _entirely_managed(document):
        return RenderedDocument(document, True)
    root = {**document.root, "version": 1}
    if hooks:
        root["hooks"] = hooks
    else:
        root.pop("hooks", None)
    next_source = json.dumps(root, indent=2) + "\n"
    return RenderedDocument(document, next_source != document.raw, next_source)


def _managed_ids(handlers: List[JsonObject], script_name: str) -> Dict[str, str]:
    result = {}
    for handler in handlers:
        agent_id = _managed_agent_id(handler, script_name)
        if agent_id:
            result[os.path.normcase(agent_id)] = agent_id
    return result


def runtime_contracts(hooks: CursorHooks) -> List[RuntimeContract]:
    guards = _managed_ids(hooks.get("preToolUse", []), GUARD_SCRIPT)
    audits = _managed_ids(hooks.get("postToolUse", []), AUDIT_SCRIPT)
    failures = _managed_ids(hooks.get("postToolUseFailure", []), AUDIT_SCRIPT)
    contracts = []
    for key, agent_id in guards.items():
        if key not in audits or key not in failures:
            continue
        agent_directory = os.path.join(runtime_root(), agent_id)
        contracts.append(
            RuntimeContract(
                agent_id,
                os.path.join(agent_directory, GUARD_SCRIPT),
                os.path.join(agent_directory, AUDIT_SCRIPT),
            )
        )
    return contracts
