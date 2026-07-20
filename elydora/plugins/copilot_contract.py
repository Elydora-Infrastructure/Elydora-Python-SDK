"""GitHub Copilot hook contract, ownership, and rendering."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import re
import shlex
import sys
from typing import Any, Dict, List, Optional, Set


AGENT_KEY = "copilot"
GUARD_SCRIPT = "guard.py"
AUDIT_SCRIPT = "hook.py"
CONFIG_FILE = "elydora-audit.json"
HOOK_TIMEOUT_SECONDS = 10

JsonObject = Dict[str, Any]
CopilotHooks = Dict[str, List[JsonObject]]


@dataclass(frozen=True)
class CopilotDocument:
    exists: bool
    file_path: str
    root: JsonObject
    hooks: CopilotHooks
    raw: Optional[str] = None


@dataclass(frozen=True)
class CopilotSources:
    user: CopilotDocument
    legacy: Optional[CopilotDocument]


@dataclass(frozen=True)
class RenderedDocument:
    document: CopilotDocument
    changed: bool
    next_source: Optional[str] = None


@dataclass(frozen=True)
class RuntimeContract:
    agent_id: str
    guard_path: str
    audit_path: str


def _same_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(
        os.path.abspath(right)
    )


def _same_agent_id(left: str, right: str) -> bool:
    return os.path.normcase(left) == os.path.normcase(right)


def _quote_powershell(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def build_handler(script_path: str) -> JsonObject:
    return {
        "type": "command",
        "bash": shlex.join([sys.executable, script_path]),
        "powershell": (
            f"& {_quote_powershell(sys.executable)} "
            f"{_quote_powershell(script_path)}; exit $LASTEXITCODE"
        ),
        "timeoutSec": HOOK_TIMEOUT_SECONDS,
    }


def _generated_script_path(handler: JsonObject) -> Optional[str]:
    if set(handler) != {"type", "bash", "powershell", "timeoutSec"}:
        return None
    if handler.get("type") != "command":
        return None
    if handler.get("timeoutSec") != HOOK_TIMEOUT_SECONDS:
        return None
    bash = handler.get("bash")
    if not isinstance(bash, str):
        return None
    try:
        arguments = shlex.split(bash)
    except ValueError:
        return None
    if len(arguments) != 2 or not _same_path(arguments[0], sys.executable):
        return None
    script_path = arguments[1]
    expected_powershell = (
        f"& {_quote_powershell(sys.executable)} "
        f"{_quote_powershell(script_path)}; exit $LASTEXITCODE"
    )
    return script_path if handler.get("powershell") == expected_powershell else None


def _legacy_script_path(handler: JsonObject) -> Optional[str]:
    if set(handler) != {"type", "bash", "powershell", "timeoutSec"}:
        return None
    if handler.get("type") != "command" or handler.get("timeoutSec") != 5:
        return None
    bash = handler.get("bash")
    powershell = handler.get("powershell")
    if not isinstance(bash, str) or bash != powershell:
        return None
    command = re.fullmatch(r'"[^"]+"\s+(.+)', bash)
    return command.group(1) if command else bash


def _managed_agent_id(
    handler: JsonObject,
    script_name: str,
    runtime_root: str,
) -> Optional[str]:
    script_path = _generated_script_path(handler) or _legacy_script_path(handler)
    if not script_path or os.path.basename(script_path) != script_name:
        return None
    agent_directory = os.path.dirname(script_path)
    if not _same_path(os.path.dirname(agent_directory), runtime_root):
        return None
    agent_id = os.path.basename(agent_directory)
    return agent_id if agent_id not in {"", ".", ".."} else None


def _validate_hooks(value: Any, label: str) -> CopilotHooks:
    if value is None:
        raise ValueError(f'{label} field "hooks" must be an object')
    if not isinstance(value, dict):
        raise ValueError(f'{label} field "hooks" must be an object')
    hooks: CopilotHooks = {}
    for event, handlers in value.items():
        if not isinstance(event, str):
            raise ValueError(f"{label} hook event names must be strings")
        if not isinstance(handlers, list):
            raise ValueError(f'{label} field "hooks.{event}" must be an array')
        if not all(isinstance(handler, dict) for handler in handlers):
            raise ValueError(
                f'{label} field "hooks.{event}" must contain objects'
            )
        hooks[event] = list(handlers)
    return hooks


def parse_document(file_path: str, raw: str, label: str) -> CopilotDocument:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError(f"Failed to parse {label} at {file_path}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} at {file_path} must contain a JSON object")
    if value.get("version") != 1:
        raise ValueError(f"{label} at {file_path} must declare version 1")
    hooks = _validate_hooks(value.get("hooks", {}), label)
    return CopilotDocument(True, file_path, value, hooks, raw)


def create_document(file_path: str) -> CopilotDocument:
    return CopilotDocument(False, file_path, {}, {})


def remove_managed_hooks(
    hooks: CopilotHooks,
    runtime_root: str,
    agent_id: str = "",
) -> CopilotHooks:
    result = dict(hooks)
    for event, script_name in (
        ("preToolUse", GUARD_SCRIPT),
        ("postToolUse", AUDIT_SCRIPT),
    ):
        handlers = []
        for handler in result.get(event, []):
            managed_id = _managed_agent_id(handler, script_name, runtime_root)
            remove = managed_id is not None and (
                not agent_id or _same_agent_id(managed_id, agent_id)
            )
            if not remove:
                handlers.append(handler)
        if handlers:
            result[event] = handlers
        else:
            result.pop(event, None)
    return result


def _empty_owned_document(root: JsonObject, hooks: CopilotHooks) -> bool:
    return not hooks and all(key in {"version", "hooks"} for key in root)


def render_document(
    document: CopilotDocument,
    hooks: CopilotHooks,
) -> RenderedDocument:
    if not document.exists and not hooks:
        return RenderedDocument(document, False)
    if document.exists and _empty_owned_document(document.root, hooks):
        return RenderedDocument(document, True)
    root = {**document.root, "version": 1}
    if hooks:
        root["hooks"] = hooks
    else:
        root.pop("hooks", None)
    next_source = json.dumps(root, indent=2) + "\n"
    return RenderedDocument(document, next_source != document.raw, next_source)


def _managed_ids(
    handlers: List[JsonObject],
    script_name: str,
    runtime_root: str,
) -> Set[str]:
    result: Set[str] = set()
    for handler in handlers:
        agent_id = _managed_agent_id(handler, script_name, runtime_root)
        if agent_id:
            result.add(agent_id)
    return result


def runtime_contracts(
    hooks: CopilotHooks,
    runtime_root: str,
) -> List[RuntimeContract]:
    guards = _managed_ids(hooks.get("preToolUse", []), GUARD_SCRIPT, runtime_root)
    audits = _managed_ids(hooks.get("postToolUse", []), AUDIT_SCRIPT, runtime_root)
    contracts: List[RuntimeContract] = []
    for agent_id in sorted(guards):
        if not any(_same_agent_id(agent_id, audit_id) for audit_id in audits):
            continue
        agent_directory = os.path.join(runtime_root, agent_id)
        contracts.append(RuntimeContract(
            agent_id,
            os.path.join(agent_directory, GUARD_SCRIPT),
            os.path.join(agent_directory, AUDIT_SCRIPT),
        ))
    return contracts
