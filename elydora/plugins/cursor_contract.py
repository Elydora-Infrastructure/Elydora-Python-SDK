"""Cursor hook contract, ownership, and rendering."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

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


@dataclass(frozen=True)
class _ParsedArgument:
    value: str
    next_index: int


def runtime_root() -> str:
    return os.path.join(os.path.expanduser("~"), ".elydora")


def same_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(
        os.path.abspath(right)
    )


def _same_agent_id(left: str, right: str) -> bool:
    return os.path.normcase(left) == os.path.normcase(right)


def _quote_posix(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _quote_powershell(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def build_handler(script_path: str) -> JsonObject:
    if os.name == "nt":
        command = (
            f"& {_quote_powershell(sys.executable)} "
            f"{_quote_powershell(script_path)}; exit $LASTEXITCODE"
        )
    else:
        command = f"{_quote_posix(sys.executable)} {_quote_posix(script_path)}"
    return {
        "command": command,
        "timeout": HOOK_TIMEOUT_SECONDS,
        "failClosed": True,
    }


def _read_posix_argument(command: str, start: int) -> Optional[_ParsedArgument]:
    if start >= len(command) or command[start] != "'":
        return None
    apostrophe = "'\"'\"'"
    value = ""
    index = start + 1
    while index < len(command):
        if command.startswith(apostrophe, index):
            value += "'"
            index += len(apostrophe)
            continue
        if command[index] == "'":
            return _ParsedArgument(value, index + 1)
        value += command[index]
        index += 1
    return None


def _parse_posix_command(command: str) -> Optional[Tuple[str, str]]:
    executable = _read_posix_argument(command, 0)
    if (
        executable is None
        or command[executable.next_index : executable.next_index + 1] != " "
    ):
        return None
    script = _read_posix_argument(command, executable.next_index + 1)
    if script is None or script.next_index != len(command):
        return None
    return executable.value, script.value


def _read_powershell_argument(
    command: str,
    start: int,
) -> Optional[_ParsedArgument]:
    if start >= len(command) or command[start] != "'":
        return None
    value = ""
    index = start + 1
    while index < len(command):
        if command[index] != "'":
            value += command[index]
            index += 1
            continue
        if index + 1 < len(command) and command[index + 1] == "'":
            value += "'"
            index += 2
            continue
        return _ParsedArgument(value, index + 1)
    return None


def _parse_powershell_command(command: str) -> Optional[Tuple[str, str]]:
    if not command.startswith("& "):
        return None
    executable = _read_powershell_argument(command, 2)
    if (
        executable is None
        or command[executable.next_index : executable.next_index + 1] != " "
    ):
        return None
    script = _read_powershell_argument(command, executable.next_index + 1)
    if script is None or command[script.next_index :] != "; exit $LASTEXITCODE":
        return None
    return executable.value, script.value


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
            _parse_powershell_command(handler["command"])
            if os.name == "nt"
            else _parse_posix_command(handler["command"])
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


def _managed_agent_id(
    handler: JsonObject,
    script_name: str,
) -> Optional[str]:
    script_path = _managed_script_path(handler)
    if script_path is None or os.path.basename(script_path) != script_name:
        return None
    agent_directory = os.path.dirname(script_path)
    if not same_path(os.path.dirname(agent_directory), runtime_root()):
        return None
    agent_id = os.path.basename(agent_directory)
    return agent_id if agent_id not in {"", ".", ".."} else None


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
                not agent_id or _same_agent_id(managed_id, agent_id)
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
