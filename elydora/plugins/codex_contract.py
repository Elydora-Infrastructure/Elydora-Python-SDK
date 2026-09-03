"""Codex user-hook contract, exact ownership, and rendering."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import shlex
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from elydora._runtime_paths import runtime_root

from ._runtime import managed_script_reference, same_agent_id, same_path
from ._shell_command import (
    encoded_windows_command,
    is_python_executable,
    parse_encoded_windows_command,
    parse_posix_command,
    posix_source,
)
from ._strict_json import JsonObject, parse_json_object


AGENT_KEY = "codex"
CONFIG_FILE = "hooks.json"
GUARD_SCRIPT = "guard.py"
AUDIT_SCRIPT = "hook.py"
HOOK_TIMEOUT_SECONDS = 10
OWNED_DESCRIPTION = "Elydora audit and freeze enforcement"
GUARD_STATUS = "Checking Elydora agent state"
AUDIT_STATUS = "Recording Elydora tool use"

CodexHooks = Dict[str, List[JsonObject]]


@dataclass(frozen=True)
class CodexDocument:
    exists: bool
    file_path: str
    root: JsonObject
    hooks: CodexHooks
    raw: Optional[str] = None


@dataclass(frozen=True)
class RenderedDocument:
    document: CodexDocument
    changed: bool
    next_source: Optional[str] = None


@dataclass(frozen=True)
class RuntimeContract:
    agent_id: str
    guard_path: str
    audit_path: str


def build_handler(script_path: str, status_message: str) -> JsonObject:
    return {
        "type": "command",
        "command": posix_source(script_path),
        "commandWindows": encoded_windows_command(script_path),
        "timeout": HOOK_TIMEOUT_SECONDS,
        "statusMessage": status_message,
    }


def _parse_legacy_commands(handler: JsonObject) -> Optional[Tuple[str, str]]:
    command = handler.get("command")
    command_windows = handler.get("commandWindows")
    if not isinstance(command, str) or not isinstance(command_windows, str):
        return None
    try:
        arguments = shlex.split(command, posix=True)
    except ValueError:
        return None
    if len(arguments) != 2:
        return None
    expected_posix = f"{shlex.quote(arguments[0])} {shlex.quote(arguments[1])}"
    if command != expected_posix or command_windows != subprocess.list2cmdline(
        arguments
    ):
        return None
    return arguments[0], arguments[1]


def _managed_script_path(
    handler: JsonObject,
    status_message: str,
) -> Optional[str]:
    if (
        set(handler)
        != {"type", "command", "commandWindows", "timeout", "statusMessage"}
        or handler.get("type") != "command"
        or type(handler.get("timeout")) is not int
        or handler.get("timeout") != HOOK_TIMEOUT_SECONDS
        or handler.get("statusMessage") != status_message
    ):
        return None
    command = handler.get("command")
    command_windows = handler.get("commandWindows")
    posix = parse_posix_command(command) if isinstance(command, str) else None
    windows = (
        parse_encoded_windows_command(command_windows)
        if isinstance(command_windows, str)
        else None
    )
    if posix is None or windows is None:
        legacy = _parse_legacy_commands(handler)
        posix = legacy
        windows = legacy
    if (
        posix is None
        or windows is None
        or not os.path.isabs(posix[0])
        or not os.path.isabs(posix[1])
        or not is_python_executable(posix[0])
        or not is_python_executable(windows[0])
        or not same_path(posix[0], windows[0])
        or not same_path(posix[1], windows[1])
    ):
        return None
    return posix[1]


def _managed_agent_id(
    handler: JsonObject,
    script_name: str,
    status_message: str,
) -> Optional[str]:
    script_path = _managed_script_path(handler, status_message)
    if script_path is None:
        return None
    reference = managed_script_reference(script_path, script_name)
    return None if reference is None else reference[0]


def _read_hooks(value: Any, label: str) -> CodexHooks:
    if value is None or not isinstance(value, dict):
        raise ValueError(f'{label} field "hooks" must be an object')
    hooks: CodexHooks = {}
    for event, groups in value.items():
        if not isinstance(groups, list):
            raise ValueError(f'{label} field "hooks.{event}" must be an array')
        parsed_groups = []
        for index, group in enumerate(groups):
            if not isinstance(group, dict):
                raise ValueError(
                    f"{label} matcher group hooks.{event}[{index}] must be an object"
                )
            handlers = group.get("hooks")
            if not isinstance(handlers, list) or not all(
                isinstance(handler, dict) for handler in handlers
            ):
                raise ValueError(
                    f"{label} matcher group hooks.{event}[{index}] must contain a hooks array"
                )
            parsed_groups.append(group)
        hooks[event] = parsed_groups
    return hooks


def parse_document(file_path: str, raw: str) -> CodexDocument:
    label = f"Codex user hooks at {file_path}"
    root = parse_json_object(raw, label)
    hooks = _read_hooks(root.get("hooks", {}), label)
    return CodexDocument(True, file_path, root, hooks, raw)


def create_document(file_path: str) -> CodexDocument:
    return CodexDocument(False, file_path, {"description": OWNED_DESCRIPTION}, {})


def _exact_matcher_group(group: JsonObject) -> bool:
    return set(group) == {"matcher", "hooks"} and group.get("matcher") == "*"


def _remove_from_groups(
    groups: List[JsonObject],
    script_name: str,
    status_message: str,
    agent_id: str,
) -> List[JsonObject]:
    result = []
    for group in groups:
        handlers = []
        for handler in group["hooks"]:
            managed_id = _managed_agent_id(handler, script_name, status_message)
            remove = managed_id is not None and (
                not agent_id or same_agent_id(managed_id, agent_id)
            )
            if not remove:
                handlers.append(handler)
        if handlers or not _exact_matcher_group(group):
            result.append({**group, "hooks": handlers})
    return result


def remove_managed_hooks(hooks: CodexHooks, agent_id: str = "") -> CodexHooks:
    result = {event: list(groups) for event, groups in hooks.items()}
    for event, script_name, status_message in (
        ("PreToolUse", GUARD_SCRIPT, GUARD_STATUS),
        ("PostToolUse", AUDIT_SCRIPT, AUDIT_STATUS),
    ):
        groups = _remove_from_groups(
            result.get(event, []),
            script_name,
            status_message,
            agent_id,
        )
        if groups:
            result[event] = groups
        else:
            result.pop(event, None)
    return result


def _entirely_managed(document: CodexDocument) -> bool:
    if (
        not document.exists
        or document.root.get("description") != OWNED_DESCRIPTION
        or not set(document.root).issubset({"description", "hooks"})
        or not document.hooks
    ):
        return False
    count = 0
    for event, groups in document.hooks.items():
        contract = {
            "PreToolUse": (GUARD_SCRIPT, GUARD_STATUS),
            "PostToolUse": (AUDIT_SCRIPT, AUDIT_STATUS),
        }.get(event)
        if contract is None or not groups:
            return False
        for group in groups:
            handlers = group["hooks"]
            if (
                not _exact_matcher_group(group)
                or not handlers
                or any(
                    _managed_agent_id(handler, contract[0], contract[1]) is None
                    for handler in handlers
                )
            ):
                return False
            count += len(handlers)
    return count > 0


def render_document(document: CodexDocument, hooks: CodexHooks) -> RenderedDocument:
    if not document.exists and not hooks:
        return RenderedDocument(document, False)
    if hooks == document.hooks:
        return RenderedDocument(document, False)
    if not hooks and _entirely_managed(document):
        return RenderedDocument(document, True)
    root = dict(document.root)
    if hooks:
        root["hooks"] = hooks
    else:
        root.pop("hooks", None)
    next_source = json.dumps(root, indent=2) + "\n"
    return RenderedDocument(document, next_source != document.raw, next_source)


def _managed_ids(
    groups: List[JsonObject],
    script_name: str,
    status_message: str,
) -> Dict[str, str]:
    result = {}
    for group in groups:
        if not _exact_matcher_group(group):
            continue
        for handler in group["hooks"]:
            agent_id = _managed_agent_id(handler, script_name, status_message)
            if agent_id:
                result[os.path.normcase(agent_id)] = agent_id
    return result


def runtime_contracts(hooks: CodexHooks) -> List[RuntimeContract]:
    guards = _managed_ids(hooks.get("PreToolUse", []), GUARD_SCRIPT, GUARD_STATUS)
    audits = _managed_ids(hooks.get("PostToolUse", []), AUDIT_SCRIPT, AUDIT_STATUS)
    contracts = []
    for key, agent_id in guards.items():
        if key not in audits:
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
