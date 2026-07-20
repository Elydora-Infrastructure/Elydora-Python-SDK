"""Auggie hook contract parsing and exact Elydora ownership."""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import os
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

from ._strict_json import parse_json_object


AGENT_KEY = "augment"
GUARD_SCRIPT = "guard.py"
AUDIT_SCRIPT = "hook.py"
HOOK_TIMEOUT_MILLISECONDS = 10_000

_WRAPPER_EXTENSION = ".cmd" if os.name == "nt" else ".sh"
GUARD_WRAPPER = f"augment-guard{_WRAPPER_EXTENSION}"
AUDIT_WRAPPER = f"augment-hook{_WRAPPER_EXTENSION}"

_TOOL_EVENTS = {"PreToolUse", "PostToolUse"}
_SESSION_EVENTS = {
    "Stop",
    "SessionStart",
    "SessionEnd",
    "Notification",
    "PromptSubmit",
}

JsonObject = Dict[str, Any]
AugmentHooks = Dict[str, List[JsonObject]]


@dataclass(frozen=True)
class AugmentDocument:
    exists: bool
    config_path: str
    root: JsonObject
    hooks: AugmentHooks
    raw: Optional[str] = None


@dataclass(frozen=True)
class RenderedAugmentDocument:
    document: AugmentDocument
    changed: bool
    next_source: Optional[str] = None


@dataclass(frozen=True)
class WrapperPaths:
    guard_path: str
    audit_path: str


@dataclass(frozen=True)
class RuntimeContract:
    agent_id: str
    guard_path: str
    audit_path: str
    guard_wrapper_path: str
    audit_wrapper_path: str


def home_dir() -> str:
    return os.path.expanduser("~")


def elydora_dir() -> str:
    return os.path.join(home_dir(), ".elydora")


def resolve_config_path() -> str:
    return os.path.join(home_dir(), ".augment", "settings.json")


def wrapper_paths(agent_directory: str) -> WrapperPaths:
    return WrapperPaths(
        guard_path=os.path.join(agent_directory, GUARD_WRAPPER),
        audit_path=os.path.join(agent_directory, AUDIT_WRAPPER),
    )


def _quote_posix(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _quote_windows(value: str) -> str:
    return '"' + value.replace('"', '\\"') + '"'


def _quote_batch(value: str) -> str:
    return '"' + value.replace("%", "%%") + '"'


def build_command(wrapper_path: str) -> str:
    quote = _quote_windows if os.name == "nt" else _quote_posix
    return quote(wrapper_path)


def build_wrapper(runtime_path: str) -> str:
    if os.name == "nt":
        return (
            "@echo off\r\n"
            f"{_quote_batch(sys.executable)} {_quote_batch(runtime_path)}\r\n"
            "exit /b %errorlevel%\r\n"
        )
    return (
        f"#!/bin/sh\nexec {_quote_posix(sys.executable)} {_quote_posix(runtime_path)}\n"
    )


def build_handler(wrapper_path: str) -> JsonObject:
    return {
        "type": "command",
        "command": build_command(wrapper_path),
        "timeout": HOOK_TIMEOUT_MILLISECONDS,
    }


def _parse_windows_argument(command: str) -> Optional[str]:
    if len(command) < 2 or command[0] != '"':
        return None
    value = ""
    index = 1
    while index < len(command):
        if command[index] == "\\" and index + 1 < len(command):
            if command[index + 1] == '"':
                value += '"'
                index += 2
                continue
        if command[index] == '"':
            return value if index == len(command) - 1 and value else None
        value += command[index]
        index += 1
    return None


def _parse_posix_argument(command: str) -> Optional[str]:
    if len(command) < 2 or command[0] != "'":
        return None
    value = ""
    index = 1
    apostrophe = "'\"'\"'"
    while index < len(command):
        if command.startswith(apostrophe, index):
            value += "'"
            index += len(apostrophe)
            continue
        if command[index] == "'":
            return value if index == len(command) - 1 and value else None
        value += command[index]
        index += 1
    return None


def _parse_wrapper_command(command: str) -> Optional[str]:
    parser = _parse_windows_argument if os.name == "nt" else _parse_posix_argument
    return parser(command)


def _same_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(
        os.path.abspath(right)
    )


def _same_agent_id(left: str, right: str) -> bool:
    return os.path.normcase(left) == os.path.normcase(right)


def _managed_agent_id(handler: JsonObject, wrapper_name: str) -> Optional[str]:
    if (
        handler.get("type") != "command"
        or handler.get("timeout") != HOOK_TIMEOUT_MILLISECONDS
        or not isinstance(handler.get("command"), str)
        or "args" in handler
    ):
        return None
    wrapper_path = _parse_wrapper_command(str(handler["command"]))
    if wrapper_path is None:
        return None
    if os.path.normcase(os.path.basename(wrapper_path)) != os.path.normcase(
        wrapper_name
    ):
        return None
    agent_directory = os.path.dirname(wrapper_path)
    if not _same_path(os.path.dirname(agent_directory), elydora_dir()):
        return None
    agent_id = os.path.basename(agent_directory)
    return agent_id if agent_id not in {"", ".", ".."} else None


def _validate_handler(
    value: Any,
    event: str,
    group_index: int,
    handler_index: int,
) -> JsonObject:
    label = (
        f"Auggie settings handler hooks.{event}[{group_index}].hooks[{handler_index}]"
    )
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    handler = dict(value)
    if handler.get("type") != "command":
        raise ValueError(f'{label} type must be "command"')
    if not isinstance(handler.get("command"), str) or not handler["command"]:
        raise ValueError(f"{label} requires a non-empty command")
    arguments = handler.get("args")
    if "args" in handler and (
        not isinstance(arguments, list)
        or not all(isinstance(argument, str) for argument in arguments)
    ):
        raise ValueError(f"{label} args must be an array of strings")
    timeout = handler.get("timeout")
    if "timeout" in handler and (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError(f"{label} timeout must be a positive finite number")
    return handler


def _validate_metadata(value: Any, label: str) -> None:
    if not isinstance(value, dict):
        raise ValueError(f"{label} metadata must be an object")
    for key in (
        "includeConversationData",
        "includeMCPMetadata",
        "includeUserContext",
    ):
        if key in value and not isinstance(value[key], bool):
            raise ValueError(f"{label} metadata.{key} must be a boolean")


def _validate_group(value: Any, event: str, group_index: int) -> JsonObject:
    label = f"Auggie settings group hooks.{event}[{group_index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    group = dict(value)
    if event in _SESSION_EVENTS and "matcher" in group:
        raise ValueError(f"{label} matcher is only supported for tool events")
    matcher = group.get("matcher")
    if "matcher" in group:
        if not isinstance(matcher, str):
            raise ValueError(f"{label} matcher must be a string")
    if "metadata" in group:
        _validate_metadata(group["metadata"], label)
    handlers = group.get("hooks")
    if not isinstance(handlers, list):
        raise ValueError(f"{label} must contain a hooks array")
    group["hooks"] = [
        _validate_handler(handler, event, group_index, handler_index)
        for handler_index, handler in enumerate(handlers)
    ]
    return group


def read_hooks(root: JsonObject) -> AugmentHooks:
    if "hooks" not in root:
        return {}
    raw_hooks = root["hooks"]
    if not isinstance(raw_hooks, dict):
        raise ValueError('Auggie settings field "hooks" must be an object')
    hooks: AugmentHooks = {}
    for event, groups in raw_hooks.items():
        if event not in _TOOL_EVENTS and event not in _SESSION_EVENTS:
            raise ValueError(
                f'Auggie settings field "hooks.{event}" uses an unsupported event'
            )
        if not isinstance(groups, list):
            raise ValueError(f'Auggie settings field "hooks.{event}" must be an array')
        hooks[event] = [
            _validate_group(group, event, group_index)
            for group_index, group in enumerate(groups)
        ]
    return hooks


def parse_augment_document(config_path: str, raw: str) -> AugmentDocument:
    root = parse_json_object(raw, f"Auggie user settings at {config_path}")
    return AugmentDocument(True, config_path, root, read_hooks(root), raw)


def create_augment_document(config_path: str) -> AugmentDocument:
    return AugmentDocument(False, config_path, {}, {})


def render_augment_document(
    document: AugmentDocument, hooks: AugmentHooks
) -> RenderedAugmentDocument:
    if hooks == document.hooks:
        return RenderedAugmentDocument(document, False)
    if not document.exists and not hooks:
        return RenderedAugmentDocument(document, False)
    root = dict(document.root)
    if hooks:
        root["hooks"] = hooks
    else:
        root.pop("hooks", None)
    if not root:
        return RenderedAugmentDocument(document, True)
    next_source = json.dumps(root, indent=2, ensure_ascii=False) + "\n"
    parse_augment_document(document.config_path, next_source)
    return RenderedAugmentDocument(document, next_source != document.raw, next_source)


def _remove_managed(
    groups: List[JsonObject],
    wrapper_name: str,
    agent_id: str = "",
) -> Tuple[List[JsonObject], bool]:
    result: List[JsonObject] = []
    changed = False
    for group in groups:
        kept: List[JsonObject] = []
        group_changed = False
        for handler in group["hooks"]:
            managed_id = _managed_agent_id(handler, wrapper_name)
            remove = managed_id is not None and (
                not agent_id or _same_agent_id(managed_id, agent_id)
            )
            if remove:
                changed = True
                group_changed = True
            else:
                kept.append(handler)
        if not group_changed:
            result.append(group)
        elif kept:
            result.append({**group, "hooks": kept})
    return result, changed


def remove_managed_hooks(
    hooks: AugmentHooks, agent_id: str = ""
) -> Tuple[AugmentHooks, bool]:
    result = dict(hooks)
    changed = False
    for event, wrapper_name in (
        ("PreToolUse", GUARD_WRAPPER),
        ("PostToolUse", AUDIT_WRAPPER),
    ):
        groups, event_changed = _remove_managed(
            result.get(event, []), wrapper_name, agent_id
        )
        if not event_changed:
            continue
        changed = True
        if groups:
            result[event] = groups
        else:
            result.pop(event, None)
    return result, changed


def _managed_ids(groups: List[JsonObject], wrapper_name: str) -> Set[str]:
    result: Set[str] = set()
    for group in groups:
        for handler in group["hooks"]:
            agent_id = _managed_agent_id(handler, wrapper_name)
            if agent_id:
                result.add(agent_id)
    return result


def runtime_contracts(hooks: AugmentHooks) -> List[RuntimeContract]:
    guards = _managed_ids(hooks.get("PreToolUse", []), GUARD_WRAPPER)
    audits = _managed_ids(hooks.get("PostToolUse", []), AUDIT_WRAPPER)
    contracts: List[RuntimeContract] = []
    for guard_id in sorted(guards, key=os.path.normcase):
        audit_id = next(
            (candidate for candidate in audits if _same_agent_id(candidate, guard_id)),
            None,
        )
        if audit_id is None:
            continue
        agent_directory = os.path.join(elydora_dir(), guard_id)
        contracts.append(
            RuntimeContract(
                agent_id=guard_id,
                guard_path=os.path.join(agent_directory, GUARD_SCRIPT),
                audit_path=os.path.join(agent_directory, AUDIT_SCRIPT),
                guard_wrapper_path=os.path.join(agent_directory, GUARD_WRAPPER),
                audit_wrapper_path=os.path.join(agent_directory, AUDIT_WRAPPER),
            )
        )
    return contracts
