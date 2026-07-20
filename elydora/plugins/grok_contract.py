"""Grok hook schema, exact ownership, and JSON rendering."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from typing import Any, Dict, List, Optional, Tuple

from ._strict_json import JsonObject, parse_json_object
from .grok_command import (
    GrokRuntimeReference,
    build_grok_command,
    grok_runtime_reference,
    same_grok_agent_id,
    same_grok_path,
)


AGENT_KEY = "grok"
GUARD_SCRIPT = "guard.py"
AUDIT_SCRIPT = "hook.py"
HOOK_TIMEOUT_SECONDS = 10
MATCHER_REJECTING_EVENTS = frozenset(
    {"SessionStart", "SessionEnd", "Stop", "UserPromptSubmit"}
)

GrokHooks = Dict[str, List[JsonObject]]


@dataclass(frozen=True)
class GrokDocument:
    exists: bool
    config_path: str
    root: JsonObject
    hooks: GrokHooks
    raw: Optional[str] = None


@dataclass(frozen=True)
class RenderedGrokDocument:
    document: GrokDocument
    changed: bool
    next_source: Optional[str] = None


@dataclass(frozen=True)
class GrokRuntimeContract:
    agent_id: str
    guard_path: str
    audit_path: str


def _validate_handler(
    value: Any,
    event: str,
    group_index: int,
    handler_index: int,
) -> JsonObject:
    label = (
        f"Grok user hooks handler hooks.{event}[{group_index}]"
        f".hooks[{handler_index}]"
    )
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    handler = dict(value)
    handler_type = handler.get("type")
    if handler_type not in ("command", "http"):
        raise ValueError(f'{label} has unsupported type "{handler_type}"')
    if handler_type == "command" and (
        not isinstance(handler.get("command"), str) or not handler["command"]
    ):
        raise ValueError(f"{label} requires a non-empty command")
    if handler_type == "http" and (
        not isinstance(handler.get("url"), str) or not handler["url"]
    ):
        raise ValueError(f"{label} requires a non-empty url")
    timeout = handler.get("timeout")
    if timeout is not None and (type(timeout) is not int or timeout < 0):
        raise ValueError(f"{label} timeout must be a non-negative integer")
    environment = handler.get("env")
    if environment is not None and (
        not isinstance(environment, dict)
        or any(not isinstance(item, str) for item in environment.values())
    ):
        raise ValueError(f"{label} env must map names to strings")
    return handler


def _validate_group(value: Any, event: str, group_index: int) -> JsonObject:
    label = f"Grok user hooks group hooks.{event}[{group_index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    group = dict(value)
    matcher = group.get("matcher")
    if "matcher" in group and not isinstance(matcher, str):
        raise ValueError(f"{label} matcher must be a string")
    if "matcher" in group and event in MATCHER_REJECTING_EVENTS:
        raise ValueError(f"{label} cannot declare a matcher for {event}")
    handlers = group.get("hooks")
    if not isinstance(handlers, list):
        raise ValueError(f"{label} must contain a hooks array")
    group["hooks"] = [
        _validate_handler(handler, event, group_index, handler_index)
        for handler_index, handler in enumerate(handlers)
    ]
    return group


def _read_hooks(root: JsonObject) -> GrokHooks:
    if "hooks" not in root:
        return {}
    value = root["hooks"]
    if not isinstance(value, dict):
        raise ValueError('Grok user hooks field "hooks" must be an object')
    hooks: GrokHooks = {}
    for event, groups in value.items():
        if not isinstance(groups, list):
            raise ValueError(
                f'Grok user hooks field "hooks.{event}" must be an array'
            )
        hooks[event] = [
            _validate_group(group, event, index)
            for index, group in enumerate(groups)
        ]
    return hooks


def parse_grok_document(config_path: str, raw: str) -> GrokDocument:
    root = parse_json_object(raw, f"Grok user hooks at {config_path}")
    return GrokDocument(True, config_path, root, _read_hooks(root), raw)


def create_grok_document(config_path: str) -> GrokDocument:
    return GrokDocument(False, config_path, {}, {})


def build_grok_group(script_path: str) -> JsonObject:
    return {
        "hooks": [{
            "type": "command",
            "command": build_grok_command(script_path),
            "timeout": HOOK_TIMEOUT_SECONDS,
        }]
    }


def _exact_managed_group(group: JsonObject) -> bool:
    return set(group) == {"hooks"}


def _managed_reference(
    handler: JsonObject, script_name: str
) -> Optional[GrokRuntimeReference]:
    if (
        set(handler) != {"type", "command", "timeout"}
        or handler.get("type") != "command"
        or type(handler.get("timeout")) is not int
        or handler.get("timeout") != HOOK_TIMEOUT_SECONDS
        or not isinstance(handler.get("command"), str)
    ):
        return None
    return grok_runtime_reference(str(handler["command"]), script_name)


def _managed_contract(event: str) -> Optional[Tuple[str, str]]:
    if event == "PreToolUse":
        return event, GUARD_SCRIPT
    if event in ("PostToolUse", "PostToolUseFailure"):
        return event, AUDIT_SCRIPT
    return None


def _remove_from_groups(
    groups: List[JsonObject], script_name: str, agent_id: str
) -> List[JsonObject]:
    result: List[JsonObject] = []
    for group in groups:
        if not _exact_managed_group(group):
            result.append(group)
            continue
        kept = []
        for handler in group["hooks"]:
            reference = _managed_reference(handler, script_name)
            remove = reference is not None and (
                not agent_id or same_grok_agent_id(reference.agent_id, agent_id)
            )
            if not remove:
                kept.append(handler)
        if kept:
            result.append({"hooks": kept})
    return result


def remove_managed_grok_hooks(
    hooks: GrokHooks, agent_id: str = ""
) -> GrokHooks:
    result = {event: list(groups) for event, groups in hooks.items()}
    for event, script_name in (
        ("PreToolUse", GUARD_SCRIPT),
        ("PostToolUse", AUDIT_SCRIPT),
        ("PostToolUseFailure", AUDIT_SCRIPT),
    ):
        groups = _remove_from_groups(
            result.get(event, []), script_name, agent_id
        )
        if groups:
            result[event] = groups
        else:
            result.pop(event, None)
    return result


def _entirely_managed(document: GrokDocument) -> bool:
    if not document.exists or set(document.root) != {"hooks"}:
        return False
    if not document.hooks:
        return False
    count = 0
    for event, groups in document.hooks.items():
        contract = _managed_contract(event)
        if contract is None or not groups:
            return False
        for group in groups:
            if (
                not _exact_managed_group(group)
                or not group["hooks"]
                or any(
                    _managed_reference(handler, contract[1]) is None
                    for handler in group["hooks"]
                )
            ):
                return False
            count += len(group["hooks"])
    return count > 0


def render_grok_document(
    document: GrokDocument, hooks: GrokHooks
) -> RenderedGrokDocument:
    if not document.exists and not hooks:
        return RenderedGrokDocument(document, False)
    if not hooks and _entirely_managed(document):
        return RenderedGrokDocument(document, True)
    root = dict(document.root)
    if hooks:
        root["hooks"] = hooks
    else:
        root.pop("hooks", None)
    next_source = json.dumps(root, indent=2, ensure_ascii=False) + "\n"
    parse_grok_document(document.config_path, next_source)
    return RenderedGrokDocument(
        document,
        next_source != document.raw,
        next_source,
    )


def _references_for_event(
    groups: List[JsonObject], script_name: str
) -> Dict[str, List[GrokRuntimeReference]]:
    result: Dict[str, List[GrokRuntimeReference]] = {}
    for group in groups:
        if not _exact_managed_group(group):
            continue
        for handler in group["hooks"]:
            reference = _managed_reference(handler, script_name)
            if reference is not None:
                result.setdefault(
                    os.path.normcase(reference.agent_id), []
                ).append(reference)
    return result


def grok_runtime_contracts(hooks: GrokHooks) -> List[GrokRuntimeContract]:
    guards = _references_for_event(hooks.get("PreToolUse", []), GUARD_SCRIPT)
    successes = _references_for_event(
        hooks.get("PostToolUse", []), AUDIT_SCRIPT
    )
    failures = _references_for_event(
        hooks.get("PostToolUseFailure", []), AUDIT_SCRIPT
    )
    contracts = []
    for key, guard in guards.items():
        success = successes.get(key, [])
        failure = failures.get(key, [])
        if len(guard) != 1 or len(success) != 1 or len(failure) != 1:
            continue
        if not same_grok_path(success[0].script_path, failure[0].script_path):
            continue
        contracts.append(GrokRuntimeContract(
            agent_id=guard[0].agent_id,
            guard_path=guard[0].script_path,
            audit_path=success[0].script_path,
        ))
    return contracts
