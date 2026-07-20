"""Letta Code 0.28 hook schema and exact ownership rules."""

from __future__ import annotations

from dataclasses import dataclass
import math
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

from elydora._runtime_paths import runtime_root

from .letta_command import (
    LettaRuntimeReference,
    build_letta_command,
    letta_legacy_audit_reference,
    letta_legacy_guard_reference,
    letta_runtime_reference,
    same_letta_agent_id,
    same_letta_path,
)


AGENT_KEY = "letta"
GUARD_SCRIPT = "guard.py"
AUDIT_SCRIPT = "hook.py"
HOOK_TIMEOUT_MILLISECONDS = 10_000
MANAGED_EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure")

TOOL_EVENTS = {
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "PermissionRequest",
}
SIMPLE_EVENTS = {
    "UserPromptSubmit",
    "Notification",
    "Stop",
    "SubagentStop",
    "PreCompact",
    "SessionStart",
    "SessionEnd",
}
KNOWN_EVENTS = TOOL_EVENTS | SIMPLE_EVENTS

JsonObject = Dict[str, Any]
LettaHooks = Dict[str, Any]


@dataclass(frozen=True)
class LettaRuntimeContract:
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
    return runtime_root()


def _validate_timeout(value: JsonObject, label: str) -> None:
    if "timeout" not in value:
        return
    timeout = value["timeout"]
    try:
        finite = math.isfinite(timeout)
    except (TypeError, OverflowError):
        finite = False
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not finite
        or timeout < 0
    ):
        raise ValueError(f"{label} timeout must be a non-negative finite number")


def _validate_handler(value: Any, label: str) -> JsonObject:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    handler = dict(value)
    kind = handler.get("type")
    if kind not in {"command", "prompt"}:
        raise ValueError(f'{label} has unsupported type "{kind}"')
    _validate_timeout(handler, label)
    if "quiet" in handler and not isinstance(handler["quiet"], bool):
        raise ValueError(f"{label} quiet must be a boolean")
    if kind == "command":
        command = handler.get("command")
        if not isinstance(command, str) or not command:
            raise ValueError(f"{label} requires a non-empty command")
    else:
        prompt = handler.get("prompt")
        if not isinstance(prompt, str) or not prompt:
            raise ValueError(f"{label} requires a non-empty prompt")
        if "model" in handler and not isinstance(handler["model"], str):
            raise ValueError(f"{label} model must be a string")
    return handler


def _validate_group(value: Any, event: str, index: int) -> JsonObject:
    label = f"Letta Code settings group hooks.{event}[{index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    group = dict(value)
    if event in TOOL_EVENTS:
        if not isinstance(group.get("matcher"), str):
            raise ValueError(f"{label} matcher must be a string")
    elif "matcher" in group:
        raise ValueError(f"{label} matcher is unsupported for {event}")
    handlers = group.get("hooks")
    if not isinstance(handlers, list):
        raise ValueError(f"{label} must contain a hooks array")
    group["hooks"] = [
        _validate_handler(handler, f"{label}.hooks[{handler_index}]")
        for handler_index, handler in enumerate(handlers)
    ]
    return group


def read_letta_hooks(value: Any) -> LettaHooks:
    if not isinstance(value, dict):
        raise ValueError('Letta Code settings field "hooks" must be an object')
    if "disabled" in value and not isinstance(value["disabled"], bool):
        raise ValueError(
            'Letta Code settings field "hooks.disabled" must be a boolean'
        )
    hooks: LettaHooks = {}
    for event, groups in value.items():
        if event == "disabled" or event not in KNOWN_EVENTS:
            hooks[event] = groups
            continue
        if not isinstance(groups, list):
            raise ValueError(
                f'Letta Code settings field "hooks.{event}" must be an array'
            )
        hooks[event] = [
            _validate_group(group, event, index)
            for index, group in enumerate(groups)
        ]
    return hooks


def build_letta_group(script_path: str) -> JsonObject:
    return {
        "matcher": "*",
        "hooks": [{
            "type": "command",
            "command": build_letta_command(script_path),
            "timeout": HOOK_TIMEOUT_MILLISECONDS,
        }],
    }


def _exact_group(group: JsonObject) -> bool:
    return set(group) == {"matcher", "hooks"} and group.get("matcher") == "*"


def _current_reference(
    handler: JsonObject, script_name: str
) -> Optional[LettaRuntimeReference]:
    if (
        set(handler) == {"type", "command", "timeout"}
        and handler.get("type") == "command"
        and handler.get("timeout") == HOOK_TIMEOUT_MILLISECONDS
        and isinstance(handler.get("command"), str)
    ):
        return letta_runtime_reference(handler["command"], script_name)
    return None


def _legacy_reference(
    event: str, handler: JsonObject, script_name: str
) -> Optional[LettaRuntimeReference]:
    if (
        set(handler) != {"type", "command"}
        or handler.get("type") != "command"
        or not isinstance(handler.get("command"), str)
    ):
        return None
    if event == "PreToolUse":
        return letta_legacy_guard_reference(handler["command"], script_name)
    return letta_legacy_audit_reference(handler["command"], script_name)


def _event_groups(hooks: LettaHooks, event: str) -> List[JsonObject]:
    value = hooks.get(event)
    return value if isinstance(value, list) else []


_EVENT_CONTRACTS = (
    ("PreToolUse", GUARD_SCRIPT),
    ("PostToolUse", AUDIT_SCRIPT),
    ("PostToolUseFailure", AUDIT_SCRIPT),
)


def managed_letta_removals(
    hooks: LettaHooks, agent_id: Optional[str] = None
) -> List[ManagedRemoval]:
    removals: List[ManagedRemoval] = []
    for event, script_name in _EVENT_CONTRACTS:
        for group_index, group in enumerate(_event_groups(hooks, event)):
            indexes = tuple(
                index
                for index, handler in enumerate(group["hooks"])
                if (
                    reference := (
                        _current_reference(handler, script_name)
                        or _legacy_reference(event, handler, script_name)
                    )
                )
                is not None
                and (
                    agent_id is None
                    or same_letta_agent_id(reference.agent_id, agent_id)
                )
            )
            if indexes:
                removals.append(ManagedRemoval(
                    event,
                    group_index,
                    indexes,
                    _exact_group(group) and len(indexes) == len(group["hooks"]),
                ))
    return removals


def _references_for_event(
    groups: List[JsonObject], script_name: str
) -> Dict[str, List[LettaRuntimeReference]]:
    references: Dict[str, List[LettaRuntimeReference]] = {}
    for group in groups:
        if not _exact_group(group):
            continue
        for handler in group["hooks"]:
            reference = _current_reference(handler, script_name)
            if (
                reference is None
                or reference.executable_path is None
                or not same_letta_path(reference.executable_path, sys.executable)
            ):
                continue
            key = os.path.normcase(reference.agent_id)
            references.setdefault(key, []).append(reference)
    return references


def letta_runtime_contracts(hooks: LettaHooks) -> List[LettaRuntimeContract]:
    guards = _references_for_event(_event_groups(hooks, "PreToolUse"), GUARD_SCRIPT)
    posts = _references_for_event(_event_groups(hooks, "PostToolUse"), AUDIT_SCRIPT)
    failures = _references_for_event(
        _event_groups(hooks, "PostToolUseFailure"), AUDIT_SCRIPT
    )
    contracts: List[LettaRuntimeContract] = []
    for key, guard in guards.items():
        post = posts.get(key, [])
        failure = failures.get(key, [])
        if len(guard) != 1 or len(post) != 1 or len(failure) != 1:
            continue
        if not same_letta_path(post[0].script_path, failure[0].script_path):
            continue
        contracts.append(LettaRuntimeContract(
            guard[0].agent_id,
            guard[0].script_path,
            post[0].script_path,
        ))
    return contracts
