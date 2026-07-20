"""Kimi hook schemas, exact ownership, and TOML rendering."""

from __future__ import annotations

import copy
from dataclasses import dataclass
import os
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from tomlkit import aot, document, dumps, inline_table, parse, table
from tomlkit.items import AoT, Array

from .kimi_command import (
    KimiRuntimeReference,
    build_kimi_command,
    kimi_runtime_reference,
    same_kimi_agent_id,
    same_kimi_path,
)


AGENT_KEY = "kimi"
GUARD_SCRIPT = "guard.py"
AUDIT_SCRIPT = "hook.py"
HOOK_TIMEOUT_SECONDS = 10

SHARED_EVENTS: FrozenSet[str] = frozenset(
    {
        "PreToolUse",
        "PostToolUse",
        "PostToolUseFailure",
        "UserPromptSubmit",
        "Stop",
        "StopFailure",
        "SessionStart",
        "SessionEnd",
        "SubagentStart",
        "SubagentStop",
        "PreCompact",
        "PostCompact",
        "Notification",
    }
)
STABLE_EVENTS = SHARED_EVENTS | {
    "PermissionRequest",
    "PermissionResult",
    "Interrupt",
}
LEGACY_EVENTS = SHARED_EVENTS
SUPPORTED_FIELDS = frozenset({"event", "matcher", "command", "timeout"})

TomlObject = Dict[str, Any]
ManagedEvent = str


@dataclass(frozen=True)
class KimiContract:
    generation: str
    runtime_name: str
    label: str
    directory_label: str
    config_path: str
    events: FrozenSet[str]


@dataclass(frozen=True)
class KimiDocument:
    contract: KimiContract
    exists: bool
    value: Any
    hooks: List[TomlObject]
    uses_hook_tables: bool
    raw: Optional[str] = None


@dataclass(frozen=True)
class RenderedKimiDocument:
    document: KimiDocument
    changed: bool
    next_source: Optional[str] = None


@dataclass(frozen=True)
class KimiRuntimeContract:
    agent_id: str
    guard_path: str
    audit_path: str
    config_path: str


def _unwrap(value: Any) -> Any:
    unwrap = getattr(value, "unwrap", None)
    return unwrap() if callable(unwrap) else value


def validate_kimi_hook(
    value: Any, contract: KimiContract, index: int
) -> TomlObject:
    raw = _unwrap(value)
    if not isinstance(raw, dict):
        raise ValueError(f"{contract.label} hook {index + 1} must be a table")
    hook = dict(raw)
    unsupported = next(
        (key for key in hook if key not in SUPPORTED_FIELDS),
        None,
    )
    if unsupported is not None:
        raise ValueError(
            f'{contract.label} hook {index + 1} has unsupported field "{unsupported}"'
        )
    event = hook.get("event")
    if not isinstance(event, str) or event not in contract.events:
        raise ValueError(
            f'{contract.label} hook {index + 1} has unsupported event "{event}"'
        )
    command = hook.get("command")
    if not isinstance(command, str) or not command:
        raise ValueError(
            f"{contract.label} hook {index + 1} requires a non-empty command"
        )
    matcher = hook.get("matcher")
    if matcher is not None and not isinstance(matcher, str):
        raise ValueError(
            f"{contract.label} hook {index + 1} matcher must be a string"
        )
    timeout = hook.get("timeout")
    if timeout is not None and (
        type(timeout) is not int or timeout < 1 or timeout > 600
    ):
        raise ValueError(
            f"{contract.label} hook {index + 1} timeout must be an integer from 1 to 600"
        )
    return hook


def _read_hooks(value: Any, contract: KimiContract) -> List[TomlObject]:
    if "hooks" not in value:
        return []
    container = value["hooks"]
    raw = _unwrap(container)
    if not isinstance(raw, list):
        raise ValueError(f'{contract.label} field "hooks" must be an array')
    return [
        validate_kimi_hook(item, contract, index)
        for index, item in enumerate(raw)
    ]


def parse_kimi_document(contract: KimiContract, raw: str) -> KimiDocument:
    try:
        value = parse(raw)
    except Exception as error:
        raise ValueError(
            f"Failed to parse {contract.label} at {contract.config_path}: {error}"
        ) from error
    hooks = _read_hooks(value, contract)
    return KimiDocument(
        contract=contract,
        exists=True,
        value=value,
        hooks=hooks,
        uses_hook_tables=isinstance(value.get("hooks"), AoT),
        raw=raw,
    )


def create_kimi_document(contract: KimiContract) -> KimiDocument:
    return KimiDocument(contract, False, document(), [], False)


def build_kimi_hook(event: ManagedEvent, script_path: str) -> TomlObject:
    if event not in {"PreToolUse", "PostToolUse", "PostToolUseFailure"}:
        raise ValueError(f"Unsupported managed Kimi event: {event}")
    return {
        "event": event,
        "command": build_kimi_command(script_path),
        "timeout": HOOK_TIMEOUT_SECONDS,
    }


def _managed_reference(
    hook: TomlObject,
    event: ManagedEvent,
    script_name: str,
) -> Optional[KimiRuntimeReference]:
    if (
        set(hook) != {"event", "command", "timeout"}
        or hook.get("event") != event
        or type(hook.get("timeout")) is not int
        or hook.get("timeout") != HOOK_TIMEOUT_SECONDS
        or not isinstance(hook.get("command"), str)
    ):
        return None
    return kimi_runtime_reference(str(hook["command"]), script_name)


def _managed_contract(event: Any) -> Optional[Tuple[ManagedEvent, str]]:
    if event == "PreToolUse":
        return "PreToolUse", GUARD_SCRIPT
    if event == "PostToolUse":
        return "PostToolUse", AUDIT_SCRIPT
    if event == "PostToolUseFailure":
        return "PostToolUseFailure", AUDIT_SCRIPT
    return None


def remove_managed_kimi_hooks(
    hooks: List[TomlObject], agent_id: str = ""
) -> List[TomlObject]:
    result = []
    for hook in hooks:
        expected = _managed_contract(hook.get("event"))
        reference = (
            _managed_reference(hook, expected[0], expected[1])
            if expected is not None
            else None
        )
        remove = reference is not None and (
            not agent_id or same_kimi_agent_id(reference.agent_id, agent_id)
        )
        if not remove:
            result.append(hook)
    return result


def _matched_indices(
    original: List[TomlObject], desired: List[TomlObject]
) -> Tuple[set[int], set[int]]:
    original_matches: set[int] = set()
    desired_matches: set[int] = set()
    start = 0
    for desired_index, desired_hook in enumerate(desired):
        for original_index in range(start, len(original)):
            if original[original_index] == desired_hook:
                original_matches.add(original_index)
                desired_matches.add(desired_index)
                start = original_index + 1
                break
    return original_matches, desired_matches


def _append_hook(container: Any, hook: TomlObject) -> None:
    item = table() if isinstance(container, AoT) else inline_table()
    for key, value in hook.items():
        item[key] = value
    container.append(item)


def _render_hook_source(
    source: KimiDocument, hooks: List[TomlObject]
) -> Optional[str]:
    candidate = copy.deepcopy(source.value)
    original_matches, desired_matches = _matched_indices(source.hooks, hooks)
    if "hooks" in candidate:
        container: Any = candidate["hooks"]
        if not isinstance(container, (AoT, Array)):
            raise ValueError(f'{source.contract.label} field "hooks" must be an array')
        for index in range(len(source.hooks) - 1, -1, -1):
            if index not in original_matches:
                del container[index]
    else:
        container = aot()
        candidate.add("hooks", container)

    for index, hook in enumerate(hooks):
        if index not in desired_matches:
            _append_hook(container, hook)

    if len(container) == 0 and source.uses_hook_tables:
        del candidate["hooks"]
    rendered = dumps(candidate)
    if not rendered.strip():
        return None
    parse_kimi_document(source.contract, rendered)
    return rendered


def render_kimi_document(
    source: KimiDocument, hooks: List[TomlObject]
) -> RenderedKimiDocument:
    if not source.exists and not hooks:
        return RenderedKimiDocument(source, False)
    next_source = _render_hook_source(source, hooks)
    return RenderedKimiDocument(
        document=source,
        changed=next_source != source.raw,
        next_source=next_source,
    )


def _references_for_event(
    hooks: List[TomlObject], event: ManagedEvent, script_name: str
) -> Dict[str, List[KimiRuntimeReference]]:
    result: Dict[str, List[KimiRuntimeReference]] = {}
    for hook in hooks:
        reference = _managed_reference(hook, event, script_name)
        if reference is None:
            continue
        key = os.path.normcase(reference.agent_id)
        result.setdefault(key, []).append(reference)
    return result


def kimi_runtime_contracts(
    documents: List[KimiDocument],
) -> List[KimiRuntimeContract]:
    contracts: List[KimiRuntimeContract] = []
    for source in documents:
        guards = _references_for_event(source.hooks, "PreToolUse", GUARD_SCRIPT)
        successes = _references_for_event(
            source.hooks, "PostToolUse", AUDIT_SCRIPT
        )
        failures = _references_for_event(
            source.hooks, "PostToolUseFailure", AUDIT_SCRIPT
        )
        for key, guard in guards.items():
            success = successes.get(key, [])
            failure = failures.get(key, [])
            if len(guard) != 1 or len(success) != 1 or len(failure) != 1:
                continue
            if not same_kimi_path(success[0].script_path, failure[0].script_path):
                continue
            contracts.append(
                KimiRuntimeContract(
                    agent_id=guard[0].agent_id,
                    guard_path=guard[0].script_path,
                    audit_path=success[0].script_path,
                    config_path=source.contract.config_path,
                )
            )
    return contracts
