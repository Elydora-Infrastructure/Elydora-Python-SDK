"""Gemini CLI hook schema, controls, and exact ownership rules."""

from __future__ import annotations

from dataclasses import dataclass
import math
import os
from typing import Any, Dict, List, Optional, Tuple

from .gemini_command import (
    GeminiRuntimeReference,
    build_gemini_command,
    gemini_runtime_reference,
    same_gemini_agent_id,
)


AGENT_KEY = "gemini"
CONFIG_FILE = "settings.json"
GUARD_SCRIPT = "guard.py"
AUDIT_SCRIPT = "hook.py"
GUARD_HOOK_NAME = "elydora-guard"
AUDIT_HOOK_NAME = "elydora-audit"
HOOK_TIMEOUT_MILLISECONDS = 10_000
MANAGED_EVENTS = ("BeforeTool", "AfterTool")

KNOWN_EVENTS = {
    "BeforeTool",
    "AfterTool",
    "BeforeAgent",
    "Notification",
    "AfterAgent",
    "SessionStart",
    "SessionEnd",
    "PreCompress",
    "BeforeModel",
    "AfterModel",
    "BeforeToolSelection",
}

JsonObject = Dict[str, Any]
GeminiHooks = Dict[str, List[JsonObject]]


@dataclass(frozen=True)
class GeminiHookControls:
    enabled: bool
    disabled: Tuple[str, ...]


@dataclass(frozen=True)
class GeminiRuntimeContract:
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
    return os.path.join(os.path.expanduser("~"), ".elydora")


def _optional_string(value: JsonObject, field: str, label: str) -> None:
    if field in value and not isinstance(value[field], str):
        raise ValueError(f'{label} field "{field}" must be a string')


def _validate_timeout(value: JsonObject, label: str) -> None:
    if "timeout" not in value:
        return
    timeout = value["timeout"]
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(float(timeout))
        or timeout < 0
    ):
        raise ValueError(f"{label} timeout must be a non-negative finite number")


def _validate_environment(value: JsonObject, label: str) -> None:
    if "env" not in value:
        return
    environment = value["env"]
    if not isinstance(environment, dict) or any(
        not isinstance(item, str) for item in environment.values()
    ):
        raise ValueError(f"{label} env must map names to strings")


def _validate_handler(
    value: Any, event: str, group_index: int, handler_index: int
) -> JsonObject:
    label = (
        f"Gemini CLI settings handler hooks.{event}[{group_index}]"
        f".hooks[{handler_index}]"
    )
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    handler = dict(value)
    if handler.get("type") != "command":
        raise ValueError(
            f'{label} has unsupported type "{handler.get("type")}"'
        )
    for field in ("name", "description", "source"):
        _optional_string(handler, field, label)
    _validate_timeout(handler, label)
    _validate_environment(handler, label)
    if not isinstance(handler.get("command"), str) or not handler["command"]:
        raise ValueError(f"{label} requires a non-empty command")
    return handler


def _validate_group(value: Any, event: str, index: int) -> JsonObject:
    label = f"Gemini CLI settings group hooks.{event}[{index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    group = dict(value)
    if "matcher" in group and not isinstance(group["matcher"], str):
        raise ValueError(f"{label} matcher must be a string")
    if "sequential" in group and not isinstance(group["sequential"], bool):
        raise ValueError(f"{label} sequential must be a boolean")
    handlers = group.get("hooks")
    if not isinstance(handlers, list):
        raise ValueError(f"{label} must contain a hooks array")
    group["hooks"] = [
        _validate_handler(handler, event, index, handler_index)
        for handler_index, handler in enumerate(handlers)
    ]
    return group


def read_gemini_hooks(value: Any) -> GeminiHooks:
    if not isinstance(value, dict):
        raise ValueError('Gemini CLI settings field "hooks" must be an object')
    hooks: GeminiHooks = {}
    for event, groups in value.items():
        if not isinstance(groups, list):
            raise ValueError(
                f'Gemini CLI settings field "hooks.{event}" must be an array'
            )
        hooks[event] = (
            [
                _validate_group(group, event, index)
                for index, group in enumerate(groups)
            ]
            if event in KNOWN_EVENTS
            else list(groups)
        )
    return hooks


def read_gemini_hook_controls(value: Any) -> GeminiHookControls:
    if not isinstance(value, dict):
        raise ValueError(
            'Gemini CLI settings field "hooksConfig" must be an object'
        )
    supported = {"enabled", "disabled", "notifications"}
    extra = next((field for field in value if field not in supported), None)
    if extra is not None:
        raise ValueError(
            "Gemini CLI settings field \"hooksConfig\" contains unsupported "
            f'field "{extra}"'
        )
    if "enabled" in value and not isinstance(value["enabled"], bool):
        raise ValueError(
            'Gemini CLI settings field "hooksConfig.enabled" must be a boolean'
        )
    if "notifications" in value and not isinstance(
        value["notifications"], bool
    ):
        raise ValueError(
            "Gemini CLI settings field \"hooksConfig.notifications\" must be "
            "a boolean"
        )
    disabled = value.get("disabled", [])
    if not isinstance(disabled, list) or any(
        not isinstance(item, str) for item in disabled
    ):
        raise ValueError(
            "Gemini CLI settings field \"hooksConfig.disabled\" must be an "
            "array of strings"
        )
    return GeminiHookControls(value.get("enabled") is not False, tuple(disabled))


def managed_gemini_hooks_enabled(controls: GeminiHookControls) -> bool:
    return (
        controls.enabled
        and GUARD_HOOK_NAME not in controls.disabled
        and AUDIT_HOOK_NAME not in controls.disabled
    )


def disabled_managed_gemini_entries(
    controls: GeminiHookControls,
) -> Tuple[str, ...]:
    return tuple(
        entry
        for entry in controls.disabled
        if entry in {GUARD_HOOK_NAME, AUDIT_HOOK_NAME}
        or gemini_runtime_reference(entry, GUARD_SCRIPT, True) is not None
        or gemini_runtime_reference(entry, AUDIT_SCRIPT, True) is not None
    )


def build_gemini_group(script_path: str, name: str) -> JsonObject:
    return {
        "hooks": [{
            "type": "command",
            "name": name,
            "command": build_gemini_command(script_path),
            "timeout": HOOK_TIMEOUT_MILLISECONDS,
        }]
    }


def _exact_managed_group(group: JsonObject) -> bool:
    return set(group) == {"hooks"}


def _current_managed_reference(
    handler: JsonObject, script_name: str, hook_name: str
) -> Optional[GeminiRuntimeReference]:
    if (
        set(handler) == {"command", "name", "timeout", "type"}
        and handler.get("type") == "command"
        and handler.get("name") == hook_name
        and handler.get("timeout") == HOOK_TIMEOUT_MILLISECONDS
        and isinstance(handler.get("command"), str)
    ):
        return gemini_runtime_reference(handler["command"], script_name)
    return None


def _legacy_managed_reference(
    handler: JsonObject, script_name: str
) -> Optional[GeminiRuntimeReference]:
    if (
        set(handler) == {"command", "type"}
        and handler.get("type") == "command"
        and isinstance(handler.get("command"), str)
    ):
        return gemini_runtime_reference(handler["command"], script_name, True)
    return None


def _managed_reference(
    handler: JsonObject,
    script_name: str,
    hook_name: str,
    include_legacy: bool,
) -> Optional[GeminiRuntimeReference]:
    current = _current_managed_reference(handler, script_name, hook_name)
    if current is not None or not include_legacy:
        return current
    return _legacy_managed_reference(handler, script_name)


def managed_gemini_removals(
    hooks: GeminiHooks, agent_id: Optional[str] = None
) -> List[ManagedRemoval]:
    removals = []
    for event, script_name, hook_name in (
        ("BeforeTool", GUARD_SCRIPT, GUARD_HOOK_NAME),
        ("AfterTool", AUDIT_SCRIPT, AUDIT_HOOK_NAME),
    ):
        for group_index, group in enumerate(hooks.get(event, [])):
            handlers = group.get("hooks", [])
            indexes = tuple(
                index
                for index, handler in enumerate(handlers)
                if isinstance(handler, dict)
                and (
                    reference := _managed_reference(
                        handler, script_name, hook_name, True
                    )
                )
                is not None
                and (
                    agent_id is None
                    or same_gemini_agent_id(reference.agent_id, agent_id)
                )
            )
            if indexes:
                removals.append(
                    ManagedRemoval(
                        event,
                        group_index,
                        indexes,
                        _exact_managed_group(group)
                        and len(indexes) == len(handlers),
                    )
                )
    return removals


def _references_for_event(
    groups: List[JsonObject], script_name: str, hook_name: str
) -> Dict[str, List[GeminiRuntimeReference]]:
    result: Dict[str, List[GeminiRuntimeReference]] = {}
    for group in groups:
        if not _exact_managed_group(group):
            continue
        for handler in group["hooks"]:
            reference = _current_managed_reference(
                handler, script_name, hook_name
            )
            if reference is None:
                continue
            key = os.path.normcase(reference.agent_id)
            result.setdefault(key, []).append(reference)
    return result


def gemini_runtime_contracts(
    hooks: GeminiHooks,
) -> List[GeminiRuntimeContract]:
    guards = _references_for_event(
        hooks.get("BeforeTool", []), GUARD_SCRIPT, GUARD_HOOK_NAME
    )
    audits = _references_for_event(
        hooks.get("AfterTool", []), AUDIT_SCRIPT, AUDIT_HOOK_NAME
    )
    contracts = []
    for key, guard in guards.items():
        audit = audits.get(key, [])
        if len(guard) != 1 or len(audit) != 1:
            continue
        contracts.append(
            GeminiRuntimeContract(
                guard[0].agent_id,
                guard[0].script_path,
                audit[0].script_path,
            )
        )
    return contracts
