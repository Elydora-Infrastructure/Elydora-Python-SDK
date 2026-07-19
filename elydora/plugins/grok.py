"""Grok Build native user-hook integration."""

from __future__ import annotations

from dataclasses import dataclass
import math
import os
import shlex
# subprocess provides argument quoting only; this module starts no process.
import subprocess  # nosec B404
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

from ._file_io import (
    read_json as _read_json,
    regular_file_exists as _regular_file_exists,
    remove_file as _remove_file,
    require_runtime as _require_runtime,
    write_json_atomic as _write_json_atomic,
    write_text_atomic as _write_text_atomic,
)
from .base import AgentPlugin, InstallConfig, PluginStatus
from .hook_template import generate_hook_script


AGENT_KEY = "grok"
GUARD_SCRIPT = "guard.py"
AUDIT_SCRIPT = "hook.py"
HOOK_TIMEOUT_SECONDS = 10
CONFIG_FILE = "elydora-audit.json"
ELYDORA_DIR = os.path.join(os.path.expanduser("~"), ".elydora")

JsonObject = Dict[str, Any]
GrokHooks = Dict[str, List[JsonObject]]


@dataclass(frozen=True)
class GrokDocument:
    exists: bool
    config_path: str
    root: JsonObject
    hooks: GrokHooks


@dataclass(frozen=True)
class RuntimeContract:
    agent_id: str
    guard_path: str
    audit_path: str


def _home_dir() -> str:
    return os.path.expanduser("~")


def _resolve_config_path() -> str:
    grok_home = os.environ.get("GROK_HOME") or os.path.join(_home_dir(), ".grok")
    return os.path.join(grok_home, "hooks", CONFIG_FILE)


def _build_command(script_path: str) -> str:
    arguments = [sys.executable, script_path]
    return (
        subprocess.list2cmdline(arguments)
        if os.name == "nt"
        else shlex.join(arguments)
    )


def _build_handler(script_path: str) -> JsonObject:
    return {
        "type": "command",
        "command": _build_command(script_path),
        "timeout": HOOK_TIMEOUT_SECONDS,
    }


def _parse_generated_command(command: str) -> Optional[Tuple[str, str]]:
    try:
        arguments = shlex.split(command, posix=os.name != "nt")
    except ValueError:
        return None
    if os.name == "nt":
        arguments = [
            value[1:-1]
            if len(value) >= 2 and value.startswith('"') and value.endswith('"')
            else value
            for value in arguments
        ]
    if len(arguments) != 2 or not arguments[0] or not arguments[1]:
        return None
    return arguments[0], arguments[1]


def _same_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(
        os.path.abspath(right)
    )


def _same_agent_id(left: str, right: str) -> bool:
    return os.path.normcase(left) == os.path.normcase(right)


def _managed_agent_id(handler: JsonObject, script_name: str) -> Optional[str]:
    if (
        handler.get("type") != "command"
        or handler.get("timeout") != HOOK_TIMEOUT_SECONDS
        or not isinstance(handler.get("command"), str)
    ):
        return None
    parsed = _parse_generated_command(str(handler["command"]))
    if parsed is None:
        return None
    script_path = parsed[1]
    if os.path.normcase(os.path.basename(script_path)) != os.path.normcase(script_name):
        return None
    agent_dir = os.path.dirname(script_path)
    if not _same_path(os.path.dirname(agent_dir), ELYDORA_DIR):
        return None
    agent_id = os.path.basename(agent_dir)
    return agent_id if agent_id not in {"", ".", ".."} else None


def _validate_handler(
    value: Any,
    event: str,
    group_index: int,
    handler_index: int,
) -> JsonObject:
    label = (
        f"Grok hooks config handler hooks.{event}[{group_index}]"
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
    if timeout is not None and (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError(f"{label} timeout must be a positive number")
    return handler


def _validate_group(value: Any, event: str, group_index: int) -> JsonObject:
    label = f"Grok hooks config group hooks.{event}[{group_index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    group = dict(value)
    matcher = group.get("matcher")
    if "matcher" in group and not isinstance(matcher, str):
        raise ValueError(f"{label} matcher must be a string")
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
    raw_hooks = root["hooks"]
    if not isinstance(raw_hooks, dict):
        raise ValueError('Grok hooks config field "hooks" must be an object')
    hooks: GrokHooks = {}
    for event, groups in raw_hooks.items():
        if not isinstance(groups, list):
            raise ValueError(
                f'Grok hooks config field "hooks.{event}" must be an array'
            )
        hooks[event] = [
            _validate_group(group, event, group_index)
            for group_index, group in enumerate(groups)
        ]
    return hooks


def _read_config() -> GrokDocument:
    config_path = _resolve_config_path()
    root = _read_json(config_path, "Grok hooks config")
    if root is None:
        return GrokDocument(False, config_path, {}, {})
    return GrokDocument(True, config_path, root, _read_hooks(root))


def _remove_managed(
    groups: List[JsonObject],
    script_name: str,
    agent_id: str = "",
) -> Tuple[List[JsonObject], bool]:
    result: List[JsonObject] = []
    changed = False
    for group in groups:
        if "matcher" in group:
            result.append(group)
            continue
        handlers = group["hooks"]
        kept: List[JsonObject] = []
        group_changed = False
        for handler in handlers:
            managed_id = _managed_agent_id(handler, script_name)
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


def _remove_managed_hooks(
    hooks: GrokHooks,
    agent_id: str = "",
) -> Tuple[GrokHooks, bool]:
    result = dict(hooks)
    changed = False
    for event, script_name in (
        ("PreToolUse", GUARD_SCRIPT),
        ("PostToolUse", AUDIT_SCRIPT),
    ):
        groups, event_changed = _remove_managed(
            result.get(event, []), script_name, agent_id
        )
        if not event_changed:
            continue
        changed = True
        if groups:
            result[event] = groups
        else:
            result.pop(event, None)
    return result, changed


def _managed_ids(groups: List[JsonObject], script_name: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for group in groups:
        if "matcher" in group:
            continue
        for handler in group["hooks"]:
            agent_id = _managed_agent_id(handler, script_name)
            if agent_id:
                result[os.path.normcase(agent_id)] = agent_id
    return result


def _runtime_contracts(hooks: GrokHooks) -> List[RuntimeContract]:
    guards = _managed_ids(hooks.get("PreToolUse", []), GUARD_SCRIPT)
    audits = _managed_ids(hooks.get("PostToolUse", []), AUDIT_SCRIPT)
    contracts: List[RuntimeContract] = []
    for normalized_id in sorted(set(guards) & set(audits)):
        agent_id = guards[normalized_id]
        contracts.append(RuntimeContract(
            agent_id=agent_id,
            guard_path=os.path.join(ELYDORA_DIR, agent_id, GUARD_SCRIPT),
            audit_path=os.path.join(ELYDORA_DIR, agent_id, AUDIT_SCRIPT),
        ))
    return contracts


def _runtime_scripts_exist(contracts: List[RuntimeContract]) -> bool:
    try:
        with os.scandir(ELYDORA_DIR) as iterator:
            entries = sorted(iterator, key=lambda entry: entry.name)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise OSError(f"Read Elydora runtime directory at {ELYDORA_DIR}: {error}") from error

    for contract in contracts:
        entry = next(
            (
                candidate
                for candidate in entries
                if _same_agent_id(candidate.name, contract.agent_id)
            ),
            None,
        )
        if entry is None:
            continue
        try:
            if not entry.is_dir(follow_symlinks=False):
                continue
        except OSError as error:
            raise OSError(f"Read Elydora runtime entry at {entry.path}: {error}") from error
        runtime_config_path = os.path.join(entry.path, "config.json")
        runtime_config = _read_json(runtime_config_path, "Elydora runtime config")
        if runtime_config is None:
            continue
        agent_name = runtime_config.get("agent_name")
        if not isinstance(agent_name, str):
            raise ValueError(
                f'Elydora runtime config at {runtime_config_path} field '
                '"agent_name" must be a string'
            )
        if agent_name != AGENT_KEY:
            continue
        guard_path = os.path.join(entry.path, GUARD_SCRIPT)
        audit_path = os.path.join(entry.path, AUDIT_SCRIPT)
        return _regular_file_exists(
            guard_path, "Elydora guard runtime"
        ) and _regular_file_exists(audit_path, "Elydora audit runtime")
    return False


class GrokPlugin(AgentPlugin):
    """Install Elydora into Grok Build's native global user hooks."""

    def install(self, config: InstallConfig) -> None:
        agent_id = config.get("agent_id", "")
        if not agent_id:
            raise ValueError("agent_id is required")
        source = _read_config()
        guard_path = config.get("guard_script_path", "")
        _require_runtime(guard_path, "Elydora guard runtime")
        agent_dir = os.path.join(ELYDORA_DIR, agent_id)
        audit_path = os.path.join(agent_dir, AUDIT_SCRIPT)
        cleaned, _ = _remove_managed_hooks(source.hooks)
        hooks: GrokHooks = {
            **cleaned,
            "PreToolUse": [
                *cleaned.get("PreToolUse", []),
                {"hooks": [_build_handler(guard_path)]},
            ],
            "PostToolUse": [
                *cleaned.get("PostToolUse", []),
                {"hooks": [_build_handler(audit_path)]},
            ],
        }
        runtime_config: JsonObject = {
            "org_id": config.get("org_id", ""),
            "agent_id": agent_id,
            "kid": config.get("kid", ""),
            "base_url": config.get("base_url", "https://api.elydora.com"),
            "token": config.get("token", ""),
            "agent_name": AGENT_KEY,
        }
        audit_script = generate_hook_script(
            org_id=config.get("org_id", ""),
            agent_id=agent_id,
            private_key=config.get("private_key", ""),
            kid=config.get("kid", ""),
            base_url=config.get("base_url", "https://api.elydora.com"),
        )
        _write_json_atomic(
            os.path.join(agent_dir, "config.json"),
            runtime_config,
            0o600,
            "Elydora runtime config",
        )
        _write_text_atomic(
            os.path.join(agent_dir, "private.key"),
            config.get("private_key", ""),
            0o600,
            "Elydora private key",
        )
        _write_text_atomic(audit_path, audit_script, 0o700, "Elydora audit runtime")
        _write_json_atomic(
            source.config_path,
            {**source.root, "hooks": hooks},
            0o600,
            "Grok hooks config",
        )
        print("Grok Build: global PreToolUse and PostToolUse hooks installed.")

    def uninstall(self, agent_id: str = "") -> None:
        source = _read_config()
        if not source.exists:
            return
        hooks, changed = _remove_managed_hooks(source.hooks, agent_id)
        if not changed:
            return
        root = dict(source.root)
        if hooks:
            root["hooks"] = hooks
        else:
            root.pop("hooks", None)
        if root:
            _write_json_atomic(
                source.config_path,
                root,
                0o600,
                "Grok hooks config",
            )
        else:
            _remove_file(source.config_path, "Grok hooks config")

    def status(self) -> PluginStatus:
        source = _read_config()
        contracts = _runtime_contracts(source.hooks)
        if not contracts:
            return PluginStatus(
                installed=False,
                agent=AGENT_KEY,
                details="Not installed",
            )
        installed = _runtime_scripts_exist(contracts)
        details = (
            f"Config: {source.config_path}"
            if installed
            else f"Configured at {source.config_path}; runtime scripts missing"
        )
        return PluginStatus(installed=installed, agent=AGENT_KEY, details=details)
