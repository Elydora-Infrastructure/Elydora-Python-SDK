"""Kimi Code and legacy kimi-cli lifecycle-hook integration."""

from __future__ import annotations

import copy
from dataclasses import dataclass
import os
import shlex
import shutil
# subprocess provides argument quoting only; this module starts no process.
import subprocess  # nosec B404
import sys
from typing import Any, Dict, FrozenSet, List, Optional

from tomlkit import aot, document, dumps, inline_table, parse, table
from tomlkit.items import AoT, Array

from .base import AgentPlugin, InstallConfig, PluginStatus
from ._file_io import (
    read_json as _read_json,
    regular_file_exists as _regular_file_exists,
    remove_file as _remove_file,
    require_runtime as _require_runtime,
    write_json_atomic as _write_json_atomic,
    write_text_atomic as _write_text_atomic,
)
from .hook_template import generate_hook_script


AGENT_KEY = "kimi"
GUARD_SCRIPT = "guard.py"
AUDIT_SCRIPT = "hook.py"
HOOK_TIMEOUT_SECONDS = 10
ELYDORA_DIR = os.path.join(os.path.expanduser("~"), ".elydora")

SHARED_EVENTS: FrozenSet[str] = frozenset({
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
})
MODERN_EVENTS = SHARED_EVENTS | {
    "PermissionRequest",
    "PermissionResult",
    "Interrupt",
}
LEGACY_EVENTS = SHARED_EVENTS
SUPPORTED_FIELDS = frozenset({"event", "matcher", "command", "timeout"})

TomlObject = Dict[str, Any]


@dataclass(frozen=True)
class KimiContract:
    runtime_name: str
    label: str
    config_path: str
    events: FrozenSet[str]


@dataclass(frozen=True)
class KimiDocument:
    contract: KimiContract
    exists: bool
    raw: str
    value: Any
    hooks: List[TomlObject]


@dataclass(frozen=True)
class RuntimeContract:
    guard: str
    audit: str
    config_path: str


@dataclass(frozen=True)
class ConfigMutation:
    kind: str
    source: KimiDocument
    raw: str = ""


def _home_dir() -> str:
    return os.path.expanduser("~")


def _path_exists(path: str, label: str) -> bool:
    try:
        os.stat(path)
        return True
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError as error:
        raise OSError(f"Inspect {label} at {path}: {error}") from error


def _legacy_cli_on_path() -> bool:
    try:
        return shutil.which("kimi-cli") is not None
    except OSError as error:
        raise OSError(f"Inspect kimi-cli executable on PATH: {error}") from error


def _resolve_contracts() -> List[KimiContract]:
    home = _home_dir()
    explicit_home = os.environ.get("KIMI_CODE_HOME") or None
    kimi_home = explicit_home or os.path.join(home, ".kimi-code")
    modern = KimiContract(
        runtime_name="Kimi Code",
        label="Kimi Code hooks config",
        config_path=os.path.join(kimi_home, "config.toml"),
        events=MODERN_EVENTS,
    )
    legacy = KimiContract(
        runtime_name="kimi-cli",
        label="kimi-cli legacy hooks config",
        config_path=os.path.join(home, ".kimi", "config.toml"),
        events=LEGACY_EVENTS,
    )
    modern_detected = explicit_home is not None or _path_exists(
        kimi_home, "Kimi Code home"
    )
    legacy_detected = _path_exists(
        legacy.config_path, legacy.label
    ) or _legacy_cli_on_path()
    if legacy_detected and not modern_detected:
        return [legacy]
    return [modern, legacy] if legacy_detected else [modern]


def _unwrap(value: Any) -> Any:
    unwrap = getattr(value, "unwrap", None)
    return unwrap() if callable(unwrap) else value


def _validate_hook(value: Any, contract: KimiContract, index: int) -> TomlObject:
    raw = _unwrap(value)
    if not isinstance(raw, dict):
        raise ValueError(f"{contract.label} hook {index + 1} must be a table")
    hook = dict(raw)
    unsupported = next((key for key in hook if key not in SUPPORTED_FIELDS), None)
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
        raise ValueError(f"{contract.label} hook {index + 1} matcher must be a string")
    timeout = hook.get("timeout")
    if timeout is not None and (
        isinstance(timeout, bool)
        or not isinstance(timeout, int)
        or timeout < 1
        or timeout > 600
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
    return [_validate_hook(item, contract, index) for index, item in enumerate(raw)]


def _read_config(contract: KimiContract) -> KimiDocument:
    try:
        with open(
            contract.config_path,
            "r",
            encoding="utf-8",
            newline="",
        ) as file:
            raw = file.read()
    except FileNotFoundError:
        value = document()
        return KimiDocument(contract, False, "", value, [])
    except OSError as error:
        raise OSError(
            f"Read {contract.label} at {contract.config_path}: {error}"
        ) from error

    try:
        value = parse(raw)
    except Exception as error:
        raise ValueError(
            f"Failed to parse {contract.label} at {contract.config_path}: {error}"
        ) from error
    return KimiDocument(contract, True, raw, value, _read_hooks(value, contract))


def _read_all_configs() -> List[KimiDocument]:
    return [_read_config(contract) for contract in _resolve_contracts()]


def _build_command(script_path: str) -> str:
    arguments = [sys.executable, script_path]
    return (
        subprocess.list2cmdline(arguments)
        if os.name == "nt"
        else shlex.join(arguments)
    )


def _build_hook(event: str, script_path: str) -> TomlObject:
    return {
        "event": event,
        "command": _build_command(script_path),
        "timeout": HOOK_TIMEOUT_SECONDS,
    }


def _render_hooks(
    source: KimiDocument,
    keep_indices: List[int],
    additions: List[TomlObject],
) -> str:
    candidate = copy.deepcopy(source.value)
    if "hooks" in candidate:
        container: Any = candidate["hooks"]
        if not isinstance(container, (AoT, Array)):
            raise ValueError(f'{source.contract.label} field "hooks" must be an array')
        keep = set(keep_indices)
        for index in range(len(source.hooks) - 1, -1, -1):
            if index not in keep:
                del container[index]
    else:
        container = aot()
        candidate.add("hooks", container)

    for hook in additions:
        item = table() if isinstance(container, AoT) else inline_table()
        for key, value in hook.items():
            item[key] = value
        container.append(item)
    if len(container) == 0:
        del candidate["hooks"]
    return dumps(candidate)


def _normalize(value: str) -> str:
    return os.path.normcase(value)


def _command_references(command: str, path: str) -> bool:
    return _normalize(path) in _normalize(command)


def _is_managed_hook(
    hook: TomlObject,
    event: str,
    script_name: str,
    agent_id: str = "",
) -> bool:
    if hook.get("event") != event or not isinstance(hook.get("command"), str):
        return False
    command = str(hook["command"])
    if agent_id:
        script_path = os.path.join(ELYDORA_DIR, agent_id, script_name)
        return _command_references(command, script_path)
    normalized = _normalize(command)
    return (
        _normalize(f"{os.sep}.elydora{os.sep}") in normalized
        and _normalize(f"{os.sep}{script_name}") in normalized
    )


def _kept_hook_indices(source: KimiDocument, agent_id: str = "") -> List[int]:
    return [
        index
        for index, hook in enumerate(source.hooks)
        if not _is_managed_hook(hook, "PreToolUse", GUARD_SCRIPT, agent_id)
        and not _is_managed_hook(hook, "PostToolUse", AUDIT_SCRIPT, agent_id)
    ]


def _runtime_contract(source: KimiDocument) -> Optional[RuntimeContract]:
    guard = next(
        (
            hook
            for hook in source.hooks
            if _is_managed_hook(hook, "PreToolUse", GUARD_SCRIPT)
        ),
        None,
    )
    audit = next(
        (
            hook
            for hook in source.hooks
            if _is_managed_hook(hook, "PostToolUse", AUDIT_SCRIPT)
        ),
        None,
    )
    if guard is None or audit is None:
        return None
    return RuntimeContract(
        guard=str(guard["command"]),
        audit=str(audit["command"]),
        config_path=source.contract.config_path,
    )


def _runtime_scripts_exist(contracts: List[RuntimeContract]) -> bool:
    try:
        with os.scandir(ELYDORA_DIR) as iterator:
            entries = sorted(iterator, key=lambda entry: entry.name)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise OSError(f"Read Elydora runtime directory at {ELYDORA_DIR}: {error}") from error

    for entry in entries:
        try:
            if not entry.is_dir(follow_symlinks=False):
                continue
        except OSError as error:
            raise OSError(f"Read Elydora runtime entry at {entry.path}: {error}") from error
        guard_path = os.path.join(entry.path, GUARD_SCRIPT)
        audit_path = os.path.join(entry.path, AUDIT_SCRIPT)
        if not any(
            _command_references(contract.guard, guard_path)
            and _command_references(contract.audit, audit_path)
            for contract in contracts
        ):
            continue
        config_path = os.path.join(entry.path, "config.json")
        runtime_config = _read_json(config_path, "Elydora runtime config")
        if runtime_config is None:
            continue
        agent_name = runtime_config.get("agent_name")
        if not isinstance(agent_name, str):
            raise ValueError(
                f'Elydora runtime config at {config_path} field "agent_name" '
                "must be a string"
            )
        if agent_name != AGENT_KEY:
            continue
        return _regular_file_exists(
            guard_path, "Elydora guard runtime"
        ) and _regular_file_exists(audit_path, "Elydora audit runtime")
    return False


def _apply_mutation(mutation: ConfigMutation) -> None:
    path = mutation.source.contract.config_path
    if mutation.kind == "write":
        _write_text_atomic(path, mutation.raw, 0o600, mutation.source.contract.label)
    elif mutation.kind == "remove":
        _remove_file(path, mutation.source.contract.label)


class KimiPlugin(AgentPlugin):
    """Install Elydora into detected Kimi user hook contracts."""

    def install(self, config: InstallConfig) -> None:
        agent_id = config.get("agent_id", "")
        if not agent_id:
            raise ValueError("agent_id is required")
        sources = _read_all_configs()
        guard_path = config.get("guard_script_path", "")
        _require_runtime(guard_path, "Elydora guard runtime")
        agent_dir = os.path.join(ELYDORA_DIR, agent_id)
        audit_path = os.path.join(agent_dir, AUDIT_SCRIPT)
        mutations = [
            ConfigMutation(
                "write",
                source,
                _render_hooks(
                    source,
                    _kept_hook_indices(source),
                    [
                        _build_hook("PreToolUse", guard_path),
                        _build_hook("PostToolUse", audit_path),
                    ],
                ),
            )
            for source in sources
        ]
        runtime_config: TomlObject = {
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
        for mutation in mutations:
            _apply_mutation(mutation)
        runtimes = " and ".join(source.contract.runtime_name for source in sources)
        print(f"{runtimes}: global PreToolUse and PostToolUse hooks installed.")

    def uninstall(self, agent_id: str = "") -> None:
        sources = _read_all_configs()
        mutations: List[ConfigMutation] = []
        for source in sources:
            keep_indices = _kept_hook_indices(source, agent_id)
            if len(keep_indices) == len(source.hooks):
                mutations.append(ConfigMutation("none", source))
                continue
            raw = _render_hooks(source, keep_indices, [])
            mutations.append(
                ConfigMutation("write" if raw.strip() else "remove", source, raw)
            )
        for mutation in mutations:
            _apply_mutation(mutation)

    def status(self) -> PluginStatus:
        sources = _read_all_configs()
        contracts = [
            contract
            for source in sources
            for contract in [_runtime_contract(source)]
            if contract is not None
        ]
        if not contracts:
            return PluginStatus(
                installed=False,
                agent=AGENT_KEY,
                details="Not installed",
            )
        installed = _runtime_scripts_exist(contracts)
        paths = ", ".join(contract.config_path for contract in contracts)
        details = (
            f"Config: {paths}"
            if installed
            else f"Configured at {paths}; runtime scripts missing"
        )
        return PluginStatus(installed=installed, agent=AGENT_KEY, details=details)
