"""Kiro CLI v2 custom-agent and v3 standalone-hook integration."""

from __future__ import annotations

import json
import os
import shlex
import stat
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from .base import AgentPlugin, InstallConfig, PluginStatus
from .hook_template import generate_hook_script


AGENT_KEY = "kirocli"
V2_AGENT_NAME = "elydora-audit"
V2_DESCRIPTION = "Kiro CLI with Elydora audit and freeze enforcement"
V3_GUARD_NAME = "elydora-guard"
V3_AUDIT_NAME = "elydora-audit"
ELYDORA_DIR = os.path.join(os.path.expanduser("~"), ".elydora")
V2_AGENT_PATH = os.path.join(
    os.path.expanduser("~"), ".kiro", "agents", f"{V2_AGENT_NAME}.json"
)
V3_HOOKS_PATH = os.path.join(
    os.path.expanduser("~"), ".kiro", "hooks", "elydora-audit.json"
)

JsonObject = Dict[str, Any]
HookContract = Tuple[str, str, str]


class KiroCliPlugin(AgentPlugin):
    """Install Elydora into both supported Kiro CLI hook generations."""

    def install(self, config: InstallConfig) -> None:
        agent_id = config.get("agent_id", "")
        guard_path = config.get("guard_script_path", "")
        if not agent_id:
            raise ValueError("agent_id is required")
        if not guard_path:
            raise ValueError("guard_script_path is required")
        if not _regular_file_exists(guard_path, "Elydora guard runtime"):
            raise FileNotFoundError(f"Elydora guard runtime is missing: {guard_path}")

        v2_settings = _read_json(V2_AGENT_PATH, "Kiro CLI v2 agent config") or {}
        v3_settings = _read_json(V3_HOOKS_PATH, "Kiro CLI v3 hooks config") or {}
        v2_hooks = _hooks_object(v2_settings, "Kiro CLI v2 agent config")
        current_v3_hooks = _v3_hooks(v3_settings)

        v2_hooks["preToolUse"] = [
            *_without_v2_hooks(
                _hook_entries(v2_hooks, "preToolUse", "Kiro CLI v2 agent config")
            ),
            _build_v2_hook(guard_path),
        ]

        agent_dir = os.path.join(ELYDORA_DIR, agent_id)
        hook_path = os.path.join(agent_dir, "hook.py")
        v2_hooks["postToolUse"] = [
            *_without_v2_hooks(
                _hook_entries(v2_hooks, "postToolUse", "Kiro CLI v2 agent config")
            ),
            _build_v2_hook(hook_path),
        ]

        next_v2_settings: JsonObject = {
            "name": V2_AGENT_NAME,
            "description": V2_DESCRIPTION,
            "tools": ["*"],
            "includeMcpJson": True,
            **v2_settings,
            "hooks": v2_hooks,
        }
        next_v3_settings: JsonObject = {
            **v3_settings,
            "version": "v1",
            "hooks": [
                *[hook for hook in current_v3_hooks if not _is_managed_v3_hook(hook)],
                _build_v3_hook(
                    V3_GUARD_NAME,
                    "Block tool use when the Elydora agent is frozen",
                    "PreToolUse",
                    guard_path,
                ),
                _build_v3_hook(
                    V3_AUDIT_NAME,
                    "Record tool use in the Elydora audit trail",
                    "PostToolUse",
                    hook_path,
                ),
            ],
        }

        runtime_config = {
            "org_id": config.get("org_id", ""),
            "agent_id": agent_id,
            "kid": config.get("kid", ""),
            "base_url": config.get("base_url", "https://api.elydora.com"),
            "token": config.get("token", ""),
            "agent_name": config.get("agent_name", AGENT_KEY),
        }
        hook_script = generate_hook_script(
            org_id=config.get("org_id", ""),
            agent_id=agent_id,
            kid=config.get("kid", ""),
            base_url=config.get("base_url", "https://api.elydora.com"),
        )
        _write_json_atomic(os.path.join(agent_dir, "config.json"), runtime_config, 0o600)
        _write_text_atomic(
            os.path.join(agent_dir, "private.key"),
            config.get("private_key", ""),
            0o600,
        )
        _write_text_atomic(hook_path, hook_script, 0o700)
        _write_json_atomic(V2_AGENT_PATH, next_v2_settings, 0o600)
        _write_json_atomic(V3_HOOKS_PATH, next_v3_settings, 0o600)

        print('Kiro CLI v2: start with "kiro-cli --agent elydora-audit".')
        print('Kiro CLI v3: start with "kiro-cli --v3"; global hooks load automatically.')

    def uninstall(self, agent_id: str = "") -> None:
        v2_settings = _read_json(V2_AGENT_PATH, "Kiro CLI v2 agent config")
        v3_settings = _read_json(V3_HOOKS_PATH, "Kiro CLI v3 hooks config")

        next_v2: Optional[Tuple[JsonObject, bool]] = None
        if v2_settings is not None:
            v2_hooks = _hooks_object(v2_settings, "Kiro CLI v2 agent config")
            current_pre = _hook_entries(v2_hooks, "preToolUse", "Kiro CLI v2 agent config")
            current_post = _hook_entries(v2_hooks, "postToolUse", "Kiro CLI v2 agent config")
            next_pre = _without_v2_hooks(current_pre, agent_id)
            next_post = _without_v2_hooks(current_post, agent_id)
            if next_pre != current_pre or next_post != current_post:
                v2_hooks["preToolUse"] = next_pre
                v2_hooks["postToolUse"] = next_post
                next_v2 = (
                    {**v2_settings, "hooks": v2_hooks},
                    _is_owned_v2(v2_settings, v2_hooks),
                )

        next_v3: Optional[Tuple[JsonObject, bool]] = None
        if v3_settings is not None:
            current_hooks = _v3_hooks(v3_settings)
            v3_hooks = [
                hook for hook in current_hooks if not _is_managed_v3_hook(hook, agent_id)
            ]
            if v3_hooks != current_hooks:
                owned = all(key in {"version", "hooks"} for key in v3_settings)
                next_v3 = ({**v3_settings, "hooks": v3_hooks}, owned and not v3_hooks)

        if next_v2 is not None:
            settings, remove = next_v2
            if remove:
                _remove_file(V2_AGENT_PATH, "Kiro CLI v2 agent config")
            else:
                _write_json_atomic(V2_AGENT_PATH, settings, 0o600)

        if next_v3 is not None:
            settings, remove = next_v3
            if remove:
                _remove_file(V3_HOOKS_PATH, "Kiro CLI v3 hooks config")
            else:
                _write_json_atomic(V3_HOOKS_PATH, settings, 0o600)

        print("Elydora hooks uninstalled from Kiro CLI.")

    def status(self) -> PluginStatus:
        v2_settings = _read_json(V2_AGENT_PATH, "Kiro CLI v2 agent config")
        v3_settings = _read_json(V3_HOOKS_PATH, "Kiro CLI v3 hooks config")
        contracts: List[HookContract] = []

        if v2_settings is not None:
            v2_hooks = _hooks_object(v2_settings, "Kiro CLI v2 agent config")
            guard = _find_v2_command(
                _hook_entries(v2_hooks, "preToolUse", "Kiro CLI v2 agent config"),
                "guard.py",
            )
            audit = _find_v2_command(
                _hook_entries(v2_hooks, "postToolUse", "Kiro CLI v2 agent config"),
                "hook.py",
            )
            if guard and audit:
                contracts.append((guard, audit, V2_AGENT_PATH))

        if v3_settings is not None:
            v3_hooks = _v3_hooks(v3_settings)
            guard = _find_v3_command(v3_hooks, V3_GUARD_NAME, "guard.py")
            audit = _find_v3_command(v3_hooks, V3_AUDIT_NAME, "hook.py")
            if guard and audit:
                contracts.append((guard, audit, V3_HOOKS_PATH))

        if not contracts:
            return PluginStatus(installed=False, agent=AGENT_KEY, details="Not installed")

        config_path = contracts[-1][2]
        installed = _runtime_scripts_exist(contracts)
        details = (
            f"Config: {config_path}"
            if installed
            else f"Configured at {config_path}; runtime scripts missing"
        )
        return PluginStatus(installed=installed, agent=AGENT_KEY, details=details)


def _read_json(path: str, label: str) -> Optional[JsonObject]:
    try:
        with open(path, "r", encoding="utf-8") as file:
            raw = file.read()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise OSError(f"Read {label} at {path}: {error}") from error

    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError(f"Failed to parse {label} at {path}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} at {path} must contain a JSON object")
    return value


def _write_text_atomic(path: str, content: str, mode: int) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    descriptor, temporary_path = tempfile.mkstemp(
        dir=directory,
        prefix=f".{os.path.basename(path)}.",
        suffix=".tmp",
        text=True,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as file:
            file.write(content)
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, path)
    except BaseException as write_error:
        try:
            os.remove(temporary_path)
        except FileNotFoundError:
            pass
        except OSError as cleanup_error:
            raise RuntimeError(
                f"Write {path} failed and temporary file cleanup also failed: {cleanup_error}"
            ) from write_error
        raise


def _write_json_atomic(path: str, value: JsonObject, mode: int) -> None:
    _write_text_atomic(path, json.dumps(value, indent=2) + "\n", mode)


def _remove_file(path: str, label: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        return
    except OSError as error:
        raise OSError(f"Remove {label} at {path}: {error}") from error


def _build_command(script_path: str) -> str:
    arguments = [sys.executable, script_path]
    return subprocess.list2cmdline(arguments) if os.name == "nt" else shlex.join(arguments)


def _hooks_object(settings: JsonObject, label: str) -> JsonObject:
    if "hooks" not in settings:
        return {}
    value = settings["hooks"]
    if not isinstance(value, dict):
        raise ValueError(f'{label} field "hooks" must be an object')
    return dict(value)


def _hook_entries(hooks: JsonObject, event: str, label: str) -> List[JsonObject]:
    value = hooks.get(event)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f'{label} field "hooks.{event}" must be an array of objects')
    return value


def _is_managed_command(command: Any, script_name: str, agent_id: str = "") -> bool:
    if not isinstance(command, str):
        return False
    normalized = command.lower()
    if ".elydora" not in normalized or script_name not in normalized:
        return False
    return not agent_id or agent_id in command


def _without_v2_hooks(
    entries: List[JsonObject], agent_id: str = ""
) -> List[JsonObject]:
    return [
        hook
        for hook in entries
        if not _is_managed_command(hook.get("command"), "guard.py", agent_id)
        and not _is_managed_command(hook.get("command"), "hook.py", agent_id)
    ]


def _build_v2_hook(script_path: str) -> JsonObject:
    return {
        "matcher": "*",
        "command": _build_command(script_path),
        "timeout_ms": 5000,
    }


def _is_owned_v2(settings: JsonObject, hooks: JsonObject) -> bool:
    config_keys = {"name", "description", "tools", "includeMcpJson", "hooks"}
    hook_keys = {"preToolUse", "postToolUse"}
    return (
        all(key in config_keys for key in settings)
        and settings.get("name") == V2_AGENT_NAME
        and settings.get("description") == V2_DESCRIPTION
        and settings.get("tools") == ["*"]
        and settings.get("includeMcpJson") is True
        and all(key in hook_keys for key in hooks)
        and all(isinstance(value, list) and not value for value in hooks.values())
    )


def _v3_hooks(settings: JsonObject) -> List[JsonObject]:
    if "version" in settings and settings["version"] != "v1":
        raise ValueError('Kiro CLI v3 hooks config field "version" must be "v1"')
    if "hooks" not in settings:
        return []
    hooks = settings["hooks"]
    if not isinstance(hooks, list) or not all(isinstance(item, dict) for item in hooks):
        raise ValueError('Kiro CLI v3 hooks config field "hooks" must be an array of objects')
    return hooks


def _v3_action_command(hook: JsonObject) -> Any:
    action = hook.get("action")
    return action.get("command") if isinstance(action, dict) else None


def _is_managed_v3_hook(hook: JsonObject, agent_id: str = "") -> bool:
    if hook.get("name") == V3_GUARD_NAME:
        return _is_managed_command(_v3_action_command(hook), "guard.py", agent_id)
    if hook.get("name") == V3_AUDIT_NAME:
        return _is_managed_command(_v3_action_command(hook), "hook.py", agent_id)
    return False


def _build_v3_hook(
    name: str,
    description: str,
    trigger: str,
    script_path: str,
) -> JsonObject:
    return {
        "name": name,
        "description": description,
        "trigger": trigger,
        "matcher": ".*",
        "action": {"type": "command", "command": _build_command(script_path)},
        "timeout": 5,
        "enabled": True,
    }


def _find_v2_command(entries: List[JsonObject], script_name: str) -> Optional[str]:
    for hook in entries:
        command = hook.get("command")
        if _is_managed_command(command, script_name):
            return command
    return None


def _find_v3_command(
    entries: List[JsonObject], name: str, script_name: str
) -> Optional[str]:
    for hook in entries:
        command = _v3_action_command(hook)
        if hook.get("name") == name and _is_managed_command(command, script_name):
            return command
    return None


def _regular_file_exists(path: str, label: str) -> bool:
    try:
        metadata = os.stat(path)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise OSError(f"Read {label} at {path}: {error}") from error
    return stat.S_ISREG(metadata.st_mode)


def _runtime_scripts_exist(contracts: List[HookContract]) -> bool:
    try:
        with os.scandir(ELYDORA_DIR) as iterator:
            entries = sorted(iterator, key=lambda entry: entry.name)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise OSError(f"Read Elydora runtime directory at {ELYDORA_DIR}: {error}") from error

    for entry in entries:
        try:
            is_directory = entry.is_dir(follow_symlinks=False)
        except OSError as error:
            raise OSError(f"Read Elydora runtime entry at {entry.path}: {error}") from error
        if not is_directory:
            continue

        guard_path = os.path.join(entry.path, "guard.py")
        hook_path = os.path.join(entry.path, "hook.py")
        references_runtime = any(
            guard_path in guard and hook_path in audit for guard, audit, _path in contracts
        )
        if not references_runtime:
            continue

        config_path = os.path.join(entry.path, "config.json")
        config = _read_json(config_path, "Elydora runtime config")
        if config is None or config.get("agent_name") != AGENT_KEY:
            continue
        return _regular_file_exists(
            guard_path, "Elydora guard runtime"
        ) and _regular_file_exists(hook_path, "Elydora audit runtime")
    return False
