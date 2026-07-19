"""OpenAI Codex lifecycle-hook integration."""

from __future__ import annotations

import json
import os
import shlex
import stat
# subprocess provides argument quoting only; this module starts no process.
import subprocess  # nosec B404
import sys
import tempfile
from typing import Any, Dict, List, Optional

from .base import AgentPlugin, InstallConfig, PluginStatus
from .hook_template import generate_hook_script


AGENT_KEY = "codex"
OWNED_DESCRIPTION = "Elydora audit and freeze enforcement"
GUARD_STATUS = "Checking Elydora agent state"
AUDIT_STATUS = "Recording Elydora tool use"
GUARD_SCRIPT = "guard.py"
AUDIT_SCRIPT = "hook.py"
ELYDORA_DIR = os.path.join(os.path.expanduser("~"), ".elydora")
CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".codex", "hooks.json")

JsonObject = Dict[str, Any]


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


def _cleanup_failed_write(path: str, label: str, cause: Exception) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        return
    except OSError as cleanup_error:
        raise OSError(
            f"Write {label} failed: {cause}; cleanup of {path} failed: {cleanup_error}"
        ) from cause


def _write_text_atomic(path: str, content: str, mode: int, label: str) -> None:
    directory = os.path.dirname(path)
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    except OSError as error:
        raise OSError(f"Create directory for {label} at {directory}: {error}") from error

    descriptor = -1
    temporary_path = ""
    try:
        descriptor, temporary_path = tempfile.mkstemp(
            prefix=f".{os.path.basename(path)}.",
            suffix=".tmp",
            dir=directory,
            text=True,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as file:
            descriptor = -1
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, path)
    except Exception as error:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as close_error:
                _cleanup_failed_write(temporary_path, label, close_error)
                raise OSError(
                    f"Write {label} at {path} failed: {error}; "
                    f"close failed: {close_error}"
                ) from error
        _cleanup_failed_write(temporary_path, label, error)
        raise OSError(f"Write {label} at {path}: {error}") from error


def _write_json_atomic(path: str, value: JsonObject, mode: int, label: str) -> None:
    encoded = json.dumps(value, indent=2) + "\n"
    _write_text_atomic(path, encoded, mode, label)


def _remove_file(path: str, label: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        return
    except OSError as error:
        raise OSError(f"Remove {label} at {path}: {error}") from error


def _regular_file_exists(path: str, label: str) -> bool:
    try:
        metadata = os.stat(path)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise OSError(f"Read {label} at {path}: {error}") from error
    return stat.S_ISREG(metadata.st_mode)


def _require_runtime(path: str, label: str) -> None:
    if not path:
        raise ValueError(f"{label} path is required")
    if not _regular_file_exists(path, label):
        raise FileNotFoundError(f"{label} is missing: {path}")


def _build_handler(script_path: str, status_message: str) -> JsonObject:
    return {
        "type": "command",
        "command": f"{shlex.quote(sys.executable)} {shlex.quote(script_path)}",
        "commandWindows": subprocess.list2cmdline([sys.executable, script_path]),
        "timeout": 10,
        "statusMessage": status_message,
    }


def _hooks_object(settings: JsonObject) -> JsonObject:
    if "hooks" not in settings:
        return {}
    hooks = settings["hooks"]
    if not isinstance(hooks, dict):
        raise ValueError('Codex hooks config field "hooks" must be an object')
    return dict(hooks)


def _event_groups(hooks: JsonObject, event: str) -> List[JsonObject]:
    if event not in hooks:
        return []
    groups = hooks[event]
    if not isinstance(groups, list) or not all(
        isinstance(group, dict) for group in groups
    ):
        raise ValueError(
            f'Codex hooks config field "hooks.{event}" must be an array of objects'
        )
    return groups


def _is_managed_command(command: Any, script_name: str, agent_id: str = "") -> bool:
    if not isinstance(command, str):
        return False
    normalized = os.path.normcase(command)
    if ".elydora" not in normalized or script_name.lower() not in normalized.lower():
        return False
    if not agent_id:
        return True
    expected_path = os.path.normcase(
        os.path.join(ELYDORA_DIR, agent_id, script_name)
    )
    return expected_path in normalized


def _is_elydora_handler(handler: JsonObject, agent_id: str = "") -> bool:
    status_message = handler.get("statusMessage")
    if status_message == GUARD_STATUS:
        script_name = GUARD_SCRIPT
    elif status_message == AUDIT_STATUS:
        script_name = AUDIT_SCRIPT
    else:
        return False
    return any(
        _is_managed_command(handler.get(key), script_name, agent_id)
        for key in ("command", "commandWindows")
    )


def _without_elydora(
    groups: List[JsonObject],
    agent_id: str = "",
) -> List[JsonObject]:
    filtered_groups: List[JsonObject] = []
    for group in groups:
        handlers = group.get("hooks")
        if not isinstance(handlers, list) or not all(
            isinstance(handler, dict) for handler in handlers
        ):
            raise ValueError("Codex hook matcher group must contain a hooks array")
        filtered = [
            handler
            for handler in handlers
            if not _is_elydora_handler(handler, agent_id)
        ]
        if filtered:
            filtered_groups.append({**group, "hooks": filtered})
    return filtered_groups


def _find_handler(
    groups: List[JsonObject],
    status_message: str,
) -> Optional[JsonObject]:
    for group in groups:
        handlers = group.get("hooks")
        if not isinstance(handlers, list) or not all(
            isinstance(handler, dict) for handler in handlers
        ):
            raise ValueError("Codex hook matcher group must contain a hooks array")
        for handler in handlers:
            if (
                handler.get("statusMessage") == status_message
                and _is_elydora_handler(handler)
            ):
                return handler
    return None


def _command_references(handler: JsonObject, script_path: str) -> bool:
    return any(
        isinstance(handler.get(key), str) and script_path in handler[key]
        for key in ("command", "commandWindows")
    )


def _is_owned_settings(settings: JsonObject, hooks: JsonObject) -> bool:
    settings_keys = {"description", "hooks"}
    hook_keys = {"PreToolUse", "PostToolUse"}
    return (
        all(key in settings_keys for key in settings)
        and settings.get("description") == OWNED_DESCRIPTION
        and all(key in hook_keys for key in hooks)
        and all(isinstance(value, list) and not value for value in hooks.values())
    )


def _runtime_scripts_exist(guard: JsonObject, audit: JsonObject) -> bool:
    try:
        with os.scandir(ELYDORA_DIR) as iterator:
            entries = sorted(iterator, key=lambda entry: entry.name)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise OSError(
            f"Read Elydora runtime directory at {ELYDORA_DIR}: {error}"
        ) from error

    for entry in entries:
        try:
            is_directory = entry.is_dir(follow_symlinks=False)
        except OSError as error:
            raise OSError(
                f"Read Elydora runtime entry at {entry.path}: {error}"
            ) from error
        if not is_directory:
            continue

        guard_path = os.path.join(entry.path, GUARD_SCRIPT)
        hook_path = os.path.join(entry.path, AUDIT_SCRIPT)
        if not (
            _command_references(guard, guard_path)
            and _command_references(audit, hook_path)
        ):
            continue

        config_path = os.path.join(entry.path, "config.json")
        config = _read_json(config_path, "Elydora runtime config")
        if config is None:
            continue
        agent_name = config.get("agent_name")
        if not isinstance(agent_name, str):
            raise ValueError(
                f'Elydora runtime config at {config_path} field "agent_name" '
                "must be a string"
            )
        if agent_name != AGENT_KEY:
            continue
        return _regular_file_exists(
            guard_path, "Elydora guard runtime"
        ) and _regular_file_exists(hook_path, "Elydora audit runtime")
    return False


class CodexPlugin(AgentPlugin):
    """Install Elydora into Codex user lifecycle hooks."""

    def install(self, config: InstallConfig) -> None:
        agent_id = config.get("agent_id", "")
        if not agent_id:
            raise ValueError("agent_id is required")

        existing_settings = _read_json(CONFIG_PATH, "Codex hooks config")
        settings = (
            existing_settings
            if existing_settings is not None
            else {"description": OWNED_DESCRIPTION}
        )
        hooks = _hooks_object(settings)
        pre_tool_use = _without_elydora(_event_groups(hooks, "PreToolUse"))
        post_tool_use = _without_elydora(_event_groups(hooks, "PostToolUse"))

        guard_path = config.get("guard_script_path", "")
        _require_runtime(guard_path, "Elydora guard runtime")
        agent_dir = os.path.join(ELYDORA_DIR, agent_id)
        hook_path = os.path.join(agent_dir, AUDIT_SCRIPT)
        hooks["PreToolUse"] = [
            *pre_tool_use,
            {
                "matcher": "*",
                "hooks": [_build_handler(guard_path, GUARD_STATUS)],
            },
        ]
        hooks["PostToolUse"] = [
            *post_tool_use,
            {
                "matcher": "*",
                "hooks": [_build_handler(hook_path, AUDIT_STATUS)],
            },
        ]

        runtime_config: JsonObject = {
            "org_id": config.get("org_id", ""),
            "agent_id": agent_id,
            "kid": config.get("kid", ""),
            "base_url": config.get("base_url", "https://api.elydora.com"),
            "token": config.get("token", ""),
            "agent_name": config.get("agent_name", AGENT_KEY) or AGENT_KEY,
        }
        hook_script = generate_hook_script(
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
        _write_text_atomic(
            hook_path,
            hook_script,
            0o700,
            "Elydora audit runtime",
        )
        _write_json_atomic(
            CONFIG_PATH,
            {**settings, "hooks": hooks},
            0o600,
            "Codex hooks config",
        )
        print("Codex: run /hooks to review and trust the Elydora hooks.")

    def uninstall(self, agent_id: str = "") -> None:
        settings = _read_json(CONFIG_PATH, "Codex hooks config")
        if settings is None:
            return
        hooks = _hooks_object(settings)
        hooks["PreToolUse"] = _without_elydora(
            _event_groups(hooks, "PreToolUse"),
            agent_id,
        )
        hooks["PostToolUse"] = _without_elydora(
            _event_groups(hooks, "PostToolUse"),
            agent_id,
        )
        if _is_owned_settings(settings, hooks):
            _remove_file(CONFIG_PATH, "Codex hooks config")
        else:
            _write_json_atomic(
                CONFIG_PATH,
                {**settings, "hooks": hooks},
                0o600,
                "Codex hooks config",
            )

    def status(self) -> PluginStatus:
        settings = _read_json(CONFIG_PATH, "Codex hooks config")
        guard: Optional[JsonObject] = None
        audit: Optional[JsonObject] = None
        if settings is not None:
            hooks = _hooks_object(settings)
            guard = _find_handler(_event_groups(hooks, "PreToolUse"), GUARD_STATUS)
            audit = _find_handler(_event_groups(hooks, "PostToolUse"), AUDIT_STATUS)

        if guard is None or audit is None:
            return PluginStatus(
                installed=False,
                agent=AGENT_KEY,
                details="Not installed",
            )
        installed = _runtime_scripts_exist(guard, audit)
        details = (
            f"Config: {CONFIG_PATH}"
            if installed
            else f"Configured at {CONFIG_PATH}; runtime scripts missing"
        )
        return PluginStatus(
            installed=installed,
            agent=AGENT_KEY,
            details=details,
        )
