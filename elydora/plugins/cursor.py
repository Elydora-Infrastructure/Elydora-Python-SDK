"""Cursor native user-hook integration."""

from __future__ import annotations

import base64
import json
import os
import urllib.parse
from typing import List, Optional

from elydora._runtime_paths import resolve_agent_directory
from elydora.utils import base64url_encode

from ._transaction import FileChange
from .base import AgentPlugin, InstallConfig, PluginStatus
from .cursor_contract import (
    AGENT_KEY,
    AUDIT_SCRIPT,
    GUARD_SCRIPT,
    build_handler,
    remove_managed_hooks,
    render_document,
    runtime_contracts,
    runtime_root,
    same_path,
)
from .cursor_io import (
    read_document,
    rendered_change,
    physical_directory_exists,
    physical_file_exists,
    require_runtime_directory,
    runtime_change,
    runtime_files_exist,
    validate_config_directory,
    validate_runtime_identity,
    write_cursor_changes,
)
from .hook_template import generate_guard_script, generate_hook_script


def _runtime_config(config: InstallConfig, agent_id: str) -> dict:
    value = {
        "org_id": config.get("org_id", ""),
        "agent_id": agent_id,
        "kid": config.get("kid", ""),
        "base_url": config.get("base_url", "https://api.elydora.com"),
        "agent_name": AGENT_KEY,
    }
    token = config.get("token", "")
    if token:
        value["token"] = token
    return value


def _json_source(value: dict) -> str:
    return json.dumps(value, indent=2) + "\n"


def _present(changes: List[Optional[FileChange]]) -> List[FileChange]:
    return [change for change in changes if change is not None]


def _agent_paths(config: InstallConfig) -> tuple[str, str, str]:
    agent_id = config.get("agent_id", "")
    if not agent_id:
        raise ValueError("agent_id is required")
    agent_directory = resolve_agent_directory(runtime_root(), agent_id)
    guard_path = os.path.join(agent_directory, GUARD_SCRIPT)
    configured_guard = config.get("guard_script_path", "")
    if not same_path(configured_guard, guard_path):
        raise ValueError(
            "Elydora guard runtime must use the managed agent directory: "
            f"{guard_path}"
        )
    return agent_id, agent_directory, guard_path


def _validate_install_config(config: InstallConfig) -> None:
    for field in ("org_id", "agent_id", "kid", "private_key"):
        value = config.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{field} is required")
    if config.get("agent_name") != AGENT_KEY:
        raise ValueError(f"Cursor installation requires agent_name {AGENT_KEY}")
    private_key = config["private_key"]
    try:
        padded = private_key + "=" * ((4 - len(private_key) % 4) % 4)
        seed = base64.b64decode(
            padded.replace("-", "+").replace("_", "/"),
            validate=True,
        )
    except (ValueError, UnicodeEncodeError) as error:
        raise ValueError(
            "private_key must be a canonical 32-byte base64url value"
        ) from error
    if len(seed) != 32 or base64url_encode(seed) != private_key:
        raise ValueError("private_key must be a canonical 32-byte base64url value")
    base_url = config.get("base_url", "https://api.elydora.com")
    if not isinstance(base_url, str):
        raise ValueError("base_url must be a string")
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("base_url must be an absolute HTTP or HTTPS URL")
    token = config.get("token", "")
    if not isinstance(token, str):
        raise ValueError("token must be a string")


class CursorPlugin(AgentPlugin):
    """Install Elydora into Cursor's native global user hooks."""

    manages_guard_runtime = True

    def preflight_install(self, config: InstallConfig) -> None:
        _validate_install_config(config)
        read_document()
        validate_config_directory()
        agent_id, agent_directory, guard_path = _agent_paths(config)
        if not physical_directory_exists(runtime_root()):
            return
        if not physical_directory_exists(agent_directory):
            return
        identity_exists = validate_runtime_identity(
            os.path.join(agent_directory, "config.json"),
            agent_id,
        )
        runtime_exists = False
        for file_path, label in (
            (guard_path, "Elydora guard runtime"),
            (os.path.join(agent_directory, AUDIT_SCRIPT), "Elydora audit runtime"),
            (os.path.join(agent_directory, "private.key"), "Elydora private key"),
            (os.path.join(agent_directory, "chain-state.json"), "Elydora chain state"),
            (os.path.join(agent_directory, "status-cache.json"), "Elydora status cache"),
            (os.path.join(agent_directory, "error.log"), "Elydora error log"),
        ):
            runtime_exists = physical_file_exists(file_path, label) or runtime_exists
        if runtime_exists and not identity_exists:
            raise ValueError(
                "Elydora runtime identity cannot be verified without config.json: "
                f"{agent_directory}"
            )

    def install(self, config: InstallConfig) -> None:
        self.preflight_install(config)
        document = read_document()
        agent_id, agent_directory, guard_path = _agent_paths(config)
        require_runtime_directory(agent_directory)
        audit_path = os.path.join(agent_directory, AUDIT_SCRIPT)

        runtime_config_path = os.path.join(agent_directory, "config.json")
        validate_runtime_identity(runtime_config_path, agent_id)
        hooks = remove_managed_hooks(document.hooks)
        hooks["preToolUse"] = [
            *hooks.get("preToolUse", []),
            build_handler(guard_path),
        ]
        hooks["postToolUse"] = [
            *hooks.get("postToolUse", []),
            build_handler(audit_path),
        ]
        hooks["postToolUseFailure"] = [
            *hooks.get("postToolUseFailure", []),
            build_handler(audit_path),
        ]
        hook_script = generate_hook_script(
            org_id=config.get("org_id", ""),
            agent_id=agent_id,
            kid=config.get("kid", ""),
            base_url=config.get("base_url", "https://api.elydora.com"),
            success_output="{}\n",
            fail_closed=True,
            native_payload=True,
            agent_name=AGENT_KEY,
        )
        guard_script = generate_guard_script(
            AGENT_KEY,
            agent_id,
            success_output='{"permission":"allow"}\n',
            fail_closed=True,
            deny_protocol="cursor",
        )
        changes = _present([
            runtime_change(
                guard_path,
                "Elydora guard runtime",
                guard_script,
                0o700,
            ),
            runtime_change(
                runtime_config_path,
                "Elydora runtime config",
                _json_source(_runtime_config(config, agent_id)),
                0o600,
            ),
            runtime_change(
                os.path.join(agent_directory, "private.key"),
                "Elydora private key",
                config.get("private_key", ""),
                0o600,
            ),
            runtime_change(
                audit_path,
                "Elydora audit runtime",
                hook_script,
                0o700,
            ),
            rendered_change(render_document(document, hooks)),
        ])
        write_cursor_changes(changes, "Install Cursor hooks")
        print(f"  Cursor hooks: {document.file_path}")

    def uninstall(self, agent_id: str = "") -> None:
        document = read_document()
        hooks = remove_managed_hooks(document.hooks, agent_id)
        change = rendered_change(render_document(document, hooks))
        write_cursor_changes(
            [] if change is None else [change],
            "Uninstall Cursor hooks",
        )

    def status(self) -> PluginStatus:
        document = read_document()
        contracts = runtime_contracts(document.hooks)
        if not contracts:
            return PluginStatus(
                installed=False,
                agent=AGENT_KEY,
                details="Not installed",
            )
        installed = runtime_files_exist(contracts)
        details = (
            f"Config: {document.file_path}"
            if installed
            else f"Configured at {document.file_path}; runtime files missing"
        )
        return PluginStatus(
            installed=installed,
            agent=AGENT_KEY,
            details=details,
        )
