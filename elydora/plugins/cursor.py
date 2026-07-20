"""Cursor native user-hook integration."""

from __future__ import annotations

import json
import os
from typing import List, Optional

from elydora._runtime_paths import resolve_agent_directory

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


class CursorPlugin(AgentPlugin):
    """Install Elydora into Cursor's native global user hooks."""

    manages_guard_runtime = True

    def preflight_install(self, config: InstallConfig) -> None:
        read_document()
        agent_id, agent_directory, guard_path = _agent_paths(config)
        if not physical_directory_exists(agent_directory):
            return
        validate_runtime_identity(
            os.path.join(agent_directory, "config.json"),
            agent_id,
        )
        for file_path, label in (
            (guard_path, "Elydora guard runtime"),
            (os.path.join(agent_directory, AUDIT_SCRIPT), "Elydora audit runtime"),
            (os.path.join(agent_directory, "private.key"), "Elydora private key"),
        ):
            physical_file_exists(file_path, label)

    def install(self, config: InstallConfig) -> None:
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
        hook_script = generate_hook_script(
            org_id=config.get("org_id", ""),
            agent_id=agent_id,
            kid=config.get("kid", ""),
            base_url=config.get("base_url", "https://api.elydora.com"),
            success_output="{}\n",
        )
        guard_script = generate_guard_script(
            AGENT_KEY,
            agent_id,
            success_output='{"permission":"allow"}\n',
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
