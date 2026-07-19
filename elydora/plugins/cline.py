"""Cline native user-level file-hook integration."""

from __future__ import annotations

import os

from ._file_io import write_json_atomic, write_text_atomic
from .base import AgentPlugin, InstallConfig, PluginStatus
from .cline_contract import (
    AGENT_KEY,
    AUDIT_SCRIPT,
    HookFile,
    build_metadata,
    build_wrapper,
    elydora_dir,
    resolve_hook_files,
    runtime_contract,
)
from .cline_io import (
    PendingWrite,
    read_hook_file,
    remove_owned_hooks,
    require_available_hook_file,
    require_runtime,
    runtime_files_exist,
    write_hook_pair,
)
from .hook_template import generate_hook_script


class ClinePlugin(AgentPlugin):
    """Install Elydora into Cline's global file-hook directory."""

    def install(self, config: InstallConfig) -> None:
        agent_id = config.get("agent_id", "")
        if not agent_id:
            raise ValueError("agent_id is required")
        paths = resolve_hook_files()
        guard_state = read_hook_file(paths.guard_path)
        audit_state = read_hook_file(paths.audit_path)
        require_available_hook_file(guard_state)
        require_available_hook_file(audit_state)

        guard_path = config.get("guard_script_path", "")
        require_runtime(guard_path, "Elydora guard runtime")
        agent_directory = os.path.join(elydora_dir(), agent_id)
        audit_path = os.path.join(agent_directory, AUDIT_SCRIPT)
        guard_metadata = build_metadata("guard", agent_id, guard_path)
        audit_metadata = build_metadata("audit", agent_id, audit_path)
        guard_source = build_wrapper(guard_metadata)
        audit_source = build_wrapper(audit_metadata)
        runtime_contract(
            HookFile(True, paths.guard_path, guard_source, guard_metadata),
            HookFile(True, paths.audit_path, audit_source, audit_metadata),
        )

        runtime_config = {
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
        write_json_atomic(
            os.path.join(agent_directory, "config.json"),
            runtime_config,
            0o600,
            "Elydora runtime config",
        )
        write_text_atomic(
            os.path.join(agent_directory, "private.key"),
            config.get("private_key", ""),
            0o600,
            "Elydora private key",
        )
        write_text_atomic(
            audit_path,
            audit_script,
            0o700,
            "Elydora audit runtime",
        )
        write_hook_pair(
            PendingWrite(guard_state, guard_source),
            PendingWrite(audit_state, audit_source),
        )
        print("Cline: user-level PreToolUse and PostToolUse hooks installed.")

    def uninstall(self, agent_id: str = "") -> None:
        paths = resolve_hook_files()
        guard_state = read_hook_file(paths.guard_path)
        audit_state = read_hook_file(paths.audit_path)
        remove_owned_hooks((guard_state, audit_state), agent_id)

    def status(self) -> PluginStatus:
        paths = resolve_hook_files()
        guard_state = read_hook_file(paths.guard_path)
        audit_state = read_hook_file(paths.audit_path)
        contract = runtime_contract(guard_state, audit_state)
        if contract is None:
            return PluginStatus(
                installed=False,
                agent=AGENT_KEY,
                details="Not installed",
            )
        installed = runtime_files_exist(contract)
        details = (
            f"Config: {paths.hooks_directory}"
            if installed
            else (
                f"Configured at {paths.hooks_directory}; "
                "runtime scripts missing"
            )
        )
        return PluginStatus(
            installed=installed,
            agent=AGENT_KEY,
            details=details,
        )
