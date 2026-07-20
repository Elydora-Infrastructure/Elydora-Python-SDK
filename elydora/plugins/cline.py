"""Cline native user-level file-hook integration."""

from __future__ import annotations

from typing import Tuple

from .base import AgentPlugin, InstallConfig, PluginStatus
from .cline_contract import (
    AGENT_KEY,
    HookFile,
    HookPaths,
    resolve_hook_files,
    runtime_contract,
)
from .cline_installation import (
    commit_cline_installation,
    commit_cline_uninstall,
    preflight_cline_installation,
    prepare_cline_installation,
    prepare_cline_uninstall,
)
from .cline_io import (
    read_hook_file,
    require_available_hook_file,
    runtime_files_exist,
)


def _read_hook_pair() -> Tuple[HookPaths, HookFile, HookFile]:
    paths = resolve_hook_files()
    return (
        paths,
        read_hook_file(paths.guard_path),
        read_hook_file(paths.audit_path),
    )


def _require_available_pair(guard_file: HookFile, audit_file: HookFile) -> None:
    require_available_hook_file(guard_file)
    require_available_hook_file(audit_file)


class ClinePlugin(AgentPlugin):
    """Install Elydora into Cline's global file-hook directory."""

    manages_guard_runtime = True

    def preflight_install(self, config: InstallConfig) -> None:
        _paths, guard_file, audit_file = _read_hook_pair()
        _require_available_pair(guard_file, audit_file)
        preflight_cline_installation(config, guard_file, audit_file)

    def install(self, config: InstallConfig) -> None:
        _paths, guard_file, audit_file = _read_hook_pair()
        _require_available_pair(guard_file, audit_file)
        changes = prepare_cline_installation(config, guard_file, audit_file)
        commit_cline_installation(changes)
        print("Cline: user-level PreToolUse and PostToolUse hooks installed.")

    def uninstall(self, agent_id: str = "") -> None:
        _paths, guard_file, audit_file = _read_hook_pair()
        changes = prepare_cline_uninstall((guard_file, audit_file), agent_id)
        commit_cline_uninstall(changes)

    def status(self) -> PluginStatus:
        paths, guard_file, audit_file = _read_hook_pair()
        contract = runtime_contract(guard_file, audit_file)
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
                "managed runtime incomplete"
            )
        )
        return PluginStatus(
            installed=installed,
            agent=AGENT_KEY,
            details=details,
        )
