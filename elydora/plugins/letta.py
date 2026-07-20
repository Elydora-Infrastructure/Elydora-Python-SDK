"""Letta Code 0.28 native global hook integration."""

from __future__ import annotations

from typing import Dict

from .base import AgentPlugin, InstallConfig, PluginStatus
from .letta_config import render_letta_document
from .letta_contract import (
    AGENT_KEY,
    JsonObject,
    build_letta_group,
    letta_runtime_contracts,
)
from .letta_installation import (
    LettaRuntimePaths,
    commit_letta_installation,
    commit_letta_uninstall,
    preflight_letta_installation,
    prepare_letta_installation,
    prepare_letta_uninstall,
)
from .letta_io import letta_runtime_files_exist
from .letta_sources import read_letta_sources


def _installed_groups(paths: LettaRuntimePaths) -> Dict[str, JsonObject]:
    return {
        "PreToolUse": build_letta_group(paths.guard_path),
        "PostToolUse": build_letta_group(paths.audit_path),
        "PostToolUseFailure": build_letta_group(paths.audit_path),
    }


class LettaPlugin(AgentPlugin):
    """Install Elydora into Letta Code's native global settings."""

    manages_guard_runtime = True

    def preflight_install(self, config: InstallConfig) -> None:
        sources = read_letta_sources()
        preflight_letta_installation(config, sources)

    def install(self, config: InstallConfig) -> None:
        sources = read_letta_sources()
        paths = preflight_letta_installation(config, sources)
        rendered = render_letta_document(
            sources.global_settings,
            None,
            _installed_groups(paths),
        )
        changes = prepare_letta_installation(config, paths, rendered)
        commit_letta_installation(changes, sources)
        print(f"Letta Code hooks installed at {sources.global_settings.file_path}")
        print("Letta Code verification: run /hooks and restart active sessions.")

    def uninstall(self, agent_id: str = "") -> None:
        sources = read_letta_sources()
        rendered = render_letta_document(
            sources.global_settings, agent_id or None, {}
        )
        commit_letta_uninstall(prepare_letta_uninstall(rendered), sources)

    def status(self) -> PluginStatus:
        sources = read_letta_sources()
        contracts = letta_runtime_contracts(sources.global_settings.hooks)
        configured = not sources.disable_control.disabled and bool(contracts)
        installed = configured and letta_runtime_files_exist(contracts)
        file_path = sources.global_settings.file_path
        if installed:
            details = f"Config: {file_path}"
        elif contracts and sources.disable_control.disabled:
            details = f"Configured hooks are disabled: {file_path}"
        elif contracts:
            details = f"Configured at {file_path}; managed contract incomplete"
        else:
            details = "Not installed"
        return PluginStatus(installed=installed, agent=AGENT_KEY, details=details)
