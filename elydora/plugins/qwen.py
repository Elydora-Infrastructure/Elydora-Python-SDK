"""Qwen Code 0.20 native global user-hook integration."""

from __future__ import annotations

from typing import Dict

from .base import AgentPlugin, InstallConfig, PluginStatus
from .qwen_config import render_qwen_document
from .qwen_contract import (
    AGENT_KEY,
    AUDIT_HOOK_NAME,
    GUARD_HOOK_NAME,
    JsonObject,
    build_qwen_group,
    qwen_runtime_contracts,
)
from .qwen_installation import (
    QwenRuntimePaths,
    commit_qwen_installation,
    commit_qwen_uninstall,
    preflight_qwen_installation,
    prepare_qwen_installation,
    prepare_qwen_uninstall,
)
from .qwen_io import qwen_runtime_files_exist
from .qwen_sources import read_qwen_sources


def _installed_groups(paths: QwenRuntimePaths) -> Dict[str, JsonObject]:
    return {
        "PreToolUse": build_qwen_group(paths.guard_path, GUARD_HOOK_NAME),
        "PostToolUse": build_qwen_group(paths.audit_path, AUDIT_HOOK_NAME),
        "PostToolUseFailure": build_qwen_group(
            paths.audit_path, AUDIT_HOOK_NAME
        ),
    }


class QwenPlugin(AgentPlugin):
    """Install Elydora into Qwen Code's native user settings."""

    manages_guard_runtime = True

    def preflight_install(self, config: InstallConfig) -> None:
        sources = read_qwen_sources()
        preflight_qwen_installation(config, sources)

    def install(self, config: InstallConfig) -> None:
        sources = read_qwen_sources()
        paths = preflight_qwen_installation(config, sources)
        rendered = render_qwen_document(
            sources.user,
            None,
            _installed_groups(paths),
        )
        changes = prepare_qwen_installation(config, paths, rendered)
        commit_qwen_installation(changes, sources)
        print(f"Qwen Code hooks installed at {sources.user.file_path}")
        print("Qwen Code verification: run /hooks and restart active sessions.")

    def uninstall(self, agent_id: str = "") -> None:
        sources = read_qwen_sources()
        rendered = render_qwen_document(
            sources.user, agent_id or None, {}
        )
        commit_qwen_uninstall(prepare_qwen_uninstall(rendered), sources)

    def status(self) -> PluginStatus:
        sources = read_qwen_sources()
        contracts = qwen_runtime_contracts(sources.user.hooks)
        configured = not sources.disable_control.disabled and bool(contracts)
        installed = configured and qwen_runtime_files_exist(contracts)
        if installed:
            details = f"Config: {sources.user.file_path}"
        elif contracts and sources.disable_control.disabled:
            details = f"Configured hooks are disabled: {sources.user.file_path}"
        elif contracts:
            details = (
                f"Configured at {sources.user.file_path}; "
                "managed contract incomplete"
            )
        else:
            details = "Not installed"
        return PluginStatus(
            installed=installed,
            agent=AGENT_KEY,
            details=details,
        )
