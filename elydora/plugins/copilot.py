"""GitHub Copilot CLI native user-hook integration."""

from __future__ import annotations

import os
from typing import List

from .base import AgentPlugin, InstallConfig, PluginStatus
from .copilot_contract import (
    AGENT_KEY,
    CopilotSources,
    RenderedDocument,
    RuntimeContract,
    build_handler,
    remove_managed_hooks,
    render_document,
    runtime_contracts,
)
from .copilot_installation import (
    commit_copilot_installation,
    commit_copilot_uninstall,
    preflight_copilot_installation,
    prepare_copilot_installation,
    prepare_copilot_uninstall,
)
from .copilot_io import read_sources, runtime_files_exist


def _render_installation(
    sources: CopilotSources,
    guard_path: str,
    audit_path: str,
) -> List[RenderedDocument]:
    user_hooks = remove_managed_hooks(sources.user.hooks)
    user_hooks["preToolUse"] = [
        *user_hooks.get("preToolUse", []),
        build_handler(guard_path),
    ]
    user_hooks["postToolUse"] = [
        *user_hooks.get("postToolUse", []),
        build_handler(audit_path),
    ]
    user_hooks["postToolUseFailure"] = [
        *user_hooks.get("postToolUseFailure", []),
        build_handler(audit_path),
    ]
    rendered = [render_document(sources.user, user_hooks)]
    if sources.legacy is not None:
        rendered.append(render_document(
            sources.legacy,
            remove_managed_hooks(sources.legacy.hooks),
        ))
    return rendered


def _render_uninstall(
    sources: CopilotSources,
    agent_id: str,
) -> List[RenderedDocument]:
    rendered = [render_document(
        sources.user,
        remove_managed_hooks(sources.user.hooks, agent_id),
    )]
    if sources.legacy is not None:
        rendered.append(render_document(
            sources.legacy,
            remove_managed_hooks(sources.legacy.hooks, agent_id),
        ))
    return rendered


def _merged_contracts(sources: CopilotSources) -> List[RuntimeContract]:
    contracts = runtime_contracts(sources.user.hooks)
    if sources.legacy is not None:
        contracts.extend(runtime_contracts(sources.legacy.hooks))
    unique = {
        os.path.normcase(contract.agent_id): contract
        for contract in contracts
    }
    return list(unique.values())


class CopilotPlugin(AgentPlugin):
    """Install Elydora into GitHub Copilot CLI's global user hooks."""

    manages_guard_runtime = True

    def preflight_install(self, config: InstallConfig) -> None:
        sources = read_sources()
        preflight_copilot_installation(config, sources)

    def install(self, config: InstallConfig) -> None:
        sources = read_sources()
        paths = preflight_copilot_installation(config, sources)
        rendered = _render_installation(
            sources,
            paths.guard_path,
            paths.audit_path,
        )
        prepared = prepare_copilot_installation(config, sources, rendered)
        commit_copilot_installation(prepared)
        print(f"GitHub Copilot CLI hooks: {sources.user.file_path}")
        print(
            "GitHub Copilot CLI: restart active sessions to load updated hooks."
        )

    def uninstall(self, agent_id: str = "") -> None:
        sources = read_sources()
        rendered = _render_uninstall(sources, agent_id)
        commit_copilot_uninstall(prepare_copilot_uninstall(rendered))

    def status(self) -> PluginStatus:
        sources = read_sources()
        contracts = _merged_contracts(sources)
        configured = sources.disabled_by is None and bool(contracts)
        installed = configured and runtime_files_exist(contracts)
        details = (
            f"Config: {sources.user.file_path}"
            if installed
            else (
                f"Configured at {sources.user.file_path}; "
                "managed contract incomplete"
            )
        )
        return PluginStatus(
            installed=installed,
            agent=AGENT_KEY,
            details=details if contracts else "Not installed",
        )
