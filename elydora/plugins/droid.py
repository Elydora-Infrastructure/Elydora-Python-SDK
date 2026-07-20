"""Factory Droid native global user-hook integration."""

from __future__ import annotations

from typing import Dict, List

from .base import AgentPlugin, InstallConfig, PluginStatus
from .droid_config import (
    DroidSources,
    RenderedDocument,
    active_document,
    additions_for_target,
    effective_hooks,
    hook_block,
    installation_documents,
    render_document,
    source_documents,
)
from .droid_contract import (
    AGENT_KEY,
    JsonObject,
    build_group,
    runtime_contracts,
)
from .droid_installation import (
    commit_droid_installation,
    commit_droid_uninstall,
    preflight_droid_installation,
    prepare_droid_installation,
    prepare_droid_uninstall,
)
from .droid_io import display_config_path, read_sources, runtime_files_exist


def _render_installation(
    sources: DroidSources,
    guard_path: str,
    audit_path: str,
) -> List[RenderedDocument]:
    target = active_document(sources)
    groups: Dict[str, JsonObject] = {
        "PreToolUse": build_group(guard_path),
        "PostToolUse": build_group(audit_path),
    }
    return [
        render_document(
            document,
            None,
            additions_for_target(document, target, groups),
        )
        for document in installation_documents(sources)
    ]


def _render_uninstall(
    sources: DroidSources,
    agent_id: str,
) -> List[RenderedDocument]:
    return [
        render_document(document, agent_id or None, {})
        for document in source_documents(sources)
    ]


class DroidPlugin(AgentPlugin):
    """Install Elydora into Factory Droid's user-level hook sources."""

    manages_guard_runtime = True

    def preflight_install(self, config: InstallConfig) -> None:
        sources = read_sources()
        preflight_droid_installation(config, sources)

    def install(self, config: InstallConfig) -> None:
        sources = read_sources()
        paths = preflight_droid_installation(config, sources)
        rendered = _render_installation(
            sources,
            paths.guard_path,
            paths.audit_path,
        )
        prepared = prepare_droid_installation(config, sources, rendered)
        commit_droid_installation(prepared)
        print(f"Factory Droid hooks: {active_document(sources).file_path}")
        print("Factory Droid: run /hooks to review the Elydora hook changes.")

    def uninstall(self, agent_id: str = "") -> None:
        sources = read_sources()
        rendered = _render_uninstall(sources, agent_id)
        commit_droid_uninstall(prepare_droid_uninstall(rendered))

    def status(self) -> PluginStatus:
        sources = read_sources()
        contracts = runtime_contracts(effective_hooks(sources))
        blocked = hook_block(sources)
        configured = blocked is None and bool(contracts)
        installed = configured and runtime_files_exist(contracts)
        config_path = display_config_path(sources)
        if blocked is not None:
            details = (
                f"Configured hooks are disabled by {blocked.field}: "
                f"{blocked.file_path}"
            )
        elif not contracts:
            details = "Not installed"
        elif installed:
            details = f"Config: {config_path}"
        else:
            details = (
                f"Configured at {config_path}; managed contract incomplete"
            )
        return PluginStatus(
            installed=installed,
            agent=AGENT_KEY,
            details=details,
        )
