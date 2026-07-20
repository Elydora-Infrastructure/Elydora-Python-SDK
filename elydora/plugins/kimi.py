"""Kimi Code and legacy kimi-cli lifecycle-hook integration."""

from __future__ import annotations

from typing import List

from .base import AgentPlugin, InstallConfig, PluginStatus
from .kimi_contract import (
    AGENT_KEY,
    KimiDocument,
    TomlObject,
    build_kimi_hook,
    kimi_runtime_contracts,
    remove_managed_kimi_hooks,
    render_kimi_document,
)
from .kimi_installation import (
    commit_kimi_installation,
    commit_kimi_uninstall,
    preflight_kimi_installation,
    prepare_kimi_installation,
    prepare_kimi_uninstall,
)
from .kimi_io import kimi_runtime_files_exist, read_kimi_documents


def _installed_hooks(
    source: KimiDocument,
    guard_path: str,
    audit_path: str,
) -> List[TomlObject]:
    return [
        *remove_managed_kimi_hooks(source.hooks),
        build_kimi_hook("PreToolUse", guard_path),
        build_kimi_hook("PostToolUse", audit_path),
        build_kimi_hook("PostToolUseFailure", audit_path),
    ]


class KimiPlugin(AgentPlugin):
    """Install Elydora into detected Kimi user hook contracts."""

    manages_guard_runtime = True

    def preflight_install(self, config: InstallConfig) -> None:
        documents = read_kimi_documents()
        preflight_kimi_installation(config, documents)

    def install(self, config: InstallConfig) -> None:
        documents = read_kimi_documents()
        paths = preflight_kimi_installation(config, documents)
        rendered = [
            render_kimi_document(
                source,
                _installed_hooks(source, paths.guard_path, paths.audit_path),
            )
            for source in documents
        ]
        changes = prepare_kimi_installation(config, paths, rendered)
        commit_kimi_installation(changes)
        runtimes = " and ".join(
            source.contract.runtime_name for source in documents
        )
        print(
            f"{runtimes}: global PreToolUse, PostToolUse, "
            "and PostToolUseFailure hooks installed."
        )

    def uninstall(self, agent_id: str = "") -> None:
        documents = read_kimi_documents()
        rendered = [
            render_kimi_document(
                source,
                remove_managed_kimi_hooks(source.hooks, agent_id),
            )
            for source in documents
        ]
        commit_kimi_uninstall(prepare_kimi_uninstall(rendered))

    def status(self) -> PluginStatus:
        documents = read_kimi_documents()
        contracts = kimi_runtime_contracts(documents)
        installed = bool(contracts) and kimi_runtime_files_exist(contracts)
        config_path = (
            contracts[-1].config_path
            if contracts
            else documents[0].contract.config_path
        )
        details = (
            f"Config: {config_path}"
            if installed
            else f"Configured at {config_path}; managed contract incomplete"
        )
        return PluginStatus(
            installed=installed,
            agent=AGENT_KEY,
            details=details if contracts else "Not installed",
        )
