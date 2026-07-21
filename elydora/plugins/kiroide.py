"""Kiro IDE 1.0 workspace hook integration."""

from __future__ import annotations

from .base import AgentPlugin, InstallConfig, PluginStatus
from .kiroide_contract import (
    AGENT_KEY,
    AUDIT_NAME,
    GUARD_NAME,
    build_kiroide_hook,
    kiroide_runtime_contracts,
    managed_kiroide_hooks_present,
    render_kiroide_document,
    require_available_kiroide_hooks,
    without_managed_kiroide_hooks,
)
from .kiroide_installation import (
    commit_kiroide_installation,
    commit_kiroide_uninstall,
    preflight_kiroide_installation,
    prepare_kiroide_installation,
    prepare_kiroide_uninstall,
)
from .kiroide_command import same_kiroide_agent_id
from .kiroide_io import (
    kiroide_runtime_files_exist,
    legacy_kiroide_contract_matches_agent,
    read_kiroide_sources,
    require_kiroide_workspace_owner,
)


class KiroIdePlugin(AgentPlugin):
    """Install Elydora into the active Kiro IDE workspace."""

    manages_guard_runtime = True
    manages_runtime_directories = True
    manages_runtime_removal = True

    def preflight_install(self, config: InstallConfig) -> None:
        sources = read_kiroide_sources()
        require_available_kiroide_hooks(sources.document.hooks)
        preflight_kiroide_installation(config, sources)

    def install(self, config: InstallConfig) -> None:
        sources = read_kiroide_sources()
        require_available_kiroide_hooks(sources.document.hooks)
        paths = preflight_kiroide_installation(config, sources)
        hooks = without_managed_kiroide_hooks(sources.document.hooks)
        rendered = render_kiroide_document(
            sources.document,
            [
                *hooks,
                build_kiroide_hook(GUARD_NAME, paths.guard_path),
                build_kiroide_hook(AUDIT_NAME, paths.audit_path),
            ],
        )
        prepared = prepare_kiroide_installation(
            config, paths, sources, rendered
        )
        commit_kiroide_installation(prepared, sources, paths)
        print(f"  Kiro IDE workspace hooks: {sources.paths.config_path}")
        print(
            "  Kiro IDE verification: confirm Elydora hooks in the "
            "Agent Hooks panel."
        )

    def uninstall(self, agent_id: str = "") -> None:
        sources = read_kiroide_sources()
        contracts = kiroide_runtime_contracts(sources.document.hooks)
        if agent_id:
            discovered_agent_ids = [agent_id]
        else:
            discovered_agent_ids = [contract.agent_id for contract in contracts]
            legacy_contract = sources.legacy.contract
            if legacy_contract is not None:
                discovered_agent_ids.append(legacy_contract.agent_id)
        agent_ids: list[str] = []
        for discovered_agent_id in discovered_agent_ids:
            if not any(
                same_kiroide_agent_id(discovered_agent_id, existing_agent_id)
                for existing_agent_id in agent_ids
            ):
                agent_ids.append(discovered_agent_id)
        for managed_agent_id in agent_ids:
            owns_workspace_runtime = any(
                same_kiroide_agent_id(contract.agent_id, managed_agent_id)
                for contract in contracts
            )
            require_kiroide_workspace_owner(
                managed_agent_id,
                sources.paths.workspace_root,
                allow_missing_workspace_root=owns_workspace_runtime,
                allow_legacy_ownerless_config=(
                    legacy_kiroide_contract_matches_agent(
                        sources.legacy, managed_agent_id
                    )
                ),
            )
        rendered = render_kiroide_document(
            sources.document,
            without_managed_kiroide_hooks(sources.document.hooks, agent_id),
        )
        prepared = prepare_kiroide_uninstall(
            sources, rendered, agent_id, agent_ids
        )
        commit_kiroide_uninstall(prepared, sources)
        print("Elydora hooks uninstalled from Kiro IDE.")

    def status(self) -> PluginStatus:
        sources = read_kiroide_sources()
        require_available_kiroide_hooks(sources.document.hooks)
        contracts = kiroide_runtime_contracts(sources.document.hooks)
        configured = bool(contracts)
        managed_present = managed_kiroide_hooks_present(sources.document.hooks)
        installed = configured and kiroide_runtime_files_exist(
            contracts, sources.paths.workspace_root
        )
        if installed:
            details = f"Config: {sources.paths.config_path}"
        elif configured:
            details = (
                f"Configured at {sources.paths.config_path}; "
                "runtime files are missing or invalid"
            )
        elif managed_present:
            details = (
                f"Managed hooks are incomplete or invalid: "
                f"{sources.paths.config_path}"
            )
        else:
            details = "Not installed"
        return PluginStatus(installed=installed, agent=AGENT_KEY, details=details)
