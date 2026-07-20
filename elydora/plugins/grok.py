"""Grok Build native user-hook integration."""

from __future__ import annotations

from .base import AgentPlugin, InstallConfig, PluginStatus
from .grok_contract import (
    AGENT_KEY,
    GrokHooks,
    build_grok_group,
    grok_runtime_contracts,
    remove_managed_grok_hooks,
    render_grok_document,
)
from .grok_installation import (
    commit_grok_installation,
    commit_grok_uninstall,
    preflight_grok_installation,
    prepare_grok_installation,
    prepare_grok_uninstall,
)
from .grok_io import grok_runtime_files_exist, read_grok_document


def _installed_hooks(
    hooks: GrokHooks, guard_path: str, audit_path: str
) -> GrokHooks:
    cleaned = remove_managed_grok_hooks(hooks)
    return {
        **cleaned,
        "PreToolUse": [
            *cleaned.get("PreToolUse", []),
            build_grok_group(guard_path),
        ],
        "PostToolUse": [
            *cleaned.get("PostToolUse", []),
            build_grok_group(audit_path),
        ],
        "PostToolUseFailure": [
            *cleaned.get("PostToolUseFailure", []),
            build_grok_group(audit_path),
        ],
    }


class GrokPlugin(AgentPlugin):
    """Install Elydora into Grok Build's native global user hooks."""

    manages_guard_runtime = True

    def preflight_install(self, config: InstallConfig) -> None:
        document = read_grok_document()
        preflight_grok_installation(config, document)

    def install(self, config: InstallConfig) -> None:
        document = read_grok_document()
        paths = preflight_grok_installation(config, document)
        rendered = render_grok_document(
            document,
            _installed_hooks(document.hooks, paths.guard_path, paths.audit_path),
        )
        changes = prepare_grok_installation(config, paths, rendered)
        commit_grok_installation(changes)
        print(
            "Grok Build: global PreToolUse, PostToolUse, "
            "and PostToolUseFailure hooks installed."
        )

    def uninstall(self, agent_id: str = "") -> None:
        document = read_grok_document()
        rendered = render_grok_document(
            document,
            remove_managed_grok_hooks(document.hooks, agent_id),
        )
        commit_grok_uninstall(prepare_grok_uninstall(rendered))

    def status(self) -> PluginStatus:
        document = read_grok_document()
        contracts = grok_runtime_contracts(document.hooks)
        installed = bool(contracts) and grok_runtime_files_exist(contracts)
        details = (
            f"Config: {document.config_path}"
            if installed
            else f"Configured at {document.config_path}; managed contract incomplete"
        )
        return PluginStatus(
            installed=installed,
            agent=AGENT_KEY,
            details=details if contracts else "Not installed",
        )
