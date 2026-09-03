"""OpenAI Codex native user-hook integration."""

from __future__ import annotations

from ._runtime import (
    DEFAULT_BASE_URL,
    present,
    resolve_runtime_paths,
    runtime_file_changes,
    validate_install_config,
    validate_runtime_tree,
)
from ._transaction import write_changes
from .base import AgentPlugin, InstallConfig, PluginStatus
from .codex_contract import (
    AGENT_KEY,
    AUDIT_STATUS,
    GUARD_STATUS,
    build_handler,
    remove_managed_hooks,
    render_document,
    runtime_contracts,
)
from .codex_io import (
    read_document,
    rendered_change,
    runtime_files_exist,
    validate_hooks_directory,
)
from .guard_template import generate_guard_script
from .hook_template import generate_hook_script

PRODUCT = "Codex"


class CodexPlugin(AgentPlugin):
    """Install Elydora into Codex's native global user hooks."""

    manages_guard_runtime = True

    def preflight_install(self, config: InstallConfig) -> None:
        validate_install_config(config, AGENT_KEY, PRODUCT)
        document = read_document()
        validate_hooks_directory(document.file_path)
        paths = resolve_runtime_paths(config)
        validate_runtime_tree(paths.agent_directory, paths.agent_id, AGENT_KEY, PRODUCT)

    def install(self, config: InstallConfig) -> None:
        self.preflight_install(config)
        document = read_document()
        paths = resolve_runtime_paths(config)
        hooks = remove_managed_hooks(document.hooks)
        hooks["PreToolUse"] = [
            *hooks.get("PreToolUse", []),
            {"matcher": "*", "hooks": [build_handler(paths.guard_path, GUARD_STATUS)]},
        ]
        hooks["PostToolUse"] = [
            *hooks.get("PostToolUse", []),
            {"matcher": "*", "hooks": [build_handler(paths.audit_path, AUDIT_STATUS)]},
        ]
        guard_script = generate_guard_script(AGENT_KEY, paths.agent_id)
        audit_script = generate_hook_script(
            org_id=config.get("org_id", ""),
            agent_id=paths.agent_id,
            kid=config.get("kid", ""),
            base_url=config.get("base_url", DEFAULT_BASE_URL),
            native_payload=True,
            agent_name=AGENT_KEY,
        )
        changes = [
            *runtime_file_changes(config, paths, AGENT_KEY, guard_script, audit_script),
            *present([rendered_change(render_document(document, hooks))]),
        ]
        write_changes(changes, "Install Codex hooks")
        print(f"  Codex hooks: {document.file_path}")
        print("  Codex trust: run /hooks and approve both Elydora command hooks.")

    def uninstall(self, agent_id: str = "") -> None:
        document = read_document()
        hooks = remove_managed_hooks(document.hooks, agent_id)
        change = rendered_change(render_document(document, hooks))
        if change is None:
            return
        validate_hooks_directory(document.file_path)
        write_changes([change], "Uninstall Codex hooks")

    def status(self) -> PluginStatus:
        document = read_document()
        contracts = runtime_contracts(document.hooks)
        if not contracts:
            return PluginStatus(installed=False, agent=AGENT_KEY, details="Not installed")
        installed = runtime_files_exist(contracts)
        details = (
            f"Config: {document.file_path}"
            if installed
            else f"Configured at {document.file_path}; runtime files missing"
        )
        return PluginStatus(installed=installed, agent=AGENT_KEY, details=details)
