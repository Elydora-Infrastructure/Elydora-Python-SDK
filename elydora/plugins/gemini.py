"""Gemini CLI native global user-hook integration."""

from __future__ import annotations

from .base import AgentPlugin, InstallConfig, PluginStatus
from .gemini_config import GeminiDocument, render_gemini_document
from .gemini_contract import (
    AGENT_KEY,
    AUDIT_HOOK_NAME,
    GUARD_HOOK_NAME,
    build_gemini_group,
    disabled_managed_gemini_entries,
    gemini_runtime_contracts,
    managed_gemini_hooks_enabled,
)
from .gemini_installation import (
    commit_gemini_installation,
    preflight_gemini_installation,
    prepare_gemini_installation,
)
from .gemini_io import (
    gemini_runtime_files_exist,
    read_gemini_document,
    write_gemini_document,
)


def _require_enabled_hooks(document: GeminiDocument) -> None:
    if not document.hook_controls.enabled:
        raise ValueError(
            "Gemini CLI hooks are disabled by hooksConfig.enabled: "
            f"{document.file_path}"
        )
    disabled = disabled_managed_gemini_entries(document.hook_controls)
    if disabled:
        raise ValueError(
            "Gemini CLI hooks are disabled by hooksConfig.disabled: "
            + ", ".join(disabled)
        )


class GeminiPlugin(AgentPlugin):
    """Install Elydora into Gemini CLI's native user settings."""

    manages_guard_runtime = True

    def preflight_install(self, config: InstallConfig) -> None:
        document = read_gemini_document()
        _require_enabled_hooks(document)
        preflight_gemini_installation(config, document)

    def install(self, config: InstallConfig) -> None:
        document = read_gemini_document()
        _require_enabled_hooks(document)
        paths = preflight_gemini_installation(config, document)
        rendered = render_gemini_document(
            document,
            None,
            {
                "BeforeTool": build_gemini_group(
                    paths.guard_path, GUARD_HOOK_NAME
                ),
                "AfterTool": build_gemini_group(
                    paths.audit_path, AUDIT_HOOK_NAME
                ),
            },
        )
        changes = prepare_gemini_installation(config, paths, rendered)
        commit_gemini_installation(changes)
        print(f"Gemini CLI hooks installed at {document.file_path}")
        print("Gemini CLI verification: run /hooks list.")

    def uninstall(self, agent_id: str = "") -> None:
        document = read_gemini_document()
        write_gemini_document(
            render_gemini_document(document, agent_id or None, {})
        )

    def status(self) -> PluginStatus:
        document = read_gemini_document()
        contracts = gemini_runtime_contracts(document.hooks)
        controls_enabled = managed_gemini_hooks_enabled(
            document.hook_controls
        )
        configured = controls_enabled and bool(contracts)
        installed = configured and gemini_runtime_files_exist(contracts)
        if installed:
            details = f"Config: {document.file_path}"
        elif contracts and not controls_enabled:
            details = f"Configured hooks are disabled: {document.file_path}"
        elif contracts:
            details = (
                f"Configured at {document.file_path}; managed contract incomplete"
            )
        else:
            details = "Not installed"
        return PluginStatus(
            installed=installed,
            agent=AGENT_KEY,
            details=details,
        )
