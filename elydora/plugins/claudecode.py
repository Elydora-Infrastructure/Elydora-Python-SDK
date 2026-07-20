"""Claude Code native user-hook integration."""

from __future__ import annotations

from .base import AgentPlugin, InstallConfig, PluginStatus
from .claudecode_contract import (
    AGENT_KEY,
    AUDIT_STATUS,
    GUARD_STATUS,
    ClaudeHooks,
    build_claude_group,
    claude_runtime_contracts,
    remove_managed_claude_hooks,
    render_claude_document,
)
from .claudecode_installation import (
    commit_claude_installation,
    commit_claude_uninstall,
    preflight_claude_installation,
    prepare_claude_installation,
    prepare_claude_uninstall,
)
from .claudecode_io import (
    claude_runtime_files_exist,
    read_claude_document,
)


def _require_enabled_hooks(disabled: bool, file_path: str) -> None:
    if disabled:
        raise ValueError(
            f"Claude Code hooks are disabled by disableAllHooks: {file_path}"
        )


def _installed_hooks(
    hooks: ClaudeHooks, guard_path: str, audit_path: str
) -> ClaudeHooks:
    cleaned = remove_managed_claude_hooks(hooks)
    return {
        **cleaned,
        "PreToolUse": [
            *cleaned.get("PreToolUse", []),
            build_claude_group(guard_path, GUARD_STATUS),
        ],
        "PostToolUse": [
            *cleaned.get("PostToolUse", []),
            build_claude_group(audit_path, AUDIT_STATUS),
        ],
        "PostToolUseFailure": [
            *cleaned.get("PostToolUseFailure", []),
            build_claude_group(audit_path, AUDIT_STATUS),
        ],
    }


class ClaudeCodePlugin(AgentPlugin):
    """Install Elydora into Claude Code's native global user settings."""

    manages_guard_runtime = True

    def preflight_install(self, config: InstallConfig) -> None:
        document = read_claude_document()
        _require_enabled_hooks(document.hooks_disabled, document.file_path)
        preflight_claude_installation(config, document)

    def install(self, config: InstallConfig) -> None:
        document = read_claude_document()
        _require_enabled_hooks(document.hooks_disabled, document.file_path)
        paths = preflight_claude_installation(config, document)
        rendered = render_claude_document(
            document,
            _installed_hooks(document.hooks, paths.guard_path, paths.audit_path),
        )
        changes = prepare_claude_installation(config, paths, rendered)
        commit_claude_installation(changes)
        print(
            "Claude Code: global PreToolUse, PostToolUse, "
            "and PostToolUseFailure hooks installed."
        )
        print("  Claude Code verification: run /hooks and claude doctor.")

    def uninstall(self, agent_id: str = "") -> None:
        document = read_claude_document()
        rendered = render_claude_document(
            document,
            remove_managed_claude_hooks(document.hooks, agent_id),
        )
        commit_claude_uninstall(prepare_claude_uninstall(rendered))

    def status(self) -> PluginStatus:
        document = read_claude_document()
        contracts = claude_runtime_contracts(document.hooks)
        configured = not document.hooks_disabled and bool(contracts)
        installed = configured and claude_runtime_files_exist(contracts)
        details = (
            f"Config: {document.file_path}"
            if installed
            else f"Configured at {document.file_path}; managed contract incomplete"
        )
        return PluginStatus(
            installed=installed,
            agent=AGENT_KEY,
            details=details if configured else "Not installed",
        )
