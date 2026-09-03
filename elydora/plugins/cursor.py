"""Cursor native user-hook integration."""

from __future__ import annotations

import urllib.parse

from ._managed_files import physical_directory_exists
from ._runtime import (
    DEFAULT_BASE_URL,
    present,
    resolve_runtime_paths,
    runtime_file_changes,
    validate_private_key,
    validate_runtime_tree,
)
from ._transaction import write_changes
from .base import AgentPlugin, InstallConfig, PluginStatus
from .cursor_contract import (
    AGENT_KEY,
    build_handler,
    remove_managed_hooks,
    render_document,
    runtime_contracts,
)
from .cursor_io import (
    read_document,
    rendered_change,
    runtime_files_exist,
    validate_config_directory,
)
from .guard_template import generate_guard_script
from .hook_template import generate_hook_script

PRODUCT = "Cursor"


def _validate_install_config(config: InstallConfig) -> None:
    for field in ("org_id", "agent_id", "kid", "private_key"):
        value = config.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{field} is required")
    if config.get("agent_name") != AGENT_KEY:
        raise ValueError(f"Cursor installation requires agent_name {AGENT_KEY}")
    validate_private_key(config["private_key"])
    base_url = config.get("base_url", DEFAULT_BASE_URL)
    if not isinstance(base_url, str):
        raise ValueError("base_url must be a string")
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("base_url must be an absolute HTTP or HTTPS URL")
    if not isinstance(config.get("token", ""), str):
        raise ValueError("token must be a string")


class CursorPlugin(AgentPlugin):
    """Install Elydora into Cursor's native global user hooks."""

    manages_guard_runtime = True

    def preflight_install(self, config: InstallConfig) -> None:
        _validate_install_config(config)
        read_document()
        validate_config_directory()
        paths = resolve_runtime_paths(config)
        validate_runtime_tree(paths.agent_directory, paths.agent_id, AGENT_KEY, PRODUCT)

    def install(self, config: InstallConfig) -> None:
        self.preflight_install(config)
        document = read_document()
        paths = resolve_runtime_paths(config)
        if not physical_directory_exists(
            paths.agent_directory, "Elydora agent runtime directory"
        ):
            raise FileNotFoundError(
                f"Elydora agent runtime directory is missing: {paths.agent_directory}"
            )
        validate_runtime_tree(paths.agent_directory, paths.agent_id, AGENT_KEY, PRODUCT)
        hooks = remove_managed_hooks(document.hooks)
        hooks["preToolUse"] = [*hooks.get("preToolUse", []), build_handler(paths.guard_path)]
        hooks["postToolUse"] = [*hooks.get("postToolUse", []), build_handler(paths.audit_path)]
        hooks["postToolUseFailure"] = [
            *hooks.get("postToolUseFailure", []),
            build_handler(paths.audit_path),
        ]
        audit_script = generate_hook_script(
            org_id=config.get("org_id", ""),
            agent_id=paths.agent_id,
            kid=config.get("kid", ""),
            base_url=config.get("base_url", DEFAULT_BASE_URL),
            success_output="{}\n",
            fail_closed=True,
            native_payload=True,
            agent_name=AGENT_KEY,
        )
        guard_script = generate_guard_script(
            AGENT_KEY,
            paths.agent_id,
            success_output='{"permission":"allow"}\n',
            fail_closed=True,
            deny_protocol="cursor",
        )
        changes = [
            *runtime_file_changes(config, paths, AGENT_KEY, guard_script, audit_script),
            *present([rendered_change(render_document(document, hooks))]),
        ]
        write_changes(changes, "Install Cursor hooks")
        print(f"  Cursor hooks: {document.file_path}")

    def uninstall(self, agent_id: str = "") -> None:
        document = read_document()
        hooks = remove_managed_hooks(document.hooks, agent_id)
        change = rendered_change(render_document(document, hooks))
        if change is not None:
            write_changes([change], "Uninstall Cursor hooks")

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
