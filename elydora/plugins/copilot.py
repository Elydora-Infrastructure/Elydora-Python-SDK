"""GitHub Copilot CLI user-hook integration."""

from __future__ import annotations

import json
import os
from typing import List, Optional

from ._transaction import (
    FileChange,
    file_change,
    require_runtime,
    write_changes,
)
from .base import AgentPlugin, InstallConfig, PluginStatus
from .copilot_contract import (
    AGENT_KEY,
    AUDIT_SCRIPT,
    CopilotHooks,
    CopilotSources,
    RuntimeContract,
    build_handler,
    remove_managed_hooks,
    render_document,
    runtime_contracts,
)
from .copilot_io import read_sources, rendered_change, runtime_files_exist
from .hook_template import generate_hook_script


ELYDORA_DIR = os.path.join(os.path.expanduser("~"), ".elydora")


def _home_dir() -> str:
    return os.path.expanduser("~")


def _json_source(value: dict) -> str:
    return json.dumps(value, indent=2) + "\n"


def _runtime_config(config: InstallConfig, agent_id: str) -> dict:
    value = {
        "org_id": config.get("org_id", ""),
        "agent_id": agent_id,
        "kid": config.get("kid", ""),
        "base_url": config.get("base_url", "https://api.elydora.com"),
        "agent_name": AGENT_KEY,
    }
    token = config.get("token", "")
    if token:
        value["token"] = token
    return value


def _rendered_changes(
    sources: CopilotSources,
    user_hooks: CopilotHooks,
    agent_id: str = "",
) -> List[FileChange]:
    rendered = [render_document(sources.user, user_hooks)]
    if sources.legacy is not None:
        rendered.append(render_document(
            sources.legacy,
            remove_managed_hooks(
                sources.legacy.hooks,
                ELYDORA_DIR,
                agent_id,
            ),
        ))
    return [
        change
        for item in rendered
        for change in [rendered_change(item)]
        if change is not None
    ]


def _contracts(sources: CopilotSources) -> List[RuntimeContract]:
    contracts = runtime_contracts(sources.user.hooks, ELYDORA_DIR)
    if sources.legacy is not None:
        contracts.extend(runtime_contracts(sources.legacy.hooks, ELYDORA_DIR))
    unique = {}
    for contract in contracts:
        unique[os.path.normcase(contract.agent_id)] = contract
    return list(unique.values())


def _configured_path(
    sources: CopilotSources,
    contracts: List[RuntimeContract],
) -> str:
    user_ids = {
        os.path.normcase(contract.agent_id)
        for contract in runtime_contracts(sources.user.hooks, ELYDORA_DIR)
    }
    if any(os.path.normcase(contract.agent_id) in user_ids for contract in contracts):
        return sources.user.file_path
    if sources.legacy is not None:
        return sources.legacy.file_path
    return sources.user.file_path


class CopilotPlugin(AgentPlugin):
    """Install Elydora into GitHub Copilot CLI's global user hooks."""

    def install(self, config: InstallConfig) -> None:
        agent_id = config.get("agent_id", "")
        if not agent_id:
            raise ValueError("agent_id is required")
        sources = read_sources(_home_dir())
        guard_path = config.get("guard_script_path", "")
        require_runtime(guard_path, "Elydora guard runtime")

        agent_directory = os.path.join(ELYDORA_DIR, agent_id)
        audit_path = os.path.join(agent_directory, AUDIT_SCRIPT)
        user_hooks = remove_managed_hooks(sources.user.hooks, ELYDORA_DIR)
        user_hooks["preToolUse"] = [
            *user_hooks.get("preToolUse", []),
            build_handler(guard_path),
        ]
        user_hooks["postToolUse"] = [
            *user_hooks.get("postToolUse", []),
            build_handler(audit_path),
        ]

        audit_script = generate_hook_script(
            org_id=config.get("org_id", ""),
            agent_id=agent_id,
            kid=config.get("kid", ""),
            base_url=config.get("base_url", "https://api.elydora.com"),
        )
        candidates: List[Optional[FileChange]] = [
            file_change(
                os.path.join(agent_directory, "config.json"),
                "Elydora runtime config",
                _json_source(_runtime_config(config, agent_id)),
                0o600,
            ),
            file_change(
                os.path.join(agent_directory, "private.key"),
                "Elydora private key",
                config.get("private_key", ""),
                0o600,
            ),
            file_change(
                audit_path,
                "Elydora audit runtime",
                audit_script,
                0o700,
            ),
        ]
        changes = [change for change in candidates if change is not None]
        changes.extend(_rendered_changes(sources, user_hooks))
        write_changes(changes, "Install GitHub Copilot hooks")
        print(f"GitHub Copilot CLI hooks: {sources.user.file_path}")

    def uninstall(self, agent_id: str = "") -> None:
        sources = read_sources(_home_dir())
        user_hooks = remove_managed_hooks(
            sources.user.hooks,
            ELYDORA_DIR,
            agent_id,
        )
        changes = _rendered_changes(sources, user_hooks, agent_id)
        write_changes(changes, "Uninstall GitHub Copilot hooks")

    def status(self) -> PluginStatus:
        sources = read_sources(_home_dir())
        contracts = _contracts(sources)
        if not contracts:
            return PluginStatus(
                installed=False,
                agent=AGENT_KEY,
                details="Not installed",
            )
        installed = runtime_files_exist(contracts)
        config_path = _configured_path(sources, contracts)
        details = (
            f"Config: {config_path}"
            if installed
            else f"Configured at {config_path}; runtime scripts missing"
        )
        return PluginStatus(
            installed=installed,
            agent=AGENT_KEY,
            details=details,
        )
