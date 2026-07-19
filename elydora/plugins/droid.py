"""Factory Droid native global user-hook integration."""

from __future__ import annotations

import json
import os
from typing import List, Optional

from ._transaction import FileChange, file_change, require_runtime, write_changes
from .base import AgentPlugin, InstallConfig, PluginStatus
from .droid_config import (
    additions_for,
    installation_targets,
    render_document,
    unique_documents,
)
from .droid_contract import (
    AGENT_KEY,
    AUDIT_SCRIPT,
    GUARD_SCRIPT,
    TOOL_EVENTS,
    build_group,
    elydora_dir,
    merge_hook_settings,
    runtime_contracts,
    validate_javascript_regexes,
)
from .droid_io import (
    display_config_path,
    read_sources,
    rendered_change,
    runtime_files_exist,
)
from .hook_template import generate_hook_script


def _agent_directory(agent_id: str) -> str:
    if (
        not agent_id
        or agent_id in {".", ".."}
        or os.path.basename(agent_id) != agent_id
        or os.path.isabs(agent_id)
    ):
        raise ValueError("agent_id must be a single non-empty path segment")
    return os.path.join(elydora_dir(), agent_id)


def _same_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(
        os.path.abspath(right)
    )


def _append_change(changes: List[FileChange], change: Optional[FileChange]) -> None:
    if change is not None:
        changes.append(change)


class DroidPlugin(AgentPlugin):
    """Install Elydora into Factory Droid's user-level hook sources."""

    def install(self, config: InstallConfig) -> None:
        agent_id = config.get("agent_id", "")
        agent_directory = _agent_directory(agent_id)
        sources = read_sources()
        validate_javascript_regexes([
            sources.primary.hooks if sources.primary is not None else {},
            sources.settings.hooks,
        ])

        guard_path = config.get("guard_script_path", "")
        expected_guard_path = os.path.join(agent_directory, GUARD_SCRIPT)
        if not _same_path(guard_path, expected_guard_path):
            raise ValueError(
                "Elydora guard runtime must use the managed agent directory: "
                f"{expected_guard_path}"
            )
        require_runtime(guard_path, "Elydora guard runtime")
        audit_path = os.path.join(agent_directory, AUDIT_SCRIPT)

        selected = installation_targets(sources)
        groups = {
            "PreToolUse": build_group(guard_path),
            "PostToolUse": build_group(audit_path),
        }
        documents = unique_documents([
            sources.primary,
            sources.settings if sources.settings.has_hooks_container else None,
            *(selected.targets[event] for event in TOOL_EVENTS),
        ])
        rendered = [
            render_document(
                document,
                None,
                additions_for(document, selected.targets, groups),
            )
            for document in documents
        ]

        runtime_config = {
            "org_id": config.get("org_id", ""),
            "agent_id": agent_id,
            "kid": config.get("kid", ""),
            "base_url": config.get("base_url", "https://api.elydora.com"),
            "token": config.get("token", ""),
            "agent_name": AGENT_KEY,
        }
        audit_script = generate_hook_script(
            org_id=config.get("org_id", ""),
            agent_id=agent_id,
            kid=config.get("kid", ""),
            base_url=config.get("base_url", "https://api.elydora.com"),
        )
        changes: List[FileChange] = []
        _append_change(changes, file_change(
            os.path.join(agent_directory, "config.json"),
            "Elydora runtime config",
            json.dumps(runtime_config, indent=2) + "\n",
            0o600,
        ))
        _append_change(changes, file_change(
            os.path.join(agent_directory, "private.key"),
            "Elydora private key",
            config.get("private_key", ""),
            0o600,
        ))
        _append_change(changes, file_change(
            audit_path,
            "Elydora audit runtime",
            audit_script,
            0o700,
        ))
        for item in rendered:
            _append_change(changes, rendered_change(item))
        write_changes(changes, "Write Factory Droid installation")

        locations = ", ".join(
            f"{event}: {selected.targets[event].file_path}"
            for event in TOOL_EVENTS
        )
        print(f"Factory Droid: {locations}")
        print("Factory Droid: run /hooks to review the Elydora hook changes.")

    def uninstall(self, agent_id: str = "") -> None:
        sources = read_sources()
        documents = unique_documents([
            sources.primary,
            sources.settings if sources.settings.has_hooks_container else None,
        ])
        changes: List[FileChange] = []
        for document in documents:
            rendered = render_document(document, agent_id or None, {})
            _append_change(changes, rendered_change(rendered))
        write_changes(changes, "Write Factory Droid hook sources")

    def status(self) -> PluginStatus:
        sources = read_sources()
        effective = merge_hook_settings(
            sources.primary.hooks if sources.primary is not None else None,
            sources.settings.hooks,
        )
        contracts = runtime_contracts(effective)
        config_path = display_config_path(sources)
        if effective.get("hooksDisabled") is True:
            return PluginStatus(
                installed=False,
                agent=AGENT_KEY,
                details=f"Configured hooks are disabled: {config_path}",
            )
        if not contracts:
            return PluginStatus(
                installed=False,
                agent=AGENT_KEY,
                details="Not installed",
            )
        installed = runtime_files_exist(contracts)
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
