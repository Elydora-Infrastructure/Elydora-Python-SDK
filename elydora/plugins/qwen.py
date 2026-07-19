"""Qwen Code native global user-hook integration."""

from __future__ import annotations

import json
import os
from typing import List, Optional

from ._transaction import FileChange, file_change, write_changes
from .base import AgentPlugin, InstallConfig, PluginStatus
from .hook_template import generate_hook_script
from .qwen_config import render_document
from .qwen_contract import (
    AGENT_KEY,
    AUDIT_SCRIPT,
    GUARD_SCRIPT,
    build_group,
    elydora_dir,
    runtime_contracts,
    validate_javascript_regexes,
)
from .qwen_io import (
    read_document,
    rendered_change,
    require_runtime,
    runtime_files_exist,
)


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


class QwenPlugin(AgentPlugin):
    """Install Elydora into Qwen Code's global user settings."""

    def install(self, config: InstallConfig) -> None:
        agent_id = config.get("agent_id", "")
        agent_directory = _agent_directory(agent_id)
        document = read_document()
        validate_javascript_regexes([document.hooks])

        guard_path = config.get("guard_script_path", "")
        expected_guard_path = os.path.join(agent_directory, GUARD_SCRIPT)
        if not _same_path(guard_path, expected_guard_path):
            raise ValueError(
                "Elydora guard runtime must use the managed agent directory: "
                f"{expected_guard_path}"
            )
        require_runtime(guard_path, "Elydora guard runtime")
        audit_path = os.path.join(agent_directory, AUDIT_SCRIPT)
        rendered = render_document(
            document,
            None,
            {
                "PreToolUse": build_group(guard_path),
                "PostToolUse": build_group(audit_path),
            },
        )

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
        _append_change(
            changes,
            file_change(
                os.path.join(agent_directory, "config.json"),
                "Elydora runtime config",
                json.dumps(runtime_config, indent=2) + "\n",
                0o600,
            ),
        )
        _append_change(
            changes,
            file_change(
                os.path.join(agent_directory, "private.key"),
                "Elydora private key",
                config.get("private_key", ""),
                0o600,
            ),
        )
        _append_change(
            changes,
            file_change(
                audit_path,
                "Elydora audit runtime",
                audit_script,
                0o700,
            ),
        )
        _append_change(changes, rendered_change(rendered))
        write_changes(changes, "Write Qwen Code installation")

        print(f"Qwen Code: user hooks installed at {document.file_path}")
        print("Qwen Code: run /hooks to review the Elydora hook changes.")

    def uninstall(self, agent_id: str = "") -> None:
        document = read_document()
        if not document.exists:
            return
        rendered = render_document(document, agent_id or None, {})
        change = rendered_change(rendered)
        write_changes(
            [change] if change is not None else [],
            "Write Qwen Code settings",
        )

    def status(self) -> PluginStatus:
        document = read_document()
        contracts = runtime_contracts(document.hooks)
        if document.hooks_disabled:
            return PluginStatus(
                installed=False,
                agent=AGENT_KEY,
                details=f"Configured hooks are disabled: {document.file_path}",
            )
        if not contracts:
            return PluginStatus(
                installed=False,
                agent=AGENT_KEY,
                details="Not installed",
            )
        installed = runtime_files_exist(contracts)
        details = (
            f"Config: {document.file_path}"
            if installed
            else f"Configured at {document.file_path}; runtime scripts missing"
        )
        return PluginStatus(
            installed=installed,
            agent=AGENT_KEY,
            details=details,
        )
