"""OpenAI Codex native user-hook integration."""

from __future__ import annotations

import base64
import json
import os
import urllib.parse
from typing import List, Optional

from elydora._runtime_paths import resolve_agent_directory
from elydora.utils import base64url_encode

from ._managed_files import MAX_CONFIG_BYTES, MAX_SECRET_BYTES
from ._transaction import FileChange
from .base import AgentPlugin, InstallConfig, PluginStatus
from .codex_contract import (
    AGENT_KEY,
    AUDIT_SCRIPT,
    AUDIT_STATUS,
    GUARD_SCRIPT,
    GUARD_STATUS,
    build_handler,
    remove_managed_hooks,
    render_document,
    runtime_contracts,
    runtime_root,
    same_path,
)
from .codex_io import (
    read_document,
    rendered_change,
    runtime_change,
    runtime_files_exist,
    validate_hooks_directory,
    validate_runtime_tree,
    write_codex_changes,
)
from .hook_template import generate_guard_script, generate_hook_script


def _runtime_config(config: InstallConfig, agent_id: str) -> dict:
    value = {
        "org_id": config.get("org_id", ""),
        "agent_id": agent_id,
        "kid": config.get("kid", ""),
        "base_url": config.get("base_url", "https://api.elydora.com"),
        "agent_name": AGENT_KEY,
    }
    token = config.get("token")
    if token:
        value["token"] = token
    return value


def _json_source(value: dict) -> str:
    return json.dumps(value, indent=2) + "\n"


def _present(changes: List[Optional[FileChange]]) -> List[FileChange]:
    return [change for change in changes if change is not None]


def _agent_paths(config: InstallConfig) -> tuple[str, str, str, str]:
    agent_id = config.get("agent_id", "")
    if not agent_id:
        raise ValueError("agent_id is required")
    agent_directory = resolve_agent_directory(runtime_root(), agent_id)
    guard_path = os.path.join(agent_directory, GUARD_SCRIPT)
    audit_path = os.path.join(agent_directory, AUDIT_SCRIPT)
    configured_guard = config.get("guard_script_path", "")
    if not same_path(configured_guard, guard_path):
        raise ValueError(
            f"Elydora guard runtime must use the managed agent directory: {guard_path}"
        )
    return agent_id, agent_directory, guard_path, audit_path


def _validate_private_key(value: str) -> None:
    try:
        padded = value + "=" * ((4 - len(value) % 4) % 4)
        seed = base64.b64decode(
            padded.replace("-", "+").replace("_", "/"),
            validate=True,
        )
    except (ValueError, UnicodeEncodeError) as error:
        raise ValueError(
            "private_key must be a canonical 32-byte base64url value"
        ) from error
    if len(seed) != 32 or base64url_encode(seed) != value:
        raise ValueError("private_key must be a canonical 32-byte base64url value")


def _validate_install_config(config: InstallConfig) -> None:
    for field in ("org_id", "agent_id", "kid", "private_key", "base_url"):
        value = config.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{field} is required")
    if config.get("agent_name") != AGENT_KEY:
        raise ValueError(f"Codex installation requires agent_name {AGENT_KEY}")
    _validate_private_key(config["private_key"])

    base_url = config["base_url"]
    try:
        parsed = urllib.parse.urlsplit(base_url)
        hostname = parsed.hostname
        parsed.port
        has_credentials = parsed.username is not None or parsed.password is not None
    except ValueError as error:
        raise ValueError("base_url must be an absolute HTTP or HTTPS URL") from error
    invalid_character = "\\" in base_url or any(
        character.isspace() or ord(character) < 32 for character in base_url
    )
    valid_origin = (
        parsed.scheme in ("http", "https")
        and bool(parsed.netloc)
        and hostname is not None
        and not invalid_character
    )
    if not valid_origin:
        raise ValueError("base_url must be an absolute HTTP or HTTPS URL")
    if has_credentials or parsed.query or parsed.fragment:
        raise ValueError(
            "base_url must exclude credentials, query parameters, and fragments"
        )

    if "token" in config:
        token = config["token"]
        if not isinstance(token, str) or not token:
            raise ValueError("token must be a non-empty string when provided")
    _agent_paths(config)


class CodexPlugin(AgentPlugin):
    """Install Elydora into Codex's native global user hooks."""

    manages_guard_runtime = True

    def preflight_install(self, config: InstallConfig) -> None:
        _validate_install_config(config)
        document = read_document()
        validate_hooks_directory(document.file_path)
        agent_id, agent_directory, _, _ = _agent_paths(config)
        validate_runtime_tree(runtime_root(), agent_directory, agent_id)

    def install(self, config: InstallConfig) -> None:
        self.preflight_install(config)
        document = read_document()
        agent_id, agent_directory, guard_path, audit_path = _agent_paths(config)

        hooks = remove_managed_hooks(document.hooks)
        hooks["PreToolUse"] = [
            *hooks.get("PreToolUse", []),
            {
                "matcher": "*",
                "hooks": [build_handler(guard_path, GUARD_STATUS)],
            },
        ]
        hooks["PostToolUse"] = [
            *hooks.get("PostToolUse", []),
            {
                "matcher": "*",
                "hooks": [build_handler(audit_path, AUDIT_STATUS)],
            },
        ]

        guard_script = generate_guard_script(AGENT_KEY, agent_id)
        audit_script = generate_hook_script(
            org_id=config.get("org_id", ""),
            agent_id=agent_id,
            kid=config.get("kid", ""),
            base_url=config.get("base_url", "https://api.elydora.com"),
            native_payload=True,
            agent_name=AGENT_KEY,
        )
        changes = _present(
            [
                runtime_change(
                    guard_path,
                    "Elydora guard runtime",
                    guard_script,
                    0o700,
                ),
                runtime_change(
                    os.path.join(agent_directory, "config.json"),
                    "Elydora runtime config",
                    _json_source(_runtime_config(config, agent_id)),
                    0o600,
                    MAX_CONFIG_BYTES,
                ),
                runtime_change(
                    os.path.join(agent_directory, "private.key"),
                    "Elydora private key",
                    config.get("private_key", ""),
                    0o600,
                    MAX_SECRET_BYTES,
                ),
                runtime_change(
                    audit_path,
                    "Elydora audit runtime",
                    audit_script,
                    0o700,
                ),
                rendered_change(render_document(document, hooks)),
            ]
        )
        write_codex_changes(changes, "Install Codex hooks")
        print(f"  Codex hooks: {document.file_path}")
        print("  Codex trust: run /hooks and approve both Elydora command hooks.")

    def uninstall(self, agent_id: str = "") -> None:
        document = read_document()
        hooks = remove_managed_hooks(document.hooks, agent_id)
        change = rendered_change(render_document(document, hooks))
        if change is None:
            return
        validate_hooks_directory(document.file_path)
        write_codex_changes([change], "Uninstall Codex hooks")

    def status(self) -> PluginStatus:
        document = read_document()
        contracts = runtime_contracts(document.hooks)
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
            else f"Configured at {document.file_path}; runtime files missing"
        )
        return PluginStatus(
            installed=installed,
            agent=AGENT_KEY,
            details=details,
        )
