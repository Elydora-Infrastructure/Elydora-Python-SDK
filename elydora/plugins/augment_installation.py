"""Transactional Auggie hook and runtime installation."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from typing import List, Optional

from elydora._runtime_paths import resolve_agent_directory

from ._managed_files import MAX_CONFIG_BYTES, MAX_SECRET_BYTES, MAX_SOURCE_BYTES
from ._transaction import FileChange, file_change, write_changes
from .augment_contract import (
    AGENT_KEY,
    AUDIT_SCRIPT,
    GUARD_SCRIPT,
    AugmentDocument,
    RenderedAugmentDocument,
    build_wrapper,
    elydora_dir,
    wrapper_paths,
)
from .augment_io import (
    rendered_change,
    validate_api_origin,
    validate_private_key,
    validate_runtime_tree,
)
from .base import InstallConfig
from .guard_template import generate_guard_script
from .hook_template import generate_hook_script


@dataclass(frozen=True)
class AugmentRuntimePaths:
    agent_id: str
    agent_directory: str
    guard_path: str
    audit_path: str
    guard_wrapper_path: str
    audit_wrapper_path: str


def _same_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(
        os.path.abspath(right)
    )


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


def _agent_paths(config: InstallConfig) -> AugmentRuntimePaths:
    agent_id = config.get("agent_id", "")
    if not agent_id:
        raise ValueError("agent_id is required")
    agent_directory = resolve_agent_directory(elydora_dir(), agent_id)
    guard_path = os.path.join(agent_directory, GUARD_SCRIPT)
    audit_path = os.path.join(agent_directory, AUDIT_SCRIPT)
    if not _same_path(config.get("guard_script_path", ""), guard_path):
        raise ValueError(
            f"Elydora guard runtime must use the managed agent directory: {guard_path}"
        )
    wrappers = wrapper_paths(agent_directory)
    return AugmentRuntimePaths(
        agent_id,
        agent_directory,
        guard_path,
        audit_path,
        wrappers.guard_path,
        wrappers.audit_path,
    )


def _validate_install_config(config: InstallConfig) -> None:
    for field in ("org_id", "agent_id", "kid", "private_key", "base_url"):
        value = config.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{field} is required")
    if config.get("agent_name") != AGENT_KEY:
        raise ValueError(
            f"Augment Code CLI installation requires agent_name {AGENT_KEY}"
        )
    validate_private_key(config["private_key"])
    validate_api_origin(config["base_url"])
    if "token" in config:
        token = config["token"]
        if not isinstance(token, str) or not token:
            raise ValueError("token must be a non-empty string when provided")
    _agent_paths(config)


def preflight_augment_installation(
    config: InstallConfig, document: AugmentDocument
) -> AugmentRuntimePaths:
    if not document.config_path:
        raise ValueError("Augment Code CLI installation requires a settings path")
    _validate_install_config(config)
    paths = _agent_paths(config)
    validate_runtime_tree(paths.agent_directory, paths.agent_id)
    return paths


def _runtime_change(
    file_path: str,
    label: str,
    next_source: str,
    mode: int,
    maximum_bytes: int = MAX_SOURCE_BYTES,
) -> Optional[FileChange]:
    return file_change(file_path, label, next_source, mode, maximum_bytes)


def _present(changes: List[Optional[FileChange]]) -> List[FileChange]:
    return [change for change in changes if change is not None]


def prepare_augment_installation(
    config: InstallConfig,
    paths: AugmentRuntimePaths,
    rendered: RenderedAugmentDocument,
) -> List[FileChange]:
    if not rendered.changed and rendered.document.raw is None:
        raise ValueError("Auggie hook installation did not produce a settings document")
    validate_runtime_tree(paths.agent_directory, paths.agent_id)
    guard_script = generate_guard_script(AGENT_KEY, paths.agent_id)
    audit_script = generate_hook_script(
        org_id=config.get("org_id", ""),
        agent_id=paths.agent_id,
        kid=config.get("kid", ""),
        base_url=config.get("base_url", "https://api.elydora.com"),
        native_payload=True,
        agent_name=AGENT_KEY,
    )
    changes = _present(
        [
            _runtime_change(
                paths.guard_path, "Elydora guard runtime", guard_script, 0o700
            ),
            _runtime_change(
                os.path.join(paths.agent_directory, "config.json"),
                "Elydora runtime config",
                _json_source(_runtime_config(config, paths.agent_id)),
                0o600,
                MAX_CONFIG_BYTES,
            ),
            _runtime_change(
                os.path.join(paths.agent_directory, "private.key"),
                "Elydora private key",
                config.get("private_key", ""),
                0o600,
                MAX_SECRET_BYTES,
            ),
            _runtime_change(
                paths.audit_path, "Elydora audit runtime", audit_script, 0o700
            ),
            _runtime_change(
                paths.guard_wrapper_path,
                "Auggie guard wrapper",
                build_wrapper(paths.guard_path),
                0o700,
            ),
            _runtime_change(
                paths.audit_wrapper_path,
                "Auggie audit wrapper",
                build_wrapper(paths.audit_path),
                0o700,
            ),
            rendered_change(rendered),
        ]
    )
    validate_runtime_tree(paths.agent_directory, paths.agent_id)
    return changes


def commit_augment_installation(changes: List[FileChange]) -> None:
    write_changes(changes, "Install Augment Code CLI hooks")


def prepare_augment_uninstall(
    rendered: RenderedAugmentDocument,
) -> List[FileChange]:
    return _present([rendered_change(rendered)])


def commit_augment_uninstall(changes: List[FileChange]) -> None:
    write_changes(changes, "Uninstall Augment Code CLI hooks")
