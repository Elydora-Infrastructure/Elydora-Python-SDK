"""Transactional Cline hook and runtime installation."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import sys
from typing import List, Optional, Sequence

from elydora._runtime_paths import resolve_agent_directory

from ._managed_files import MAX_CONFIG_BYTES, MAX_SECRET_BYTES, MAX_SOURCE_BYTES
from ._transaction import FileChange, file_change, source_change, write_changes
from .base import InstallConfig
from .cline_contract import (
    AGENT_KEY,
    AUDIT_SCRIPT,
    GUARD_SCRIPT,
    HookFile,
    assert_wrapper_integrity,
    build_metadata,
    build_wrapper,
    elydora_dir,
    resolve_hook_files,
    runtime_contract,
    same_agent_id,
)
from .cline_io import (
    validate_api_origin,
    validate_hook_tree,
    validate_private_key,
    validate_runtime_tree,
)
from .guard_template import generate_guard_script
from .hook_template import generate_hook_script


@dataclass(frozen=True)
class ClineRuntimePaths:
    agent_id: str
    agent_directory: str
    guard_path: str
    audit_path: str


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


def _agent_paths(config: InstallConfig) -> ClineRuntimePaths:
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
    return ClineRuntimePaths(agent_id, agent_directory, guard_path, audit_path)


def _validate_install_config(config: InstallConfig) -> None:
    for field in ("org_id", "agent_id", "kid", "private_key", "base_url"):
        value = config.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{field} is required")
    if config.get("agent_name") != AGENT_KEY:
        raise ValueError(f"Cline installation requires agent_name {AGENT_KEY}")
    validate_private_key(config["private_key"])
    validate_api_origin(config["base_url"])
    if "token" in config:
        token = config["token"]
        if not isinstance(token, str) or not token:
            raise ValueError("token must be a non-empty string when provided")
    if not os.path.isabs(sys.executable):
        raise RuntimeError("Cline requires an absolute Python executable path")
    _agent_paths(config)


def _validate_hook_files(guard_file: HookFile, audit_file: HookFile) -> None:
    expected = resolve_hook_files()
    if not _same_path(guard_file.file_path, expected.guard_path) or not _same_path(
        audit_file.file_path, expected.audit_path
    ):
        raise ValueError("Cline installation received unexpected hook paths")
    validate_hook_tree(expected.hooks_directory)


def preflight_cline_installation(
    config: InstallConfig,
    guard_file: HookFile,
    audit_file: HookFile,
) -> ClineRuntimePaths:
    _validate_install_config(config)
    _validate_hook_files(guard_file, audit_file)
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


def _hook_change(
    file: HookFile, label: str, next_source: Optional[str]
) -> Optional[FileChange]:
    original = file.source if file.exists else None
    if file.exists and original is None:
        raise RuntimeError(f"{label} snapshot is missing source")
    return source_change(
        file.file_path,
        label,
        original,
        next_source,
        0o700,
    )


def _present(changes: Sequence[Optional[FileChange]]) -> List[FileChange]:
    return [change for change in changes if change is not None]


def prepare_cline_installation(
    config: InstallConfig,
    guard_file: HookFile,
    audit_file: HookFile,
) -> List[FileChange]:
    paths = preflight_cline_installation(config, guard_file, audit_file)
    guard_metadata = build_metadata("guard", paths.agent_id, paths.guard_path)
    audit_metadata = build_metadata("audit", paths.agent_id, paths.audit_path)
    guard_wrapper = build_wrapper(guard_metadata)
    audit_wrapper = build_wrapper(audit_metadata)
    runtime_contract(
        HookFile(True, guard_file.file_path, guard_wrapper, guard_metadata),
        HookFile(True, audit_file.file_path, audit_wrapper, audit_metadata),
    )
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
        (
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
            _hook_change(guard_file, "Cline PreToolUse hook", guard_wrapper),
            _hook_change(audit_file, "Cline PostToolUse hook", audit_wrapper),
        )
    )
    validate_runtime_tree(paths.agent_directory, paths.agent_id)
    validate_hook_tree(os.path.dirname(guard_file.file_path))
    return changes


def commit_cline_installation(changes: Sequence[FileChange]) -> None:
    write_changes(changes, "Install Cline hooks")


def prepare_cline_uninstall(
    files: Sequence[HookFile], agent_id: str = ""
) -> List[FileChange]:
    owned = [
        file
        for file in files
        if file.metadata is not None
        and (not agent_id or same_agent_id(file.metadata.agent_id, agent_id))
    ]
    changes: List[Optional[FileChange]] = []
    for file in owned:
        metadata = file.metadata
        assert metadata is not None
        assert_wrapper_integrity(file)
        changes.append(
            _hook_change(file, f"Cline {metadata.kind} hook", None)
        )
    return _present(changes)


def commit_cline_uninstall(changes: Sequence[FileChange]) -> None:
    write_changes(changes, "Uninstall Cline hooks")
