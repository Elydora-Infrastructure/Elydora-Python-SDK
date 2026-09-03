"""Transactional Cline hook and runtime installation."""

from __future__ import annotations

import os
import sys
from typing import List, Optional, Sequence

from ._runtime import (
    DEFAULT_BASE_URL,
    RuntimePaths,
    present,
    resolve_runtime_paths,
    runtime_file_changes,
    same_agent_id,
    same_path,
    validate_install_config,
    validate_runtime_tree,
)
from ._transaction import FileChange, source_change, write_changes
from .base import InstallConfig
from .cline_contract import (
    AGENT_KEY,
    HookFile,
    assert_wrapper_integrity,
    build_metadata,
    build_wrapper,
    resolve_hook_files,
    runtime_contract,
)
from .cline_io import validate_hook_tree
from .guard_template import generate_guard_script
from .hook_template import generate_hook_script

PRODUCT = "Cline"


def _validate_hook_files(guard_file: HookFile, audit_file: HookFile) -> None:
    expected = resolve_hook_files()
    if not same_path(guard_file.file_path, expected.guard_path) or not same_path(
        audit_file.file_path, expected.audit_path
    ):
        raise ValueError("Cline installation received unexpected hook paths")
    validate_hook_tree(expected.hooks_directory)


def preflight_cline_installation(
    config: InstallConfig,
    guard_file: HookFile,
    audit_file: HookFile,
) -> RuntimePaths:
    validate_install_config(config, AGENT_KEY, PRODUCT)
    if not os.path.isabs(sys.executable):
        raise RuntimeError("Cline requires an absolute Python executable path")
    _validate_hook_files(guard_file, audit_file)
    paths = resolve_runtime_paths(config)
    validate_runtime_tree(paths.agent_directory, paths.agent_id, AGENT_KEY, PRODUCT)
    return paths


def _hook_change(
    file: HookFile, label: str, next_source: Optional[str]
) -> Optional[FileChange]:
    original = file.source if file.exists else None
    if file.exists and original is None:
        raise RuntimeError(f"{label} snapshot is missing source")
    return source_change(file.file_path, label, original, next_source, 0o700)


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
        base_url=config.get("base_url", DEFAULT_BASE_URL),
        native_payload=True,
        agent_name=AGENT_KEY,
    )
    changes = [
        *runtime_file_changes(config, paths, AGENT_KEY, guard_script, audit_script),
        *present([
            _hook_change(guard_file, "Cline PreToolUse hook", guard_wrapper),
            _hook_change(audit_file, "Cline PostToolUse hook", audit_wrapper),
        ]),
    ]
    validate_runtime_tree(paths.agent_directory, paths.agent_id, AGENT_KEY, PRODUCT)
    validate_hook_tree(os.path.dirname(guard_file.file_path))
    return changes


def commit_cline_installation(changes: Sequence[FileChange]) -> None:
    write_changes(changes, "Install Cline hooks")


def prepare_cline_uninstall(
    files: Sequence[HookFile], agent_id: str = ""
) -> List[FileChange]:
    changes: List[Optional[FileChange]] = []
    for file in files:
        metadata = file.metadata
        if metadata is None or (agent_id and not same_agent_id(metadata.agent_id, agent_id)):
            continue
        assert_wrapper_integrity(file)
        changes.append(_hook_change(file, f"Cline {metadata.kind} hook", None))
    return present(changes)


def commit_cline_uninstall(changes: Sequence[FileChange]) -> None:
    write_changes(changes, "Uninstall Cline hooks")
