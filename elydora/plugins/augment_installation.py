"""Transactional Auggie hook and runtime installation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from ._runtime import (
    DEFAULT_BASE_URL,
    RuntimePaths,
    present,
    resolve_runtime_paths,
    runtime_file_changes,
    validate_install_config,
    validate_runtime_tree,
)
from ._transaction import FileChange, file_change, write_changes
from .augment_contract import (
    AGENT_KEY,
    AUDIT_WRAPPER,
    GUARD_WRAPPER,
    AugmentDocument,
    RenderedAugmentDocument,
    build_wrapper,
    wrapper_paths,
)
from .augment_io import rendered_change
from .base import InstallConfig
from .guard_template import generate_guard_script
from .hook_template import generate_hook_script

WRAPPER_ARTIFACTS = (
    (GUARD_WRAPPER, "Auggie guard wrapper"),
    (AUDIT_WRAPPER, "Auggie audit wrapper"),
)


@dataclass(frozen=True)
class AugmentRuntimePaths(RuntimePaths):
    guard_wrapper_path: str
    audit_wrapper_path: str


def _agent_paths(config: InstallConfig) -> AugmentRuntimePaths:
    paths = resolve_runtime_paths(config)
    wrappers = wrapper_paths(paths.agent_directory)
    return AugmentRuntimePaths(
        paths.agent_id,
        paths.agent_directory,
        paths.guard_path,
        paths.audit_path,
        wrappers.guard_path,
        wrappers.audit_path,
    )


def _validate_runtime_tree(paths: AugmentRuntimePaths) -> None:
    validate_runtime_tree(
        paths.agent_directory, paths.agent_id, AGENT_KEY, "Auggie", WRAPPER_ARTIFACTS
    )


def preflight_augment_installation(
    config: InstallConfig, document: AugmentDocument
) -> AugmentRuntimePaths:
    if not document.config_path:
        raise ValueError("Augment Code CLI installation requires a settings path")
    validate_install_config(config, AGENT_KEY, "Augment Code CLI")
    paths = _agent_paths(config)
    _validate_runtime_tree(paths)
    return paths


def prepare_augment_installation(
    config: InstallConfig,
    paths: AugmentRuntimePaths,
    rendered: RenderedAugmentDocument,
) -> List[FileChange]:
    if not rendered.changed and rendered.document.raw is None:
        raise ValueError("Auggie hook installation did not produce a settings document")
    _validate_runtime_tree(paths)
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
            file_change(
                paths.guard_wrapper_path,
                "Auggie guard wrapper",
                build_wrapper(paths.guard_path),
                0o700,
            ),
            file_change(
                paths.audit_wrapper_path,
                "Auggie audit wrapper",
                build_wrapper(paths.audit_path),
                0o700,
            ),
            rendered_change(rendered),
        ]),
    ]
    _validate_runtime_tree(paths)
    return changes


def commit_augment_installation(changes: List[FileChange]) -> None:
    write_changes(changes, "Install Augment Code CLI hooks")


def prepare_augment_uninstall(rendered: RenderedAugmentDocument) -> List[FileChange]:
    return present([rendered_change(rendered)])


def commit_augment_uninstall(changes: List[FileChange]) -> None:
    write_changes(changes, "Uninstall Augment Code CLI hooks")
