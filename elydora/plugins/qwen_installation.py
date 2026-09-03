"""Transactional Qwen Code hook and runtime installation."""

from __future__ import annotations

from typing import List, Optional

from ._managed_files import MAX_SOURCE_BYTES
from ._runtime import (
    DEFAULT_BASE_URL,
    RuntimePaths,
    present,
    resolve_runtime_paths,
    runtime_file_changes,
    same_path,
    validate_install_config,
    validate_runtime_tree,
)
from ._transaction import FileChange, FilePrecondition, source_change, write_changes
from .base import InstallConfig
from .guard_template import generate_guard_script
from .hook_template import generate_hook_script
from .qwen_config import RenderedQwenDocument, qwen_document_label
from .qwen_contract import AGENT_KEY
from .qwen_sources import QwenSources, require_qwen_hooks_enabled

PRODUCT = "Qwen Code"


def preflight_qwen_installation(
    config: InstallConfig, sources: QwenSources
) -> RuntimePaths:
    require_qwen_hooks_enabled(sources)
    validate_install_config(config, AGENT_KEY, PRODUCT)
    paths = resolve_runtime_paths(config)
    validate_runtime_tree(paths.agent_directory, paths.agent_id, AGENT_KEY, PRODUCT)
    return paths


def _rendered_change(rendered: RenderedQwenDocument) -> Optional[FileChange]:
    if not rendered.changed:
        return None
    return source_change(
        rendered.document.file_path,
        qwen_document_label(rendered.document),
        rendered.document.raw if rendered.document.exists else None,
        rendered.next_source,
        0o600,
        MAX_SOURCE_BYTES,
        expected_snapshot=rendered.document.snapshot,
    )


def prepare_qwen_installation(
    config: InstallConfig,
    paths: RuntimePaths,
    rendered: RenderedQwenDocument,
) -> List[FileChange]:
    guard_script = generate_guard_script(AGENT_KEY, paths.agent_id)
    audit_script = generate_hook_script(
        org_id=config.get("org_id", ""),
        agent_id=paths.agent_id,
        kid=config.get("kid", ""),
        base_url=config.get("base_url", DEFAULT_BASE_URL),
        native_payload=True,
        agent_name=AGENT_KEY,
    )
    return [
        *runtime_file_changes(config, paths, AGENT_KEY, guard_script, audit_script),
        *present([_rendered_change(rendered)]),
    ]


def _read_only_preconditions(
    sources: QwenSources, changed_path: str
) -> List[FilePrecondition]:
    return [
        condition
        for condition in sources.preconditions
        if not same_path(condition.file_path, changed_path)
    ]


def commit_qwen_installation(changes: List[FileChange], sources: QwenSources) -> None:
    write_changes(
        changes,
        "Install Qwen Code hooks",
        _read_only_preconditions(sources, sources.user.file_path),
    )


def prepare_qwen_uninstall(rendered: RenderedQwenDocument) -> Optional[FileChange]:
    return _rendered_change(rendered)


def commit_qwen_uninstall(change: Optional[FileChange], sources: QwenSources) -> None:
    if change is None:
        return
    write_changes(
        [change],
        "Uninstall Qwen Code hooks",
        _read_only_preconditions(sources, sources.user.file_path),
    )
