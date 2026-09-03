"""Transactional GitHub Copilot CLI hook installation."""

from __future__ import annotations

from dataclasses import dataclass
import os
import sys
from typing import Optional, Sequence, Tuple

from ._managed_files import MAX_SOURCE_BYTES
from ._runtime import (
    DEFAULT_BASE_URL,
    RuntimePaths,
    resolve_runtime_paths,
    runtime_file_changes,
    same_path,
    validate_install_config,
    validate_runtime_tree,
)
from ._transaction import FileChange, FilePrecondition, source_change, write_changes
from .base import InstallConfig
from .copilot_contract import AGENT_KEY, CopilotSources, RenderedDocument
from .copilot_io import require_hooks_enabled
from .copilot_schema import validate_javascript_regexes
from .guard_template import generate_guard_script
from .hook_template import generate_hook_script

PRODUCT = "GitHub Copilot CLI"


@dataclass(frozen=True)
class PreparedCopilotInstallation:
    changes: Tuple[FileChange, ...]
    preconditions: Tuple[FilePrecondition, ...]


def preflight_copilot_installation(
    config: InstallConfig,
    sources: CopilotSources,
) -> RuntimePaths:
    if not sources.user.file_path:
        raise ValueError("GitHub Copilot CLI installation requires a user hook path")
    require_hooks_enabled(sources)
    hook_sources = [sources.user.hooks]
    if sources.legacy is not None:
        hook_sources.append(sources.legacy.hooks)
    validate_javascript_regexes(hook_sources)
    validate_install_config(config, AGENT_KEY, PRODUCT)
    if not os.path.isabs(sys.executable):
        raise RuntimeError("GitHub Copilot CLI requires an absolute Python executable path")
    paths = resolve_runtime_paths(config)
    validate_runtime_tree(paths.agent_directory, paths.agent_id, AGENT_KEY, "Copilot")
    return paths


def _document_change(rendered: RenderedDocument) -> Optional[FileChange]:
    if not rendered.changed:
        return None
    return source_change(
        rendered.document.file_path,
        "GitHub Copilot hook source",
        rendered.document.raw,
        rendered.next_source,
        0o600,
        MAX_SOURCE_BYTES,
        rendered.document.snapshot,
    )


def _document_preconditions(
    rendered: Sequence[RenderedDocument],
) -> Tuple[FilePrecondition, ...]:
    return tuple(
        FilePrecondition(
            item.document.file_path,
            "GitHub Copilot hook source",
            item.document.snapshot,
            MAX_SOURCE_BYTES,
        )
        for item in rendered
        if not item.changed
    )


def _settings_preconditions(sources: CopilotSources) -> Tuple[FilePrecondition, ...]:
    return tuple(
        FilePrecondition(item.file_path, item.label, item.snapshot, MAX_SOURCE_BYTES)
        for item in sources.settings_preconditions
    )


def _validate_rendered_documents(
    sources: CopilotSources,
    rendered: Sequence[RenderedDocument],
) -> None:
    expected = [sources.user]
    if sources.legacy is not None:
        expected.append(sources.legacy)
    if len(rendered) != len(expected):
        raise ValueError("GitHub Copilot rendered source set is incomplete")
    for document in expected:
        matches = [
            item for item in rendered
            if same_path(item.document.file_path, document.file_path)
        ]
        if len(matches) != 1:
            raise ValueError("GitHub Copilot rendered source set contains unexpected paths")


def prepare_copilot_installation(
    config: InstallConfig,
    sources: CopilotSources,
    rendered: Sequence[RenderedDocument],
) -> PreparedCopilotInstallation:
    paths = preflight_copilot_installation(config, sources)
    _validate_rendered_documents(sources, rendered)
    guard_script = generate_guard_script(AGENT_KEY, paths.agent_id)
    audit_script = generate_hook_script(
        org_id=config.get("org_id", ""),
        agent_id=paths.agent_id,
        kid=config.get("kid", ""),
        base_url=config.get("base_url", DEFAULT_BASE_URL),
        native_payload=True,
        agent_name=AGENT_KEY,
    )
    document_changes = [
        change for change in (_document_change(item) for item in rendered)
        if change is not None
    ]
    changes = (
        *runtime_file_changes(config, paths, AGENT_KEY, guard_script, audit_script),
        *document_changes,
    )
    preconditions = (
        *_settings_preconditions(sources),
        *_document_preconditions(rendered),
    )
    return PreparedCopilotInstallation(changes, preconditions)


def commit_copilot_installation(prepared: PreparedCopilotInstallation) -> None:
    write_changes(prepared.changes, "Install GitHub Copilot hooks", prepared.preconditions)


def prepare_copilot_uninstall(
    rendered: Sequence[RenderedDocument],
) -> Tuple[FileChange, ...]:
    return tuple(
        change for change in (_document_change(item) for item in rendered)
        if change is not None
    )


def commit_copilot_uninstall(changes: Sequence[FileChange]) -> None:
    write_changes(changes, "Uninstall GitHub Copilot hooks")
