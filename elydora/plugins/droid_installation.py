"""Transactional Factory Droid hook installation."""

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
from .droid_config import (
    DroidDocument,
    DroidSources,
    RenderedDocument,
    installation_documents,
    source_documents,
)
from .droid_contract import AGENT_KEY, validate_javascript_regexes
from .droid_io import require_hooks_enabled
from .guard_template import generate_guard_script
from .hook_template import generate_hook_script

PRODUCT = "Factory Droid"


@dataclass(frozen=True)
class PreparedDroidInstallation:
    changes: Tuple[FileChange, ...]
    preconditions: Tuple[FilePrecondition, ...]


@dataclass(frozen=True)
class PreparedDroidUninstall:
    changes: Tuple[FileChange, ...]
    preconditions: Tuple[FilePrecondition, ...]


def _source_label(document: DroidDocument) -> str:
    if document.kind == "settings":
        return "Factory Droid user settings"
    if document.kind == "local-settings":
        return "Factory Droid local settings"
    if document.kind == "legacy":
        return "Factory Droid legacy hooks"
    return "Factory Droid user hooks"


def preflight_droid_installation(
    config: InstallConfig,
    sources: DroidSources,
) -> RuntimePaths:
    require_hooks_enabled(sources)
    validate_javascript_regexes([document.hooks for document in source_documents(sources)])
    validate_install_config(config, AGENT_KEY, PRODUCT)
    if not os.path.isabs(sys.executable):
        raise RuntimeError("Factory Droid requires an absolute Python executable path")
    paths = resolve_runtime_paths(config)
    validate_runtime_tree(paths.agent_directory, paths.agent_id, AGENT_KEY, PRODUCT)
    return paths


def _document_change(rendered: RenderedDocument) -> Optional[FileChange]:
    if not rendered.changed:
        return None
    document = rendered.document
    return source_change(
        document.file_path,
        _source_label(document),
        document.raw if document.exists else None,
        rendered.next_source,
        0o600,
        MAX_SOURCE_BYTES,
        document.snapshot,
    )


def _document_changes(rendered: Sequence[RenderedDocument]) -> Tuple[FileChange, ...]:
    return tuple(
        change for change in (_document_change(item) for item in rendered)
        if change is not None
    )


def _validate_rendered_documents(
    sources: DroidSources,
    rendered: Sequence[RenderedDocument],
) -> None:
    expected = installation_documents(sources)
    if len(rendered) != len(expected):
        raise ValueError("Factory Droid rendered source set is incomplete")
    for document in expected:
        matches = [
            item for item in rendered
            if same_path(item.document.file_path, document.file_path)
        ]
        if len(matches) != 1:
            raise ValueError("Factory Droid rendered source set contains unexpected paths")


def _unchanged_preconditions(
    documents: Sequence[DroidDocument],
    changed_paths: Sequence[str],
) -> Tuple[FilePrecondition, ...]:
    return tuple(
        FilePrecondition(
            document.file_path,
            _source_label(document),
            document.snapshot,
            MAX_SOURCE_BYTES,
        )
        for document in documents
        if not any(same_path(document.file_path, changed) for changed in changed_paths)
    )


def prepare_droid_installation(
    config: InstallConfig,
    sources: DroidSources,
    rendered: Sequence[RenderedDocument],
) -> PreparedDroidInstallation:
    paths = preflight_droid_installation(config, sources)
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
    document_changes = _document_changes(rendered)
    changes = (
        *runtime_file_changes(config, paths, AGENT_KEY, guard_script, audit_script),
        *document_changes,
    )
    changed_paths = [change.file_path for change in document_changes]
    preconditions = (
        *_unchanged_preconditions(source_documents(sources), changed_paths),
        *sources.policy.preconditions,
    )
    return PreparedDroidInstallation(changes, preconditions)


def commit_droid_installation(prepared: PreparedDroidInstallation) -> None:
    write_changes(prepared.changes, "Install Factory Droid hooks", prepared.preconditions)


def prepare_droid_uninstall(
    rendered: Sequence[RenderedDocument],
) -> PreparedDroidUninstall:
    changes = _document_changes(rendered)
    changed_paths = [change.file_path for change in changes]
    documents = [item.document for item in rendered]
    return PreparedDroidUninstall(changes, _unchanged_preconditions(documents, changed_paths))


def commit_droid_uninstall(prepared: PreparedDroidUninstall) -> None:
    write_changes(prepared.changes, "Uninstall Factory Droid hooks", prepared.preconditions)
