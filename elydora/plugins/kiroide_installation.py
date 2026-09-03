"""Transactional Kiro IDE workspace hook installation."""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import List, Optional, Sequence, Tuple

from ._managed_files import (
    MAX_CONFIG_BYTES,
    MAX_SECRET_BYTES,
    MAX_SOURCE_BYTES,
    read_physical_file,
)
from ._opaque_removal import OpaqueRemovalChange
from ._runtime import (
    DEFAULT_BASE_URL,
    present,
    resolve_runtime_paths,
    runtime_config_source,
    same_agent_id,
    validate_install_config,
)
from ._transaction import (
    DirectoryPrecondition,
    FileChange,
    FilePrecondition,
    cleanup_created_directories,
    source_change,
    write_changes,
)
from ._strict_json import JsonObject
from ._runtime_removal import (
    KIRO_IDE_RUNTIME_FILES,
    PreparedRuntimeRemoval,
    finalize_runtime_removal,
    prepare_runtime_removal,
)
from .base import InstallConfig
from .guard_template import generate_guard_script
from .hook_template import generate_hook_script
from .kiroide_contract import (
    AGENT_KEY,
    RenderedKiroIdeDocument,
    kiroide_runtime_contracts,
)
from .kiroide_directories import (
    KiroIdeRuntimeDirectoryState,
    inspect_runtime_directories,
    pin_runtime_directories,
    pin_workspace_directories,
    require_runtime_directory_state,
)
from .kiroide_io import (
    KiroIdeSources,
    LegacyKiroIdeDocument,
    legacy_kiroide_contract_matches_agent,
    require_physical_legacy_directory,
    validate_kiroide_runtime_config,
    validate_runtime_tree,
)

PRODUCT = "Kiro IDE"


@dataclass(frozen=True)
class KiroIdeRuntimePaths:
    agent_id: str
    runtime_parent: str
    runtime_root: str
    agent_directory: str
    guard_path: str
    audit_path: str
    directories: KiroIdeRuntimeDirectoryState


@dataclass(frozen=True)
class PreparedKiroIdeInstallation:
    changes: List[FileChange]
    runtime_preconditions: List[FilePrecondition]


@dataclass(frozen=True)
class PreparedKiroIdeUninstall:
    changes: List[FileChange]
    runtime_removals: List[PreparedRuntimeRemoval]


def _require_runtime_state(
    paths: KiroIdeRuntimePaths, operation: str
) -> None:
    require_runtime_directory_state(
        paths.runtime_parent,
        paths.runtime_root,
        paths.agent_directory,
        paths.directories,
        operation,
    )


def _agent_paths(config: InstallConfig) -> KiroIdeRuntimePaths:
    paths = resolve_runtime_paths(config)
    root = os.path.dirname(paths.agent_directory)
    runtime_parent = os.path.dirname(root)
    return KiroIdeRuntimePaths(
        paths.agent_id,
        runtime_parent,
        root,
        paths.agent_directory,
        paths.guard_path,
        paths.audit_path,
        inspect_runtime_directories(runtime_parent, root, paths.agent_directory),
    )


def preflight_kiroide_installation(
    config: InstallConfig, sources: KiroIdeSources
) -> KiroIdeRuntimePaths:
    if not sources.document.file_path:
        raise ValueError("Kiro IDE installation requires a workspace hook path")
    validate_install_config(config, AGENT_KEY, PRODUCT)
    paths = _agent_paths(config)
    owns_workspace_runtime = any(
        same_agent_id(contract.agent_id, paths.agent_id)
        for contract in kiroide_runtime_contracts(sources.document.hooks)
    )
    owns_global_legacy_runtime = legacy_kiroide_contract_matches_agent(
        sources.legacy, paths.agent_id
    )
    validate_runtime_tree(
        paths.agent_directory,
        paths.agent_id,
        sources.paths.workspace_root,
        allow_missing_workspace_root=owns_workspace_runtime,
        allow_legacy_ownerless_config=owns_global_legacy_runtime,
    )
    _require_runtime_state(paths, "Kiro IDE installation preflight")
    return paths


def _runtime_change(
    file_path: str,
    label: str,
    next_source: str,
    mode: int,
    maximum_bytes: int = MAX_SOURCE_BYTES,
    enforce_mode: bool = False,
) -> Tuple[Optional[FileChange], Optional[FilePrecondition]]:
    snapshot = read_physical_file(file_path, label, maximum_bytes)
    change = source_change(
        file_path,
        label,
        None if snapshot is None else snapshot.contents,
        next_source,
        mode,
        maximum_bytes,
        expected_snapshot=snapshot,
        enforce_mode=enforce_mode,
    )
    precondition = (
        None
        if change is not None
        else FilePrecondition(file_path, label, snapshot, maximum_bytes)
    )
    return change, precondition


def _rendered_change(
    rendered: RenderedKiroIdeDocument,
) -> Optional[FileChange]:
    if not rendered.changed:
        return None
    return source_change(
        rendered.document.file_path,
        "Kiro IDE hooks",
        rendered.document.raw if rendered.document.exists else None,
        rendered.next_source,
        0o600,
        MAX_SOURCE_BYTES,
        expected_snapshot=rendered.document.snapshot,
    )


def _removes_legacy(
    legacy: LegacyKiroIdeDocument, agent_id: str = ""
) -> bool:
    return legacy.contract is not None and (
        not agent_id
        or same_agent_id(legacy.contract.agent_id, agent_id)
    )


def _legacy_change(
    legacy: LegacyKiroIdeDocument, agent_id: str = ""
) -> Optional[FileChange]:
    if not _removes_legacy(legacy, agent_id):
        return None
    if legacy.raw is None:
        raise OSError(f"Legacy Kiro IDE hook source is missing: {legacy.file_path}")
    require_physical_legacy_directory(legacy)
    return source_change(
        legacy.file_path,
        "legacy Kiro IDE hook",
        legacy.raw,
        None,
        0o600,
        MAX_SOURCE_BYTES,
        expected_snapshot=legacy.snapshot,
    )


def prepare_kiroide_installation(
    config: InstallConfig,
    paths: KiroIdeRuntimePaths,
    sources: KiroIdeSources,
    rendered: RenderedKiroIdeDocument,
) -> PreparedKiroIdeInstallation:
    operation = "Kiro IDE installation preparation"
    _require_runtime_state(paths, operation)
    guard_script = generate_guard_script(AGENT_KEY, paths.agent_id)
    audit_script = generate_hook_script(
        org_id=config.get("org_id", ""),
        agent_id=paths.agent_id,
        kid=config.get("kid", ""),
        base_url=config.get("base_url", DEFAULT_BASE_URL),
        native_payload=True,
        agent_name=AGENT_KEY,
    )
    runtime = [
        _runtime_change(
            paths.guard_path, "Elydora guard runtime", guard_script, 0o700
        ),
        _runtime_change(
            os.path.join(paths.agent_directory, "config.json"),
            "Elydora runtime config",
            runtime_config_source(
                config,
                paths.agent_id,
                AGENT_KEY,
                workspace_root=sources.paths.workspace_root,
            ),
            0o600,
            MAX_CONFIG_BYTES,
            enforce_mode=os.name != "nt",
        ),
        _runtime_change(
            os.path.join(paths.agent_directory, "private.key"),
            "Elydora private key",
            config.get("private_key", ""),
            0o600,
            MAX_SECRET_BYTES,
            enforce_mode=os.name != "nt",
        ),
        _runtime_change(
            paths.audit_path, "Elydora audit runtime", audit_script, 0o700
        ),
    ]
    changes = present(
        [
            *(change for change, _condition in runtime),
            _rendered_change(rendered),
            _legacy_change(sources.legacy, paths.agent_id),
        ]
    )
    _require_runtime_state(paths, operation)
    return PreparedKiroIdeInstallation(
        changes,
        [
            condition
            for _change, condition in runtime
            if condition is not None
        ],
    )


def _provider_preconditions(
    sources: KiroIdeSources,
    changes: List[FileChange],
) -> List[FilePrecondition]:
    changed = {
        os.path.normcase(os.path.abspath(change.file_path)) for change in changes
    }
    values = (
        (
            sources.document.file_path,
            "Kiro IDE hooks",
            sources.document.snapshot,
        ),
        (
            sources.legacy.file_path,
            "legacy Kiro IDE hook",
            sources.legacy.snapshot,
        ),
    )
    return [
        FilePrecondition(file_path, label, snapshot, MAX_SOURCE_BYTES)
        for file_path, label, snapshot in values
        if os.path.normcase(os.path.abspath(file_path)) not in changed
    ]


def _commit_kiroide_changes(
    changes: List[FileChange],
    sources: KiroIdeSources,
    operation: str,
    runtime_paths: Optional[KiroIdeRuntimePaths] = None,
    runtime_preconditions: Sequence[FilePrecondition] = (),
    directory_preconditions: Sequence[DirectoryPrecondition] = (),
    opaque_removals: Sequence[OpaqueRemovalChange] = (),
    create_workspace_directories: Optional[bool] = None,
) -> None:
    directories = []
    try:
        directories.extend(
            pin_workspace_directories(
                sources,
                operation,
                bool(changes)
                if create_workspace_directories is None
                else create_workspace_directories,
            )
        )
        if runtime_paths is not None:
            directories.extend(
                pin_runtime_directories(
                    runtime_paths.runtime_parent,
                    runtime_paths.runtime_root,
                    runtime_paths.agent_directory,
                    runtime_paths.directories,
                    operation,
                    bool(changes),
                )
            )
    except Exception as error:
        failures = cleanup_created_directories(directories)
        suffix = f"; recovery failed: {'; '.join(failures)}" if failures else ""
        raise OSError(f"{operation}: {error}{suffix}") from error
    write_changes(
        changes,
        operation,
        [
            *_provider_preconditions(sources, changes),
            *runtime_preconditions,
        ],
        [*directories, *directory_preconditions],
        opaque_removals,
    )


def commit_kiroide_installation(
    prepared: PreparedKiroIdeInstallation,
    sources: KiroIdeSources,
    paths: KiroIdeRuntimePaths,
) -> None:
    _commit_kiroide_changes(
        prepared.changes,
        sources,
        "Install Kiro IDE hooks",
        paths,
        prepared.runtime_preconditions,
    )


def prepare_kiroide_uninstall(
    sources: KiroIdeSources,
    rendered: RenderedKiroIdeDocument,
    agent_id: str = "",
    runtime_agent_ids: Sequence[str] = (),
) -> PreparedKiroIdeUninstall:
    runtime_removals = []
    selected_agent_ids: List[str] = []
    candidates = runtime_agent_ids or ((agent_id,) if agent_id else ())
    for runtime_agent_id in candidates:
        if any(
            same_agent_id(runtime_agent_id, selected_agent_id)
            for selected_agent_id in selected_agent_ids
        ):
            continue
        selected_agent_ids.append(runtime_agent_id)
        allow_legacy_ownerless_config = legacy_kiroide_contract_matches_agent(
            sources.legacy, runtime_agent_id
        )

        def validate_config(config: JsonObject, config_path: str) -> None:
            validate_kiroide_runtime_config(
                config,
                runtime_agent_id,
                config_path,
                sources.paths.workspace_root,
                allow_missing_workspace_root=any(
                    same_agent_id(
                        contract.agent_id, runtime_agent_id
                    )
                    for contract in kiroide_runtime_contracts(
                        sources.document.hooks
                    )
                ),
                allow_legacy_ownerless_config=allow_legacy_ownerless_config,
            )

        runtime_removal = prepare_runtime_removal(
            runtime_agent_id,
            AGENT_KEY,
            config_validator=validate_config,
            managed_files=KIRO_IDE_RUNTIME_FILES,
        )
        if runtime_removal is not None:
            runtime_removals.append(runtime_removal)
    provider_changes = present(
        [_rendered_change(rendered), _legacy_change(sources.legacy, agent_id)]
    )
    return PreparedKiroIdeUninstall(
        [
            *provider_changes,
            *(
                change
                for runtime_removal in runtime_removals
                for change in runtime_removal.changes
            ),
        ],
        runtime_removals,
    )


def commit_kiroide_uninstall(
    prepared: PreparedKiroIdeUninstall, sources: KiroIdeSources
) -> None:
    _commit_kiroide_changes(
        prepared.changes,
        sources,
        "Uninstall Kiro IDE hooks",
        runtime_preconditions=tuple(
            condition
            for removal in prepared.runtime_removals
            for condition in removal.file_preconditions
        ),
        directory_preconditions=tuple(
            condition
            for removal in prepared.runtime_removals
            for condition in removal.directory_preconditions
        ),
        opaque_removals=tuple(
            change
            for removal in prepared.runtime_removals
            for change in removal.opaque_removals
        ),
        create_workspace_directories=False,
    )
    for removal in prepared.runtime_removals:
        finalize_runtime_removal(removal)
