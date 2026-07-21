"""Physical directory identity contracts for Kiro IDE installation."""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import List, NoReturn, Optional

from ._managed_files import DirectorySnapshot, read_physical_directory
from ._transaction import DirectoryPrecondition, cleanup_created_directories
from .kiroide_io import KiroIdeSources, require_kiroide_directory_state


@dataclass(frozen=True)
class KiroIdeRuntimeDirectoryState:
    parent: DirectorySnapshot
    root: Optional[DirectorySnapshot]
    agent: Optional[DirectorySnapshot]


def inspect_runtime_directories(
    runtime_parent: str,
    runtime_root: str,
    agent_directory: str,
) -> KiroIdeRuntimeDirectoryState:
    parent = read_physical_directory(runtime_parent, "Elydora runtime parent")
    if parent is None:
        raise OSError(f"Elydora runtime parent is missing: {runtime_parent}")
    return KiroIdeRuntimeDirectoryState(
        parent,
        read_physical_directory(runtime_root, "Elydora runtime directory"),
        read_physical_directory(
            agent_directory, "Elydora agent runtime directory"
        ),
    )


def _require_directory_snapshot(
    directory_path: str,
    label: str,
    expected: Optional[DirectorySnapshot],
    operation: str,
) -> None:
    current = read_physical_directory(directory_path, label)
    if current != expected:
        raise OSError(f"{label} changed during {operation}: {directory_path}")


def require_runtime_directory_state(
    runtime_parent: str,
    runtime_root: str,
    agent_directory: str,
    expected: KiroIdeRuntimeDirectoryState,
    operation: str,
) -> None:
    for directory_path, label, snapshot in (
        (runtime_parent, "Elydora runtime parent", expected.parent),
        (runtime_root, "Elydora runtime directory", expected.root),
        (agent_directory, "Elydora agent runtime directory", expected.agent),
    ):
        _require_directory_snapshot(
            directory_path, label, snapshot, operation
        )


def _create_pinned_directory(
    directory_path: str,
    label: str,
) -> DirectorySnapshot:
    try:
        os.mkdir(directory_path, mode=0o700)
    except OSError as error:
        raise OSError(f"Create {label} at {directory_path}: {error}") from error
    snapshot = read_physical_directory(directory_path, label)
    if snapshot is None:
        raise OSError(f"{label} is missing after creation: {directory_path}")
    return snapshot


def _verify_preconditions(
    preconditions: List[DirectoryPrecondition], operation: str
) -> List[DirectoryPrecondition]:
    for condition in preconditions:
        _require_directory_snapshot(
            condition.directory_path,
            condition.label,
            condition.original,
            operation,
        )
    return preconditions


def _raise_after_directory_recovery(
    operation: str,
    error: Exception,
    preconditions: List[DirectoryPrecondition],
) -> NoReturn:
    failures = cleanup_created_directories(preconditions)
    suffix = f"; recovery failed: {'; '.join(failures)}" if failures else ""
    raise OSError(f"{operation}: {error}{suffix}") from error


def pin_workspace_directories(
    sources: KiroIdeSources,
    operation: str,
    create_missing: bool,
) -> List[DirectoryPrecondition]:
    created: List[DirectoryPrecondition] = []
    try:
        require_kiroide_directory_state(
            sources.paths, sources.directories, operation
        )
        workspace = sources.directories.workspace
        _require_directory_snapshot(
            sources.paths.workspace_root,
            "Kiro IDE workspace",
            workspace,
            operation,
        )
        kiro = sources.directories.kiro
        kiro_created = kiro is None and create_missing
        if kiro_created:
            kiro = _create_pinned_directory(
                sources.paths.kiro_directory,
                "Kiro IDE configuration directory",
            )
            created.append(
                DirectoryPrecondition(
                    sources.paths.kiro_directory,
                    "Kiro IDE configuration directory",
                    kiro,
                    created=True,
                )
            )
        _require_directory_snapshot(
            sources.paths.workspace_root,
            "Kiro IDE workspace",
            workspace,
            operation,
        )
        _require_directory_snapshot(
            sources.paths.kiro_directory,
            "Kiro IDE configuration directory",
            kiro,
            operation,
        )
        hooks = sources.directories.hooks
        hooks_created = hooks is None and create_missing
        if hooks_created:
            hooks = _create_pinned_directory(
                sources.paths.hooks_directory,
                "Kiro IDE hooks directory",
            )
            created.append(
                DirectoryPrecondition(
                    sources.paths.hooks_directory,
                    "Kiro IDE hooks directory",
                    hooks,
                    created=True,
                )
            )
        return _verify_preconditions(
            [
                DirectoryPrecondition(
                    sources.paths.workspace_root, "Kiro IDE workspace", workspace
                ),
                DirectoryPrecondition(
                    sources.paths.kiro_directory,
                    "Kiro IDE configuration directory",
                    kiro,
                    created=kiro_created,
                ),
                DirectoryPrecondition(
                    sources.paths.hooks_directory,
                    "Kiro IDE hooks directory",
                    hooks,
                    created=hooks_created,
                ),
            ],
            operation,
        )
    except Exception as error:
        _raise_after_directory_recovery(operation, error, created)


def pin_runtime_directories(
    runtime_parent: str,
    runtime_root: str,
    agent_directory: str,
    expected: KiroIdeRuntimeDirectoryState,
    operation: str,
    create_missing: bool,
) -> List[DirectoryPrecondition]:
    created: List[DirectoryPrecondition] = []
    try:
        require_runtime_directory_state(
            runtime_parent,
            runtime_root,
            agent_directory,
            expected,
            operation,
        )
        root = expected.root
        root_created = root is None and create_missing
        if root_created:
            _require_directory_snapshot(
                runtime_parent,
                "Elydora runtime parent",
                expected.parent,
                operation,
            )
            root = _create_pinned_directory(
                runtime_root, "Elydora runtime directory"
            )
            created.append(
                DirectoryPrecondition(
                    runtime_root,
                    "Elydora runtime directory",
                    root,
                    created=True,
                )
            )
        _require_directory_snapshot(
            runtime_parent,
            "Elydora runtime parent",
            expected.parent,
            operation,
        )
        _require_directory_snapshot(
            runtime_root, "Elydora runtime directory", root, operation
        )
        agent = expected.agent
        agent_created = agent is None and create_missing
        if agent_created:
            if root is None:
                raise OSError(
                    f"Elydora runtime directory is missing: {runtime_root}"
                )
            agent = _create_pinned_directory(
                agent_directory, "Elydora agent runtime directory"
            )
            created.append(
                DirectoryPrecondition(
                    agent_directory,
                    "Elydora agent runtime directory",
                    agent,
                    created=True,
                )
            )
        return _verify_preconditions(
            [
                DirectoryPrecondition(
                    runtime_parent, "Elydora runtime parent", expected.parent
                ),
                DirectoryPrecondition(
                    runtime_root,
                    "Elydora runtime directory",
                    root,
                    created=root_created,
                ),
                DirectoryPrecondition(
                    agent_directory,
                    "Elydora agent runtime directory",
                    agent,
                    created=agent_created,
                ),
            ],
            operation,
        )
    except Exception as error:
        _raise_after_directory_recovery(operation, error, created)
