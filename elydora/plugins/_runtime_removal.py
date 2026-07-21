"""Identity-bound removal of one Elydora agent runtime directory."""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Callable, Dict, List, Optional, Tuple

from elydora._runtime_paths import resolve_agent_directory, runtime_root

from ._managed_files import (
    DirectorySnapshot,
    FileSnapshot,
    MAX_CONFIG_BYTES,
    MAX_SECRET_BYTES,
    MAX_SOURCE_BYTES,
    read_physical_directory,
)
from ._directory_removal import remove_pinned_empty_directory
from ._opaque_removal import OpaqueRemovalChange, prepare_opaque_removal
from ._pinned_directory import PinnedDirectory
from ._strict_json import JsonObject, parse_json_object
from ._transaction import write_changes
from ._transaction_types import (
    DirectoryPrecondition,
    FileChange,
    FilePrecondition,
)


RuntimeConfigValidator = Callable[[JsonObject, str], None]
RuntimeFileContract = Dict[str, Tuple[str, int]]

STANDARD_RUNTIME_FILES: RuntimeFileContract = {
    "chain-state.json": ("Elydora chain state", MAX_SOURCE_BYTES),
    "status-cache.json": ("Elydora status cache", MAX_SOURCE_BYTES),
    "error.log": ("Elydora error log", MAX_SOURCE_BYTES),
    "guard.py": ("Elydora guard runtime", MAX_SOURCE_BYTES),
    "hook.py": ("Elydora audit runtime", MAX_SOURCE_BYTES),
    "private.key": ("Elydora private key", MAX_SECRET_BYTES),
    "config.json": ("Elydora runtime config", MAX_CONFIG_BYTES),
}

KIRO_IDE_RUNTIME_FILES: RuntimeFileContract = dict(STANDARD_RUNTIME_FILES)
_OPAQUE_RUNTIME_FILE = "error.log"


def _managed_runtime_files(agent_name: str) -> RuntimeFileContract:
    files = dict(STANDARD_RUNTIME_FILES)
    if agent_name == "augment":
        extension = ".cmd" if os.name == "nt" else ".sh"
        files.update(
            {
                f"augment-guard{extension}": (
                    "Elydora Augment guard wrapper",
                    MAX_SOURCE_BYTES,
                ),
                f"augment-hook{extension}": (
                    "Elydora Augment audit wrapper",
                    MAX_SOURCE_BYTES,
                ),
            }
        )
    return files


@dataclass(frozen=True)
class PreparedRuntimeRemoval:
    agent_id: str
    agent_name: str
    runtime_root: str
    agent_directory: str
    root_snapshot: DirectorySnapshot
    agent_snapshot: DirectorySnapshot
    changes: List[FileChange]
    opaque_removals: List[OpaqueRemovalChange]
    file_preconditions: List[FilePrecondition]
    directory_preconditions: List[DirectoryPrecondition]


def _close_pinned(*directories: Optional[PinnedDirectory]) -> None:
    failures = []
    for directory in reversed(directories):
        if directory is None:
            continue
        try:
            directory.close()
        except OSError as error:
            failures.append(str(error))
    if failures:
        raise OSError("; ".join(failures))


def _validate_identity(
    config: JsonObject,
    config_path: str,
    agent_id: str,
    agent_name: str,
) -> None:
    if config.get("agent_id") != agent_id or config.get("agent_name") != agent_name:
        raise ValueError(
            f"Elydora runtime identity does not match {agent_name}: {config_path}"
        )


def _removal_change(
    file_path: str,
    label: str,
    snapshot: FileSnapshot,
    maximum_bytes: int,
) -> FileChange:
    return FileChange(
        file_path,
        label,
        snapshot.contents,
        None,
        snapshot.mode,
        snapshot.mode,
        snapshot.device,
        snapshot.inode,
        maximum_bytes,
    )


def prepare_runtime_removal(
    agent_id: str,
    agent_name: str,
    *,
    config_validator: Optional[RuntimeConfigValidator] = None,
    managed_files: Optional[RuntimeFileContract] = None,
) -> Optional[PreparedRuntimeRemoval]:
    """Inspect an exact managed runtime without mutating it."""
    root_path = runtime_root()
    agent_path = resolve_agent_directory(root_path, agent_id)
    runtime_files = (
        _managed_runtime_files(agent_name)
        if managed_files is None
        else managed_files
    )
    root_snapshot = read_physical_directory(root_path, "Elydora runtime directory")
    if root_snapshot is None:
        return None
    agent_snapshot = read_physical_directory(
        agent_path, "Elydora agent runtime directory"
    )
    if agent_snapshot is None:
        return None

    root = None
    agent = None
    try:
        root = PinnedDirectory.open(
            root_path, "Elydora runtime directory", root_snapshot
        )
        agent = PinnedDirectory.open(
            agent_path, "Elydora agent runtime directory", agent_snapshot
        )
        names = agent.list_names()
        unknown = [name for name in names if name not in runtime_files]
        if unknown:
            raise OSError(
                "Elydora agent runtime contains unmanaged entries: "
                f"{agent_path}: {', '.join(unknown)}"
            )

        opaque_path = os.path.join(agent_path, _OPAQUE_RUNTIME_FILE)
        opaque_removals = [
            prepare_opaque_removal(
                agent,
                opaque_path,
                runtime_files[_OPAQUE_RUNTIME_FILE][0],
            )
        ]
        snapshots: Dict[str, Optional[FileSnapshot]] = {}
        for name, (label, maximum_bytes) in runtime_files.items():
            if name == _OPAQUE_RUNTIME_FILE:
                continue
            snapshots[name] = agent.read_file(name, label, maximum_bytes)

        config_path = os.path.join(agent_path, "config.json")
        config_snapshot = snapshots.get("config.json")
        present = [name for name, snapshot in snapshots.items() if snapshot is not None]
        if opaque_removals[0].original is not None:
            present.append(_OPAQUE_RUNTIME_FILE)
        if config_snapshot is None:
            if present:
                raise ValueError(
                    "Elydora runtime identity cannot be verified without "
                    f"config.json: {agent_path}"
                )
        else:
            config = parse_json_object(
                config_snapshot.contents,
                f"Elydora runtime config at {config_path}",
            )
            _validate_identity(config, config_path, agent_id, agent_name)
            if config_validator is not None:
                config_validator(config, config_path)

        changes = []
        preconditions = []
        for name, (label, maximum_bytes) in runtime_files.items():
            if name == _OPAQUE_RUNTIME_FILE:
                continue
            file_path = os.path.join(agent_path, name)
            snapshot = snapshots[name]
            if snapshot is None:
                preconditions.append(
                    FilePrecondition(file_path, label, None, maximum_bytes)
                )
            else:
                changes.append(
                    _removal_change(file_path, label, snapshot, maximum_bytes)
                )

        root.assert_path_stable("runtime removal preparation")
        agent.assert_path_stable("runtime removal preparation")
        return PreparedRuntimeRemoval(
            agent_id,
            agent_name,
            root_path,
            agent_path,
            root_snapshot,
            agent_snapshot,
            changes,
            opaque_removals,
            preconditions,
            [
                DirectoryPrecondition(
                    root_path, "Elydora runtime directory", root_snapshot
                ),
                DirectoryPrecondition(
                    agent_path,
                    "Elydora agent runtime directory",
                    agent_snapshot,
                ),
            ],
        )
    finally:
        _close_pinned(root, agent)


def finalize_runtime_removal(plan: PreparedRuntimeRemoval) -> Optional[str]:
    """Remove the exact empty agent directory retained by a completed transaction."""
    root = None
    agent = None
    try:
        root = PinnedDirectory.open(
            plan.runtime_root,
            "Elydora runtime directory",
            plan.root_snapshot,
        )
        agent = PinnedDirectory.open(
            plan.agent_directory,
            "Elydora agent runtime directory",
            plan.agent_snapshot,
            delete_access=True,
        )
        preserved = remove_pinned_empty_directory(root, agent)
    finally:
        _close_pinned(root, agent)
    return preserved


def commit_runtime_removal(plan: PreparedRuntimeRemoval) -> None:
    """Delete all proven managed files, then the exact empty agent directory."""
    write_changes(
        plan.changes,
        f"Remove {plan.agent_name} runtime",
        plan.file_preconditions,
        plan.directory_preconditions,
        plan.opaque_removals,
    )
    finalize_runtime_removal(plan)
