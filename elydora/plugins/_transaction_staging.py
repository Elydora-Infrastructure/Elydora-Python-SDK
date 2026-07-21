"""Anchored staging and precondition checks for file transactions."""

from __future__ import annotations

import os
import stat
from typing import Dict, List, Optional, Sequence, Tuple
from uuid import uuid4

from ._directory_removal import remove_pinned_empty_directory
from ._managed_files import (
    DirectorySnapshot,
    FileSnapshot,
    ensure_physical_directory,
    read_physical_directory,
    read_physical_file,
)
from ._pinned_directory import PinnedDirectory
from ._private_artifact import QuarantinedFile, reserve_private_path
from ._transaction_payload import populate_reserved_text
from ._transaction_types import (
    DirectoryMap,
    DirectoryPrecondition,
    FileChange,
    FilePrecondition,
    StagedChange,
)


def directory_key(directory_path: str) -> str:
    return os.path.normcase(os.path.abspath(directory_path))


def directory_for(file_path: str, directories: DirectoryMap) -> PinnedDirectory:
    directory = directories.get(directory_key(os.path.dirname(file_path)))
    if directory is None:
        raise OSError(f"File directory is not pinned: {file_path}")
    return directory


def same_snapshot(
    current: Optional[FileSnapshot], expected: Optional[FileSnapshot]
) -> bool:
    if current is None or expected is None:
        return current is expected
    return current == expected


def remove_optional(directory: PinnedDirectory, file_path: Optional[str]) -> None:
    if not file_path:
        return
    try:
        directory.remove_file(directory.name_for(file_path))
    except FileNotFoundError:
        return


def cleanup_paths(
    directory: PinnedDirectory, paths: Sequence[Optional[str]]
) -> List[str]:
    errors = []
    for path in paths:
        try:
            remove_optional(directory, path)
        except OSError as error:
            errors.append(str(error))
    return errors


def write_staged(staged: StagedChange) -> None:
    """Populate a reservation only after its identity is journaled."""
    temporary_path = staged.temporary_path
    reservation = staged.temporary_reservation
    next_source = staged.change.next_source
    if temporary_path is None or reservation is None or next_source is None:
        raise OSError(f"Missing staged reservation for {staged.change.label}")
    assert_transaction_preconditions(*staged.preconditions, staged.directories)
    assert_unchanged(staged.change, staged.directories)
    staged.temporary_snapshot = populate_reserved_text(
        staged.directory,
        temporary_path,
        reservation,
        next_source,
        staged.change.mode,
        f"staged {staged.change.label}",
    )
    assert_transaction_preconditions(*staged.preconditions, staged.directories)


def assert_unchanged(
    change: FileChange, directories: DirectoryMap
) -> Optional[FileSnapshot]:
    directory = directory_for(change.file_path, directories)
    snapshot = directory.read_file(
        directory.name_for(change.file_path),
        change.label,
        change.maximum_bytes,
    )
    current = None if snapshot is None else snapshot.contents
    identity_changed = snapshot is not None and (
        snapshot.device != change.original_device
        or snapshot.inode != change.original_inode
        or snapshot.mode != change.original_mode
    )
    if current != change.original or identity_changed:
        raise OSError(f"{change.label} changed during installation: {change.file_path}")
    return snapshot


def _assert_file_preconditions(
    preconditions: Sequence[FilePrecondition],
    operation: str,
    directories: Optional[DirectoryMap],
) -> None:
    for condition in preconditions:
        directory = (
            None
            if directories is None
            else directories.get(directory_key(os.path.dirname(condition.file_path)))
        )
        current = (
            read_physical_file(
                condition.file_path,
                condition.label,
                condition.maximum_bytes,
            )
            if directory is None
            else directory.read_file(
                directory.name_for(condition.file_path),
                condition.label,
                condition.maximum_bytes,
            )
        )
        if not same_snapshot(current, condition.original):
            raise OSError(
                f"{condition.label} changed during {operation}: "
                f"{condition.file_path}"
            )


def _assert_directory_preconditions(
    preconditions: Sequence[DirectoryPrecondition], operation: str
) -> None:
    for condition in preconditions:
        current = read_physical_directory(condition.directory_path, condition.label)
        if current != condition.original:
            raise OSError(
                f"{condition.label} changed during {operation}: "
                f"{condition.directory_path}"
            )


def assert_transaction_preconditions(
    file_preconditions: Sequence[FilePrecondition],
    directory_preconditions: Sequence[DirectoryPrecondition],
    operation: str,
    directories: Optional[DirectoryMap] = None,
) -> None:
    _assert_file_preconditions(file_preconditions, operation, directories)
    _assert_directory_preconditions(directory_preconditions, operation)
    if directories is not None:
        for directory in directories.values():
            directory.assert_path_stable()


def pin_directories(
    changes: Sequence[FileChange],
    file_preconditions: Sequence[FilePrecondition],
    directory_preconditions: Sequence[DirectoryPrecondition],
    extra_file_targets: Sequence[Tuple[str, str, bool]] = (),
) -> DirectoryMap:
    specifications: Dict[str, Tuple[str, str, Optional[DirectorySnapshot]]] = {}
    for condition in directory_preconditions:
        if condition.original is not None:
            specifications[directory_key(condition.directory_path)] = (
                condition.directory_path,
                condition.label,
                condition.original,
            )

    file_directories = [
        (os.path.dirname(change.file_path), f"{change.label} directory", True)
        for change in changes
    ]
    file_directories.extend(
        (
            os.path.dirname(condition.file_path),
            f"{condition.label} directory",
            False,
        )
        for condition in file_preconditions
    )
    file_directories.extend(extra_file_targets)
    for directory_path, label, required in file_directories:
        key = directory_key(directory_path)
        if key in specifications:
            continue
        if required:
            ensure_physical_directory(directory_path, label)
        snapshot = read_physical_directory(directory_path, label)
        if snapshot is not None:
            specifications[key] = (directory_path, label, snapshot)

    ordered = sorted(
        specifications.items(),
        key=lambda item: (os.path.abspath(item[1][0]).count(os.sep), item[0]),
    )
    pinned: DirectoryMap = {}
    try:
        for key, (directory_path, label, expected) in ordered:
            pinned[key] = PinnedDirectory.open(directory_path, label, expected)
        return pinned
    except Exception:
        close_directories(pinned)
        raise


def close_directories(directories: DirectoryMap) -> List[str]:
    errors = []
    for directory in reversed(list(directories.values())):
        try:
            directory.close()
        except OSError as error:
            errors.append(str(error))
    return errors


def reserve_change(
    change: FileChange,
    file_preconditions: Sequence[FilePrecondition],
    directory_preconditions: Sequence[DirectoryPrecondition],
    operation: str,
    directories: DirectoryMap,
) -> StagedChange:
    assert_transaction_preconditions(
        file_preconditions, directory_preconditions, operation, directories
    )
    assert_unchanged(change, directories)
    directory = directory_for(change.file_path, directories)
    assert_transaction_preconditions(
        file_preconditions, directory_preconditions, operation, directories
    )
    basename = os.path.basename(change.file_path)
    temporary_path = None
    temporary_reservation = None
    rollback_path = None
    rollback_snapshot = None
    rollback_reservation = None
    try:
        if change.next_source is not None:
            temporary_name = f".{basename}.{uuid4().hex}.tmp"
            temporary_path = directory.path_for(temporary_name)
            temporary_reservation = reserve_private_path(
                directory,
                temporary_path,
                f"staged {change.label}",
            )
        if change.original is not None:
            rollback_name = f".{basename}.{uuid4().hex}.rollback"
            rollback_path = directory.path_for(rollback_name)
            rollback_reservation = reserve_private_path(
                directory,
                rollback_path,
                f"{change.label} rollback",
            )
        return StagedChange(
            change=change,
            directory=directory,
            temporary_path=temporary_path,
            temporary_snapshot=None,
            temporary_reservation=temporary_reservation,
            rollback_path=rollback_path,
            rollback_snapshot=rollback_snapshot,
            rollback_reservation=rollback_reservation,
            preconditions=(file_preconditions, directory_preconditions, operation),
            directories=directories,
        )
    except Exception as error:
        failures = cleanup_paths(directory, (temporary_path, rollback_path))
        suffix_message = (
            f"; cleanup failed: {'; '.join(failures)}" if failures else ""
        )
        raise OSError(f"Stage {change.label}: {error}{suffix_message}") from error


def stage_change(staged: StagedChange) -> None:
    if staged.change.next_source is None:
        return
    write_staged(staged)


def cleanup_staged(staged: StagedChange) -> None:
    _remove_exact_text(
        staged.directory,
        staged.temporary_path,
        f"staged {staged.change.label}",
        (
            staged.temporary_snapshot
            if staged.temporary_snapshot is not None
            else staged.temporary_reservation
        ),
    )
    expected_rollback = (
        staged.rollback_snapshot
        if staged.rollback_snapshot is not None
        else staged.rollback_reservation
    )
    _remove_exact_text(
        staged.directory,
        staged.rollback_path,
        f"{staged.change.label} rollback",
        expected_rollback,
    )


def _remove_exact_text(
    directory: PinnedDirectory,
    file_path: Optional[str],
    label: str,
    expected: Optional[FileSnapshot],
) -> None:
    if file_path is None or expected is None:
        return
    try:
        captured = QuarantinedFile.capture(
            directory,
            file_path,
            label,
            require_parent_path=False,
        )
    except FileNotFoundError:
        return
    metadata = captured.container.stat_file("entry")
    changed = (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or (metadata.st_dev, metadata.st_ino)
        != (expected.device, expected.inode)
    )
    if not changed:
        # An in-place rewrite keeps the inode, so the removal is only exact
        # once the bytes also match the owned snapshot.
        try:
            snapshot = captured.text_snapshot(
                len(expected.contents.encode("utf-8"))
            )
        except ValueError:
            snapshot = None
        changed = snapshot is None or snapshot.contents != expected.contents
    if changed:
        try:
            captured.restore()
        except Exception as error:
            preserved = captured.preserve() if captured.active else file_path
            raise OSError(
                f"{label} changed before cleanup; transaction data "
                f"preserved at {preserved}: {error}"
            ) from error
        raise OSError(f"{label} changed before cleanup: {file_path}")
    captured.discard()


def cleanup_created_directories(
    preconditions: Sequence[DirectoryPrecondition],
    directories: Optional[DirectoryMap] = None,
) -> List[str]:
    errors = []
    created = sorted(
        (condition for condition in preconditions if condition.created),
        key=lambda condition: os.path.abspath(condition.directory_path).count(os.sep),
        reverse=True,
    )
    for condition in created:
        child = None
        parent = None
        close_child = False
        close_parent = False
        try:
            current = read_physical_directory(condition.directory_path, condition.label)
            if current is None:
                continue
            if current != condition.original:
                raise OSError(
                    f"{condition.label} changed before recovery: "
                    f"{condition.directory_path}"
                )
            child_key = directory_key(condition.directory_path)
            child = None if directories is None else directories.get(child_key)
            if child is not None and os.name == "nt":
                child.close()
                child = PinnedDirectory.open(
                    condition.directory_path,
                    condition.label,
                    condition.original,
                    delete_access=True,
                )
                close_child = True
            if child is None:
                child = PinnedDirectory.open(
                    condition.directory_path,
                    condition.label,
                    condition.original,
                    delete_access=True,
                )
                close_child = True

            parent_path = os.path.dirname(os.path.abspath(condition.directory_path))
            parent_key = directory_key(parent_path)
            parent = None if directories is None else directories.get(parent_key)
            if parent is None:
                parent_snapshot = read_physical_directory(
                    parent_path, f"{condition.label} parent"
                )
                if parent_snapshot is None:
                    raise OSError(
                        f"{condition.label} parent is missing: {parent_path}"
                    )
                parent = PinnedDirectory.open(
                    parent_path,
                    f"{condition.label} parent",
                    parent_snapshot,
                )
                close_parent = True
            if os.name != "nt" and directories is not None:
                child_prefix = directory_key(condition.directory_path) + os.sep
                for key, descendant in directories.items():
                    if key.startswith(child_prefix):
                        descendant.close()
            preserved = remove_pinned_empty_directory(
                parent,
                child,
                require_empty=True,
            )
            if preserved is not None:
                errors.append(
                    f"Preserved created {condition.label} at {preserved} "
                    "for identity-safe POSIX cleanup"
                )
        except OSError as error:
            errors.append(f"Remove created {condition.label}: {error}")
        finally:
            for directory, should_close in (
                (child, close_child),
                (parent, close_parent),
            ):
                if directory is not None and should_close:
                    try:
                        directory.close()
                    except OSError as error:
                        errors.append(
                            f"Close created {condition.label}: {error}"
                        )
    return errors
