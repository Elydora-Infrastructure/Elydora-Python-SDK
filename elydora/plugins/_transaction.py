"""Fail-fast transactional file changes shared by hook adapters."""

from __future__ import annotations

from dataclasses import dataclass
import os
import tempfile
from typing import List, Optional, Sequence, cast
from uuid import uuid4

from ._managed_files import (
    FileSnapshot,
    MAX_SOURCE_BYTES,
    ensure_physical_directory,
    physical_file_exists,
    read_physical_file,
)


@dataclass(frozen=True)
class FileChange:
    file_path: str
    label: str
    original: Optional[str]
    next_source: Optional[str]
    mode: int
    original_mode: Optional[int]
    original_device: Optional[int]
    original_inode: Optional[int]
    maximum_bytes: int


@dataclass(frozen=True)
class FilePrecondition:
    file_path: str
    label: str
    original: Optional[FileSnapshot]
    maximum_bytes: int = MAX_SOURCE_BYTES


@dataclass
class _StagedChange:
    change: FileChange
    temporary_path: Optional[str]
    rollback_path: Optional[str]
    committed_snapshot: Optional[FileSnapshot] = None
    committed: bool = False


_EXPECTED_SNAPSHOT_UNSET = object()


def _same_snapshot(
    current: Optional[FileSnapshot],
    expected: Optional[FileSnapshot],
) -> bool:
    if current is None or expected is None:
        return current is expected
    return (
        current.contents == expected.contents
        and current.device == expected.device
        and current.inode == expected.inode
    )


def read_optional(
    file_path: str,
    label: str,
    maximum_bytes: int = MAX_SOURCE_BYTES,
) -> Optional[str]:
    snapshot = read_physical_file(file_path, label, maximum_bytes)
    return None if snapshot is None else snapshot.contents


def source_change(
    file_path: str,
    label: str,
    original: Optional[str],
    next_source: Optional[str],
    mode: int,
    maximum_bytes: int = MAX_SOURCE_BYTES,
    expected_snapshot: object = _EXPECTED_SNAPSHOT_UNSET,
) -> Optional[FileChange]:
    if original == next_source:
        return None
    if (
        next_source is not None
        and len(next_source.encode("utf-8")) > maximum_bytes
    ):
        raise ValueError(
            f"{label} exceeds {maximum_bytes} bytes: {file_path}"
        )
    snapshot = read_physical_file(file_path, label, maximum_bytes)
    current = None if snapshot is None else snapshot.contents
    if current != original:
        raise OSError(f"{label} changed before staging: {file_path}")
    if expected_snapshot is not _EXPECTED_SNAPSHOT_UNSET:
        expected = cast(Optional[FileSnapshot], expected_snapshot)
        if not _same_snapshot(snapshot, expected):
            raise OSError(f"{label} changed before staging: {file_path}")
    return FileChange(
        file_path,
        label,
        original,
        next_source,
        mode,
        None if snapshot is None else snapshot.mode,
        None if snapshot is None else snapshot.device,
        None if snapshot is None else snapshot.inode,
        maximum_bytes,
    )


def file_change(
    file_path: str,
    label: str,
    next_source: Optional[str],
    mode: int,
    maximum_bytes: int = MAX_SOURCE_BYTES,
) -> Optional[FileChange]:
    snapshot = read_physical_file(file_path, label, maximum_bytes)
    return source_change(
        file_path,
        label,
        None if snapshot is None else snapshot.contents,
        next_source,
        mode,
        maximum_bytes,
    )


def _remove_optional(file_path: Optional[str]) -> None:
    if not file_path:
        return
    try:
        os.remove(file_path)
    except FileNotFoundError:
        return


def _cleanup_paths(paths: Sequence[Optional[str]]) -> List[str]:
    errors = []
    for path in paths:
        try:
            _remove_optional(path)
        except OSError as error:
            errors.append(str(error))
    return errors


def _write_staged(
    directory: str,
    basename: str,
    suffix: str,
    content: str,
    mode: int,
    label: str,
) -> str:
    descriptor = -1
    temporary_path = ""
    try:
        descriptor, temporary_path = tempfile.mkstemp(
            prefix=f".{basename}.",
            suffix=suffix,
            dir=directory,
            text=True,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as file:
            descriptor = -1
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        os.chmod(temporary_path, mode)
        return temporary_path
    except Exception as error:
        failures = []
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as close_error:
                failures.append(f"close failed: {close_error}")
        failures.extend(_cleanup_paths((temporary_path,)))
        suffix = f"; cleanup failed: {'; '.join(failures)}" if failures else ""
        raise OSError(f"Stage {label}: {error}{suffix}") from error


def _assert_unchanged(change: FileChange) -> None:
    snapshot = read_physical_file(
        change.file_path,
        change.label,
        change.maximum_bytes,
    )
    current = None if snapshot is None else snapshot.contents
    identity_changed = snapshot is not None and (
        snapshot.device != change.original_device
        or snapshot.inode != change.original_inode
    )
    if current != change.original or identity_changed:
        raise OSError(f"{change.label} changed during installation: {change.file_path}")


def _assert_preconditions(
    preconditions: Sequence[FilePrecondition],
    operation: str,
) -> None:
    for condition in preconditions:
        current = read_physical_file(
            condition.file_path,
            condition.label,
            condition.maximum_bytes,
        )
        if not _same_snapshot(current, condition.original):
            raise OSError(
                f"{condition.label} changed during {operation}: "
                f"{condition.file_path}"
            )


def _stage(change: FileChange) -> _StagedChange:
    _assert_unchanged(change)
    directory = os.path.dirname(change.file_path)
    ensure_physical_directory(directory, f"{change.label} directory")
    basename = os.path.basename(change.file_path)
    temporary_path = None
    rollback_path = None
    try:
        if change.next_source is not None:
            temporary_path = _write_staged(
                directory,
                basename,
                ".tmp",
                change.next_source,
                change.mode,
                change.label,
            )
        if change.original is not None and change.next_source is not None:
            rollback_path = _write_staged(
                directory,
                basename,
                ".rollback",
                change.original,
                change.original_mode or change.mode,
                f"{change.label} rollback",
            )
        elif change.original is not None:
            rollback_path = os.path.join(
                directory,
                f".{basename}.{uuid4().hex}.rollback",
            )
            if os.path.lexists(rollback_path):
                raise FileExistsError(f"Rollback path already exists: {rollback_path}")
        return _StagedChange(change, temporary_path, rollback_path)
    except Exception as error:
        failures = _cleanup_paths((temporary_path, rollback_path))
        suffix = f"; cleanup failed: {'; '.join(failures)}" if failures else ""
        raise OSError(f"Stage {change.label}: {error}{suffix}") from error


def _commit(staged: _StagedChange) -> None:
    _assert_unchanged(staged.change)
    if staged.change.next_source is None:
        if staged.rollback_path is None:
            raise OSError(f"Missing rollback path for {staged.change.label}")
        os.replace(staged.change.file_path, staged.rollback_path)
    else:
        if staged.temporary_path is None:
            raise OSError(f"Missing staged file for {staged.change.label}")
        os.replace(staged.temporary_path, staged.change.file_path)
    staged.committed = True
    current = read_physical_file(
        staged.change.file_path,
        staged.change.label,
        staged.change.maximum_bytes,
    )
    if staged.change.next_source is None:
        if current is not None:
            raise OSError(
                f"{staged.change.label} remained after removal: "
                f"{staged.change.file_path}"
            )
        return
    if current is None or current.contents != staged.change.next_source:
        raise OSError(
            f"{staged.change.label} changed immediately after commit: "
            f"{staged.change.file_path}"
        )
    staged.committed_snapshot = current


def _assert_committed_unchanged(staged: _StagedChange) -> None:
    current = read_physical_file(
        staged.change.file_path,
        staged.change.label,
        staged.change.maximum_bytes,
    )
    if staged.change.next_source is None:
        if current is not None:
            raise OSError(
                f"{staged.change.label} changed during transaction recovery: "
                f"{staged.change.file_path}"
            )
        return
    committed = staged.committed_snapshot
    if current is None or committed is None or (
        current.contents != committed.contents
        or current.device != committed.device
        or current.inode != committed.inode
    ):
        raise OSError(
            f"{staged.change.label} changed during transaction recovery: "
            f"{staged.change.file_path}"
        )


def _preserve_rollback(staged: _StagedChange, error: Exception) -> OSError:
    if staged.rollback_path is None:
        return error if isinstance(error, OSError) else OSError(str(error))
    rollback_path = staged.rollback_path
    staged.rollback_path = None
    return OSError(
        f"{error}; original content preserved at {rollback_path}"
    )


def _rollback(staged: _StagedChange) -> None:
    if not staged.committed:
        return
    try:
        _assert_committed_unchanged(staged)
    except Exception as error:
        raise _preserve_rollback(staged, error) from error
    try:
        if staged.change.next_source is None or staged.change.original is not None:
            if staged.rollback_path is None:
                raise OSError(
                    f"Missing rollback data for {staged.change.label}"
                )
            os.replace(staged.rollback_path, staged.change.file_path)
            staged.rollback_path = None
        else:
            _remove_optional(staged.change.file_path)
    except Exception as error:
        raise _preserve_rollback(staged, error) from error


def _cleanup(staged: _StagedChange) -> None:
    _remove_optional(staged.temporary_path)
    _remove_optional(staged.rollback_path)


def write_changes(
    changes: Sequence[FileChange],
    label: str,
    preconditions: Sequence[FilePrecondition] = (),
) -> None:
    filtered = [change for change in changes if change.original != change.next_source]
    if not filtered:
        return
    paths = [os.path.normcase(os.path.abspath(change.file_path)) for change in filtered]
    if len(paths) != len(set(paths)):
        raise ValueError(f"{label} contains duplicate file targets")
    staged: List[_StagedChange] = []
    try:
        _assert_preconditions(preconditions, label)
        for change in filtered:
            staged.append(_stage(change))
        _assert_preconditions(preconditions, label)
        for item in staged:
            _assert_preconditions(preconditions, label)
            _commit(item)
        _assert_preconditions(preconditions, label)
    except Exception as error:
        recovery_errors = []
        for item in reversed(staged):
            try:
                _rollback(item)
            except Exception as rollback_error:
                recovery_errors.append(str(rollback_error))
        for item in staged:
            try:
                _cleanup(item)
            except OSError as cleanup_error:
                recovery_errors.append(str(cleanup_error))
        suffix = (
            f"; recovery failed: {'; '.join(recovery_errors)}"
            if recovery_errors
            else ""
        )
        raise OSError(f"{label}: {error}{suffix}") from error
    cleanup_errors = []
    for item in staged:
        try:
            _cleanup(item)
        except OSError as error:
            cleanup_errors.append(str(error))
    if cleanup_errors:
        raise OSError(f"{label} cleanup failed: {'; '.join(cleanup_errors)}")


def regular_file_exists(file_path: str, label: str) -> bool:
    return physical_file_exists(file_path, label)


def require_runtime(file_path: str, label: str) -> None:
    if not file_path:
        raise ValueError(f"{label} path is required")
    if not regular_file_exists(file_path, label):
        raise FileNotFoundError(f"{label} is missing: {file_path}")
