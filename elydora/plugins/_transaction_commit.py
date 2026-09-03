"""Durable preparation, atomic commit, and rollback for text-file changes."""

from __future__ import annotations

import os
from typing import Callable, Optional

from ._durable_file import atomic_replace, copy_into_reserved
from ._managed_files import FileSnapshot
from ._pinned_directory import PinnedDirectory
from ._private_artifact import QuarantinedFile
from ._transaction_recovery import remove_committed_creation
from ._transaction_staging import (
    assert_transaction_preconditions,
    assert_unchanged,
    read_target,
    same_identity_and_contents,
    same_snapshot,
)
from ._transaction_types import FileChange, StagedChange


ReplaceFile = Callable[[str, str, PinnedDirectory], None]


def _original_snapshot(change: FileChange) -> Optional[FileSnapshot]:
    if change.original is None:
        return None
    if (
        change.original_device is None
        or change.original_inode is None
        or change.original_mode is None
    ):
        raise OSError(f"Missing original identity for {change.label}")
    return FileSnapshot(
        change.original,
        change.original_device,
        change.original_inode,
        change.original_mode,
    )


def _read_temporary(staged: StagedChange) -> Optional[FileSnapshot]:
    if staged.temporary_path is None:
        return None
    return staged.directory.read_file(
        staged.directory.name_for(staged.temporary_path),
        f"staged {staged.change.label}",
        staged.change.maximum_bytes,
    )


def _read_rollback(staged: StagedChange) -> Optional[FileSnapshot]:
    if staged.rollback_path is None:
        return None
    return staged.directory.read_file(
        staged.directory.name_for(staged.rollback_path),
        f"{staged.change.label} rollback",
        staged.change.maximum_bytes,
    )


def _preserve_rollback(staged: StagedChange, error: Exception) -> OSError:
    if staged.rollback_path is None:
        return error if isinstance(error, OSError) else OSError(str(error))
    rollback_path = staged.rollback_path
    staged.rollback_path = None
    return OSError(f"{error}; original content preserved at {rollback_path}")


def prepare_change(staged: StagedChange, capture_file: ReplaceFile) -> None:
    """Create and flush rollback material while the public target stays visible."""
    original = _original_snapshot(staged.change)
    if original is None:
        return
    reservation = staged.rollback_reservation
    rollback_path = staged.rollback_path
    if reservation is None or rollback_path is None:
        raise OSError(f"Missing rollback reservation for {staged.change.label}")
    capture_file(staged.change.file_path, rollback_path, staged.directory)
    assert_transaction_preconditions(*staged.preconditions, staged.directories)
    current = read_target(staged)
    if not same_snapshot(current, original):
        raise OSError(
            f"{staged.change.label} changed at commit boundary: "
            f"{staged.change.file_path}"
        )
    rollback = _read_rollback(staged)
    if not same_snapshot(rollback, reservation):
        raise OSError(
            f"{staged.change.label} existing rollback reservation changed: "
            f"{rollback_path}"
        )
    copy_into_reserved(
        staged.directory,
        staged.change.file_path,
        rollback_path,
        (original.device, original.inode),
        (reservation.device, reservation.inode),
        0o600,
        staged.change.label,
        staged.change.maximum_bytes,
    )
    current = read_target(staged)
    if not same_snapshot(current, original):
        raise OSError(
            f"{staged.change.label} changed while preparing rollback: "
            f"{staged.change.file_path}"
        )
    prepared = _read_rollback(staged)
    if (
        prepared is None
        or prepared.contents != original.contents
        or (prepared.device, prepared.inode)
        != (reservation.device, reservation.inode)
        or (os.name != "nt" and prepared.mode != 0o600)
    ):
        raise OSError(
            f"{staged.change.label} rollback changed while preparing: {rollback_path}"
        )
    staged.rollback_snapshot = prepared
    staged.rollback_reservation = None


def _replace_next(
    staged: StagedChange,
    replace_file: ReplaceFile,
    after_replace: ReplaceFile,
) -> None:
    temporary = staged.temporary_snapshot
    temporary_path = staged.temporary_path
    if temporary_path is None or temporary is None:
        raise OSError(f"Missing staged file for {staged.change.label}")
    replace_file(temporary_path, staged.change.file_path, staged.directory)
    assert_transaction_preconditions(*staged.preconditions, staged.directories)
    current = read_target(staged)
    expected = _original_snapshot(staged.change)
    if not same_snapshot(current, expected):
        error = OSError(
            f"{staged.change.label} changed before atomic replacement: "
            f"{staged.change.file_path}"
        )
        if expected is not None:
            raise _preserve_rollback(staged, error) from error
        raise error
    if not same_snapshot(_read_temporary(staged), temporary):
        raise OSError(
            f"Staged {staged.change.label} changed at install boundary: "
            f"{temporary_path}"
        )
    atomic_replace(staged.directory, temporary_path, staged.change.file_path)
    staged.temporary_path = None
    staged.committed_snapshot = temporary
    staged.committed = True
    after_replace(temporary_path, staged.change.file_path, staged.directory)


def _remove_original(staged: StagedChange) -> None:
    original = _original_snapshot(staged.change)
    if original is None:
        raise OSError(f"Missing original data for {staged.change.label}")
    captured = QuarantinedFile.capture(
        staged.directory,
        staged.change.file_path,
        staged.change.label,
    )
    snapshot = captured.text_snapshot(staged.change.maximum_bytes)
    if not same_snapshot(snapshot, original):
        try:
            captured.restore()
        except Exception as error:
            preserved = (
                captured.preserve()
                if captured.active
                else staged.change.file_path
            )
            raise OSError(
                f"{staged.change.label} changed at removal boundary; "
                f"concurrent data preserved at {preserved}: {error}"
            ) from error
        raise OSError(
            f"{staged.change.label} changed at removal boundary: "
            f"{staged.change.file_path}"
        )
    captured.discard()
    staged.directory.sync()
    staged.committed_snapshot = None
    staged.committed = True


def commit_change(
    staged: StagedChange,
    replace_file: ReplaceFile,
    capture_file: ReplaceFile,
    after_replace: ReplaceFile,
) -> None:
    del capture_file
    assert_transaction_preconditions(*staged.preconditions, staged.directories)
    assert_unchanged(staged.change, staged.directories)
    if staged.change.original is not None and staged.rollback_snapshot is None:
        raise OSError(f"Missing rollback data for {staged.change.label}")
    if staged.change.next_source is None:
        _remove_original(staged)
        after_replace(
            staged.change.file_path,
            staged.change.file_path,
            staged.directory,
        )
    else:
        _replace_next(staged, replace_file, after_replace)

    current = read_target(staged)
    if not same_snapshot(current, staged.committed_snapshot):
        raise OSError(
            f"{staged.change.label} changed immediately after commit: "
            f"{staged.change.file_path}"
        )
    if os.name != "nt" and current is not None and current.mode != staged.change.mode:
        raise OSError(
            f"{staged.change.label} has an unexpected mode after commit: "
            f"{staged.change.file_path}"
        )
    assert_transaction_preconditions(*staged.preconditions, staged.directories)


def _restore_rollback_file(
    staged: StagedChange,
    expected: FileSnapshot,
    expected_current: Optional[FileSnapshot],
    restore_file: ReplaceFile,
) -> None:
    rollback_path = staged.rollback_path
    rollback = staged.rollback_snapshot
    if rollback_path is None or rollback is None:
        raise OSError(f"Missing rollback path for {staged.change.label}")
    if not same_snapshot(read_target(staged), expected_current):
        raise _preserve_rollback(
            staged,
            OSError(
                f"{staged.change.label} changed before restoration: "
                f"{staged.change.file_path}"
            ),
        )
    try:
        restore_file(rollback_path, staged.change.file_path, staged.directory)
    except Exception as error:
        raise _preserve_rollback(staged, error) from error
    if not same_snapshot(read_target(staged), expected_current):
        raise _preserve_rollback(
            staged,
            OSError(
                f"{staged.change.label} changed before atomic restoration: "
                f"{staged.change.file_path}"
            ),
        )
    current_rollback = _read_rollback(staged)
    if not same_identity_and_contents(current_rollback, rollback):
        raise _preserve_rollback(
            staged,
            OSError(
                f"{staged.change.label} recovery source changed; concurrent data "
                f"preserved at {rollback_path}"
            ),
        )
    if expected.mode != rollback.mode:
        staged.directory.chmod_file(
            staged.directory.name_for(rollback_path),
            expected.mode,
            (rollback.device, rollback.inode),
        )
    atomic_replace(staged.directory, rollback_path, staged.change.file_path)
    staged.rollback_path = None
    restored = read_target(staged)
    if (
        restored is None
        or restored.contents != expected.contents
        or restored.mode != expected.mode
    ):
        raise OSError(
            f"{staged.change.label} changed while restoring: "
            f"{staged.change.file_path}"
        )


def rollback_change(
    staged: StagedChange,
    restore_file: ReplaceFile,
    capture_file: ReplaceFile,
) -> None:
    if not staged.committed:
        return
    current = read_target(staged)
    if not same_snapshot(current, staged.committed_snapshot):
        raise _preserve_rollback(
            staged,
            OSError(
                f"{staged.change.label} changed during transaction recovery: "
                f"{staged.change.file_path}"
            ),
        )
    if staged.change.original is None:
        remove_committed_creation(staged, restore_file, capture_file)
        return
    original = _original_snapshot(staged.change)
    if original is None:
        raise OSError(f"Missing original data for {staged.change.label}")
    _restore_rollback_file(
        staged,
        original,
        staged.committed_snapshot,
        restore_file,
    )
    staged.rollback_snapshot = None
    staged.committed_snapshot = None
    staged.committed = False


__all__ = ["commit_change", "prepare_change", "rollback_change"]
