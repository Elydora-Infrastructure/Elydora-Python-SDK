"""No-clobber private-file capture and restoration primitives."""

from __future__ import annotations

import os
from typing import Callable, Optional
from uuid import uuid4

from ._managed_files import FileSnapshot
from ._pinned_directory import PinnedDirectory
from ._private_artifact import QuarantinedFile, reserve_private_path
from ._transaction_staging import same_snapshot
from ._transaction_types import StagedChange


ReplaceFile = Callable[[str, str, PinnedDirectory], None]


def _read_target(staged: StagedChange) -> Optional[FileSnapshot]:
    return staged.directory.read_file(
        staged.directory.name_for(staged.change.file_path),
        staged.change.label,
        staged.change.maximum_bytes,
    )


def _read_private_path(
    staged: StagedChange,
    file_path: str,
    label: str,
) -> Optional[FileSnapshot]:
    return staged.directory.read_file(
        staged.directory.name_for(file_path),
        label,
        staged.change.maximum_bytes,
    )


def _same_identity_and_contents(
    current: Optional[FileSnapshot], expected: Optional[FileSnapshot]
) -> bool:
    if current is None or expected is None:
        return current is expected
    return (
        current.contents == expected.contents
        and current.device == expected.device
        and current.inode == expected.inode
    )


def _recovery_path(staged: StagedChange) -> tuple[str, FileSnapshot]:
    basename = os.path.basename(staged.change.file_path)
    path = staged.directory.path_for(f".{basename}.{uuid4().hex}.recovery")
    reservation = reserve_private_path(
        staged.directory,
        path,
        f"{staged.change.label} recovery",
    )
    return path, reservation


def _preserve_private_path(error: Exception, file_path: str) -> OSError:
    return OSError(f"{error}; transaction data preserved at {file_path}")


def _release_rollback_source(staged: StagedChange, source_path: str) -> bool:
    if staged.rollback_path is not None and os.path.normcase(
        os.path.abspath(staged.rollback_path)
    ) == os.path.normcase(os.path.abspath(source_path)):
        staged.rollback_path = None
        return True
    return False


def _preserve_source_path(
    error: Exception,
    file_path: str,
    original_source: bool,
) -> OSError:
    kind = "original content" if original_source else "transaction data"
    return OSError(f"{error}; {kind} preserved at {file_path}")


def install_private_file(
    staged: StagedChange,
    source_path: str,
    expected: FileSnapshot,
    replace_file: ReplaceFile,
) -> None:
    try:
        replace_file(source_path, staged.change.file_path, staged.directory)
    except Exception:
        raise
    captured = QuarantinedFile.capture(
        staged.directory,
        source_path,
        f"{staged.change.label} recovery source",
    )
    original_source = _release_rollback_source(staged, source_path)
    captured_snapshot = captured.text_snapshot(staged.change.maximum_bytes)
    if not same_snapshot(captured_snapshot, expected):
        try:
            captured.restore(source_path)
        except Exception as error:
            preserved = captured.preserve() if captured.active else source_path
            raise OSError(
                f"{error}; concurrent data preserved at {preserved}"
            ) from error
        raise OSError(
            f"{staged.change.label} recovery source changed: {source_path}; "
            f"concurrent data preserved at {source_path}"
        )
    try:
        captured.link(staged.change.file_path)
    except Exception as error:
        preserved = captured.preserve() if captured.active else source_path
        raise _preserve_source_path(
            error,
            preserved,
            original_source,
        ) from error
    restored = _read_target(staged)
    if not same_snapshot(restored, expected):
        preserved = captured.preserve()
        raise _preserve_source_path(
            OSError(
                f"{staged.change.label} changed while installing recovery data: "
                f"{staged.change.file_path}"
            ),
            preserved,
            original_source,
        )
    captured.discard()


def capture_recovery_target(
    staged: StagedChange,
    expected: FileSnapshot,
    replace_file: ReplaceFile,
    capture_file: ReplaceFile,
) -> tuple[str, FileSnapshot]:
    path, reservation = _recovery_path(staged)
    reserved = QuarantinedFile.capture(
        staged.directory,
        path,
        f"{staged.change.label} recovery reservation",
    )
    reserved_snapshot = reserved.text_snapshot(staged.change.maximum_bytes)
    if not same_snapshot(reserved_snapshot, reservation):
        try:
            reserved.restore(path)
        except Exception as error:
            preserved = reserved.preserve() if reserved.active else path
            raise _preserve_private_path(error, preserved) from error
        raise OSError(
            f"{staged.change.label} recovery reservation changed: {path}"
        )
    try:
        capture_file(staged.change.file_path, path, staged.directory)
    except Exception:
        reserved.discard()
        raise
    captured_file = QuarantinedFile.capture(
        staged.directory,
        staged.change.file_path,
        f"{staged.change.label} recovery",
    )
    captured = captured_file.text_snapshot(staged.change.maximum_bytes)
    if captured is None:
        preserved = captured_file.preserve()
        reserved.discard()
        raise OSError(
            f"Missing recovery data for {staged.change.label}; "
            f"transaction data preserved at {preserved}"
        )
    if not same_snapshot(captured, expected):
        boundary_error = OSError(
            f"{staged.change.label} changed at recovery boundary: "
            f"{staged.change.file_path}"
        )
        try:
            captured_file.restore(staged.change.file_path)
        except Exception as restore_error:
            preserved = (
                captured_file.preserve()
                if captured_file.active
                else staged.change.file_path
            )
            reserved.discard()
            raise OSError(
                f"{boundary_error}; concurrent data preserved at {preserved}: "
                f"{restore_error}"
            ) from boundary_error
        reserved.discard()
        raise boundary_error
    try:
        captured_file.restore(path)
    except Exception as error:
        try:
            captured_file.restore(staged.change.file_path)
        except Exception as restore_error:
            preserved = (
                captured_file.preserve()
                if captured_file.active
                else staged.change.file_path
            )
            reserved.discard()
            raise OSError(
                f"{error}; transaction data preserved at {preserved}; "
                f"restoration failed: {restore_error}"
            ) from error
        reserved.discard()
        raise
    reserved.discard()
    public_snapshot = _read_private_path(
        staged,
        path,
        f"{staged.change.label} recovery",
    )
    if not same_snapshot(public_snapshot, captured):
        raise OSError(f"{staged.change.label} recovery changed: {path}")
    return path, captured


def discard_private_file(
    staged: StagedChange,
    file_path: str,
    expected: FileSnapshot,
) -> None:
    try:
        captured = QuarantinedFile.capture(
            staged.directory,
            file_path,
            f"{staged.change.label} recovery cleanup",
        )
    except FileNotFoundError:
        return
    current = captured.text_snapshot(staged.change.maximum_bytes)
    if not same_snapshot(current, expected):
        try:
            captured.restore(file_path)
        except Exception as error:
            preserved = captured.preserve() if captured.active else file_path
            raise _preserve_private_path(error, preserved) from error
        raise OSError(
            f"{staged.change.label} recovery changed before cleanup: "
            f"{file_path}"
        )
    captured.discard()


def remove_committed_creation(
    staged: StagedChange,
    replace_file: ReplaceFile,
    capture_file: ReplaceFile,
) -> None:
    expected = staged.committed_snapshot
    if expected is None:
        raise OSError(f"Missing committed data for {staged.change.label}")
    recovery_path, recovery_snapshot = capture_recovery_target(
        staged,
        expected,
        replace_file,
        capture_file,
    )
    if _read_target(staged) is not None:
        discard_private_file(staged, recovery_path, recovery_snapshot)
        raise OSError(
            f"{staged.change.label} changed after recovery capture: "
            f"{staged.change.file_path}"
        )
    discard_private_file(staged, recovery_path, recovery_snapshot)


__all__ = [
    "capture_recovery_target",
    "discard_private_file",
    "install_private_file",
    "remove_committed_creation",
]
