"""Streaming, identity-bound removal for arbitrarily large runtime files."""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Optional
from uuid import uuid4

from ._durable_file import copy_into_reserved
from ._managed_files import FileSnapshot, identity_mode_bits
from ._opaque_snapshot import (
    OpaqueFileSnapshot,
    _require_regular,
    stream_opaque_snapshot,
)
from ._pinned_directory import PinnedDirectory
from ._private_artifact import QuarantinedFile, reserve_private_path


@dataclass(frozen=True)
class OpaqueRemovalChange:
    file_path: str
    label: str
    original: Optional[OpaqueFileSnapshot]


@dataclass
class StagedOpaqueRemoval:
    change: OpaqueRemovalChange
    directory: PinnedDirectory
    rollback_path: Optional[str]
    rollback_reservation: Optional[FileSnapshot] = None
    rollback_snapshot: Optional[OpaqueFileSnapshot] = None
    committed: bool = False


def prepare_opaque_removal(
    directory: PinnedDirectory,
    file_path: str,
    label: str,
) -> OpaqueRemovalChange:
    return OpaqueRemovalChange(
        file_path,
        label,
        stream_opaque_snapshot(directory, file_path, label),
    )


def _same_captured(
    current: Optional[OpaqueFileSnapshot],
    expected: Optional[OpaqueFileSnapshot],
    *,
    include_mode: bool = True,
) -> bool:
    if current is None or expected is None:
        return current is expected
    return (
        current.device == expected.device
        and current.inode == expected.inode
        and (
            identity_mode_bits(current.mode) == identity_mode_bits(expected.mode)
            or not include_mode
        )
        and current.size == expected.size
        and current.sha256 == expected.sha256
    )


def assert_opaque_unchanged(
    change: OpaqueRemovalChange,
    directory: PinnedDirectory,
    operation: str,
) -> None:
    current = stream_opaque_snapshot(
        directory,
        change.file_path,
        change.label,
    )
    if current != change.original:
        raise OSError(
            f"{change.label} changed during {operation}: {change.file_path}"
        )


def stage_opaque_removal(
    change: OpaqueRemovalChange,
    directory: PinnedDirectory,
    operation: str,
) -> StagedOpaqueRemoval:
    assert_opaque_unchanged(change, directory, operation)
    if change.original is None:
        return StagedOpaqueRemoval(change, directory, None)
    basename = os.path.basename(change.file_path)
    rollback_name = f".{basename}.{uuid4().hex}.opaque-rollback"
    rollback_path = directory.path_for(rollback_name)
    reservation = reserve_private_path(
        directory,
        rollback_path,
        f"{change.label} rollback",
    )
    return StagedOpaqueRemoval(change, directory, rollback_path, reservation)


def _rollback_snapshot(staged: StagedOpaqueRemoval) -> Optional[OpaqueFileSnapshot]:
    if staged.rollback_path is None:
        return None
    return stream_opaque_snapshot(
        staged.directory,
        staged.rollback_path,
        f"{staged.change.label} rollback",
        require_owner_only=False,
    )


def _target_snapshot(staged: StagedOpaqueRemoval) -> Optional[OpaqueFileSnapshot]:
    return stream_opaque_snapshot(
        staged.directory,
        staged.change.file_path,
        staged.change.label,
        require_owner_only=False,
    )


def _capture_physical(staged: StagedOpaqueRemoval) -> None:
    del staged


def prepare_opaque_rollback(staged: StagedOpaqueRemoval) -> None:
    """Copy and flush opaque rollback data while its public target stays present."""
    original = staged.change.original
    if original is None:
        return
    rollback_path = staged.rollback_path
    reservation = staged.rollback_reservation
    if rollback_path is None or reservation is None:
        raise OSError(f"Missing rollback reservation for {staged.change.label}")
    _capture_physical(staged)
    try:
        assert_opaque_unchanged(staged.change, staged.directory, "commit boundary")
    except OSError as error:
        raise OSError(
            f"{staged.change.label} changed at commit boundary: "
            f"{staged.change.file_path}"
        ) from error
    try:
        current_reservation = staged.directory.read_file(
            staged.directory.name_for(rollback_path),
            f"{staged.change.label} rollback reservation",
            0,
        )
    except ValueError as error:
        raise OSError(
            f"{staged.change.label} existing rollback reservation changed: "
            f"{rollback_path}"
        ) from error
    if current_reservation != reservation:
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
    )
    assert_opaque_unchanged(staged.change, staged.directory, "rollback preparation")
    prepared = _rollback_snapshot(staged)
    if (
        prepared is None
        or prepared.device != reservation.device
        or prepared.inode != reservation.inode
        or prepared.size != original.size
        or prepared.sha256 != original.sha256
        or (os.name != "nt" and prepared.mode != 0o600)
    ):
        raise OSError(
            f"{staged.change.label} rollback changed while preparing: {rollback_path}"
        )
    staged.rollback_snapshot = prepared
    staged.rollback_reservation = None


def _secure_rollback(staged: StagedOpaqueRemoval) -> OpaqueFileSnapshot:
    captured = staged.rollback_snapshot
    if staged.rollback_path is None or captured is None:
        raise OSError(f"Missing rollback data for {staged.change.label}")
    name = staged.directory.name_for(staged.rollback_path)
    flags = (os.O_RDWR if os.name == "nt" else os.O_RDONLY) | getattr(
        os, "O_BINARY", 0
    )
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = staged.directory.open_file(name, flags)
        metadata = os.fstat(descriptor)
        _require_regular(metadata, staged.rollback_path, staged.change.label, False)
        if (metadata.st_dev, metadata.st_ino) != (
            captured.device,
            captured.inode,
        ):
            raise OSError(
                f"{staged.change.label} rollback changed before securing: "
                f"{staged.rollback_path}"
            )
        staged.directory.chmod_descriptor(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    secured = _rollback_snapshot(staged)
    if not _same_captured(secured, captured, include_mode=False):
        raise OSError(
            f"{staged.change.label} rollback changed while securing: "
            f"{staged.rollback_path}"
        )
    if os.name != "nt" and secured is not None and secured.mode != 0o600:
        raise OSError(
            f"{staged.change.label} rollback has an unexpected mode: "
            f"{staged.rollback_path}"
        )
    if secured is None:
        raise OSError(f"Missing rollback data for {staged.change.label}")
    staged.rollback_snapshot = secured
    return secured


def _preserve_rollback(staged: StagedOpaqueRemoval, error: Exception) -> OSError:
    if staged.rollback_path is None:
        return error if isinstance(error, OSError) else OSError(str(error))
    rollback_path = staged.rollback_path
    staged.rollback_path = None
    return OSError(f"{error}; original content preserved at {rollback_path}")


def _restore_snapshot(
    staged: StagedOpaqueRemoval,
    captured: OpaqueFileSnapshot,
    restore_mode: int,
) -> None:
    if staged.rollback_path is None:
        raise OSError(f"Missing rollback path for {staged.change.label}")
    if _target_snapshot(staged) is not None:
        raise _preserve_rollback(
            staged,
            OSError(
                f"{staged.change.label} changed before restoration: "
                f"{staged.change.file_path}"
            ),
        )
    target_name = staged.directory.name_for(staged.change.file_path)
    rollback_path = staged.rollback_path
    rollback_file = QuarantinedFile.capture(
        staged.directory,
        rollback_path,
        f"{staged.change.label} rollback",
    )
    current = stream_opaque_snapshot(
        rollback_file.container,
        rollback_file.entry_path,
        f"{staged.change.label} rollback",
        require_owner_only=False,
    )
    if not _same_captured(current, captured):
        try:
            rollback_file.restore(rollback_path)
        except Exception as error:
            preserved = (
                rollback_file.preserve()
                if rollback_file.active
                else rollback_path
            )
            staged.rollback_path = None
            raise OSError(
                f"{staged.change.label} rollback changed before restoration: "
                f"{rollback_path}; concurrent data preserved at {preserved}: {error}"
            ) from error
        staged.rollback_path = None
        raise OSError(
            f"{staged.change.label} rollback changed before restoration: "
            f"{rollback_path}"
        )
    try:
        rollback_file.restore(staged.change.file_path)
    except Exception as error:
        preserved = (
            rollback_file.preserve()
            if rollback_file.active
            else rollback_path
        )
        staged.rollback_path = None
        raise OSError(
            f"{error}; original content preserved at {preserved}"
        ) from error
    staged.rollback_path = None
    restored = _target_snapshot(staged)
    if not _same_captured(restored, captured):
        raise _preserve_rollback(
            staged,
            OSError(
                f"{staged.change.label} changed while restoring: "
                f"{staged.change.file_path}"
            ),
        )
    if restored is None:
        raise OSError(f"Missing restored data for {staged.change.label}")
    staged.directory.chmod_file(
        target_name,
        restore_mode,
        (restored.device, restored.inode),
    )
    restored = _target_snapshot(staged)
    if (
        not _same_captured(restored, captured, include_mode=False)
        or restored is None
        or restored.mode != restore_mode
    ):
        raise _preserve_rollback(
            staged,
            OSError(
                f"{staged.change.label} metadata restoration failed: "
                f"{staged.change.file_path}"
            ),
        )
    staged.rollback_snapshot = None
    staged.committed = False


def commit_opaque_removal(staged: StagedOpaqueRemoval) -> None:
    original = staged.change.original
    if original is None:
        assert_opaque_unchanged(staged.change, staged.directory, "transaction")
        return
    assert_opaque_unchanged(staged.change, staged.directory, "transaction")
    if staged.rollback_path is None or staged.rollback_snapshot is None:
        raise OSError(f"Missing rollback data for {staged.change.label}")
    captured_file = QuarantinedFile.capture(
        staged.directory,
        staged.change.file_path,
        staged.change.label,
    )
    captured = stream_opaque_snapshot(
        captured_file.container,
        captured_file.entry_path,
        staged.change.label,
        require_owner_only=False,
    )
    if captured is None:
        preserved = captured_file.preserve()
        raise OSError(
            f"Missing captured original for {staged.change.label}; "
            f"transaction data preserved at {preserved}"
        )
    if not _same_captured(captured, original):
        boundary_error = OSError(
            f"{staged.change.label} changed at commit boundary: "
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
            raise OSError(
                f"{boundary_error}; concurrent data preserved at {preserved}: "
                f"{restore_error}"
            ) from boundary_error
        raise boundary_error
    captured_file.discard()
    staged.directory.sync()
    staged.committed = True
    if _target_snapshot(staged) is not None:
        raise OSError(
            f"{staged.change.label} reappeared after capture: "
            f"{staged.change.file_path}"
        )


def assert_staged_opaque(staged: StagedOpaqueRemoval, operation: str) -> None:
    if staged.change.original is None:
        assert_opaque_unchanged(staged.change, staged.directory, operation)
        return
    if not staged.committed:
        assert_opaque_unchanged(staged.change, staged.directory, operation)
        return
    if _target_snapshot(staged) is not None:
        raise OSError(
            f"{staged.change.label} changed during {operation}: "
            f"{staged.change.file_path}"
        )
    current = _rollback_snapshot(staged)
    if current != staged.rollback_snapshot:
        raise OSError(
            f"{staged.change.label} rollback changed during {operation}: "
            f"{staged.rollback_path}"
        )


def rollback_opaque_removal(staged: StagedOpaqueRemoval) -> None:
    if not staged.committed:
        return
    original = staged.change.original
    if original is None or staged.rollback_snapshot is None:
        raise OSError(f"Missing rollback data for {staged.change.label}")
    _restore_snapshot(staged, staged.rollback_snapshot, original.mode)
    restored = _target_snapshot(staged)
    if (
        not _same_captured(restored, original, include_mode=False)
        or restored is None
        or restored.mode != original.mode
    ):
        raise OSError(
            f"{staged.change.label} changed after restoration: "
            f"{staged.change.file_path}"
        )


__all__ = [
    "OpaqueRemovalChange",
    "StagedOpaqueRemoval",
    "assert_opaque_unchanged",
    "assert_staged_opaque",
    "commit_opaque_removal",
    "prepare_opaque_removal",
    "prepare_opaque_rollback",
    "rollback_opaque_removal",
    "stage_opaque_removal",
    "stream_opaque_snapshot",
]
