"""Identity-bound cleanup for captured opaque rollback files."""

from __future__ import annotations

from ._opaque_removal import (
    StagedOpaqueRemoval,
    _same_captured,
    stream_opaque_snapshot,
)
from ._private_artifact import QuarantinedFile


def _capture_cleanup_physical(
    staged: StagedOpaqueRemoval,
    source_path: str,
) -> None:
    del staged, source_path


def cleanup_opaque_removal(staged: StagedOpaqueRemoval) -> None:
    if not staged.committed or staged.rollback_path is None:
        return
    expected = staged.rollback_snapshot
    if expected is None:
        raise OSError(f"Missing rollback data for {staged.change.label}")
    rollback_path = staged.rollback_path
    _capture_cleanup_physical(staged, rollback_path)
    captured_file = QuarantinedFile.capture(
        staged.directory,
        rollback_path,
        f"{staged.change.label} rollback cleanup",
    )
    captured = stream_opaque_snapshot(
        captured_file.container,
        captured_file.entry_path,
        f"{staged.change.label} rollback cleanup",
        require_owner_only=False,
    )
    if not _same_captured(captured, expected):
        try:
            captured_file.restore(rollback_path)
        except Exception as error:
            preserved = (
                captured_file.preserve()
                if captured_file.active
                else rollback_path
            )
            staged.rollback_path = None
            raise OSError(
                f"{staged.change.label} changed at cleanup boundary; "
                f"concurrent data preserved at {preserved}: {error}"
            ) from error
        staged.rollback_path = None
        raise OSError(
            f"{staged.change.label} changed at cleanup boundary; "
            f"concurrent data preserved at {rollback_path}"
        )
    captured_file.discard()
    staged.rollback_path = None
    staged.rollback_snapshot = None
    staged.committed = False


__all__ = ["cleanup_opaque_removal"]
