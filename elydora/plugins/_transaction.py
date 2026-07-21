"""Fail-fast transactional file changes shared by hook adapters."""

from __future__ import annotations

import os
from typing import List, Optional, Sequence, cast
from uuid import uuid4

from ._managed_files import (
    FileSnapshot,
    MAX_SOURCE_BYTES,
    physical_file_exists,
    read_physical_file,
)
from ._opaque_cleanup import cleanup_opaque_removal
from ._opaque_removal import (
    OpaqueRemovalChange,
    StagedOpaqueRemoval,
    assert_staged_opaque,
    commit_opaque_removal,
    prepare_opaque_rollback,
    rollback_opaque_removal,
    stage_opaque_removal,
)
from ._pinned_directory import PinnedDirectory
from ._transaction_commit import commit_change, prepare_change, rollback_change
from ._transaction_journal import (
    FileFingerprint,
    JournalRecord,
    TransactionJournal,
    active_journal_path,
    clear_journal,
    write_journal,
)
from ._transaction_lock import serialized_transactions
from ._transaction_restart import (
    recover_pending_locked,
    recover_pending_transactions as _recover_pending_transactions,
)
from ._transaction_staging import (
    assert_transaction_preconditions,
    cleanup_created_directories,
    cleanup_staged,
    close_directories,
    directory_for,
    pin_directories,
    reserve_change,
    same_snapshot,
    stage_change,
)
from ._transaction_types import (
    DirectoryMap,
    DirectoryPrecondition,
    FileChange,
    FilePrecondition,
    StagedChange,
)


_EXPECTED_SNAPSHOT_UNSET = object()


def recover_pending_transactions() -> None:
    """Recover a journal left by a terminated transaction process."""
    _recover_pending_transactions()


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
    enforce_mode: bool = False,
) -> Optional[FileChange]:
    if next_source is not None and len(next_source.encode("utf-8")) > maximum_bytes:
        raise ValueError(f"{label} exceeds {maximum_bytes} bytes: {file_path}")
    snapshot = read_physical_file(file_path, label, maximum_bytes)
    current = None if snapshot is None else snapshot.contents
    if current != original:
        raise OSError(f"{label} changed before staging: {file_path}")
    if expected_snapshot is not _EXPECTED_SNAPSHOT_UNSET:
        expected = cast(Optional[FileSnapshot], expected_snapshot)
        if not same_snapshot(snapshot, expected):
            raise OSError(f"{label} changed before staging: {file_path}")
    if original == next_source and (
        not enforce_mode or snapshot is None or snapshot.mode == mode
    ):
        return None
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
    enforce_mode: bool = False,
) -> Optional[FileChange]:
    snapshot = read_physical_file(file_path, label, maximum_bytes)
    return source_change(
        file_path,
        label,
        None if snapshot is None else snapshot.contents,
        next_source,
        mode,
        maximum_bytes,
        enforce_mode=enforce_mode,
    )


def _replace_physical(
    source_path: str,
    destination_path: str,
    directory: PinnedDirectory,
) -> None:
    del source_path, destination_path, directory


def _restore_physical(
    source_path: str,
    destination_path: str,
    directory: PinnedDirectory,
) -> None:
    del source_path, destination_path, directory


def _capture_physical(
    source_path: str,
    destination_path: str,
    directory: PinnedDirectory,
) -> None:
    del source_path, destination_path, directory


def _after_replace_physical(
    source_path: str,
    destination_path: str,
    directory: PinnedDirectory,
) -> None:
    del source_path, destination_path, directory


def _after_journal_commit() -> None:
    """Fault-injection boundary after the committed marker is durable."""


def _commit(staged: StagedChange) -> None:
    commit_change(
        staged,
        _replace_physical,
        _capture_physical,
        _after_replace_physical,
    )


def _rollback(staged: StagedChange) -> None:
    rollback_change(staged, _restore_physical, _capture_physical)


def _recover(
    staged: Sequence[StagedChange],
    opaque_staged: Sequence[StagedOpaqueRemoval],
    directories: DirectoryMap,
    directory_preconditions: Sequence[DirectoryPrecondition],
) -> List[str]:
    errors = []
    for staged_item in reversed(staged):
        try:
            _rollback(staged_item)
        except Exception as error:
            errors.append(str(error))
    for opaque_item in reversed(opaque_staged):
        try:
            rollback_opaque_removal(opaque_item)
        except Exception as error:
            errors.append(str(error))
    for staged_item in staged:
        try:
            cleanup_staged(staged_item)
        except OSError as error:
            errors.append(str(error))
    for opaque_item in opaque_staged:
        try:
            cleanup_opaque_removal(opaque_item)
        except OSError as error:
            errors.append(str(error))
    errors.extend(
        cleanup_created_directories(directory_preconditions, directories)
    )
    errors.extend(close_directories(directories))
    return errors


def _finish_committed(
    staged: Sequence[StagedChange],
    opaque_staged: Sequence[StagedOpaqueRemoval],
    directories: DirectoryMap,
) -> List[str]:
    errors = []
    for staged_item in staged:
        try:
            cleanup_staged(staged_item)
        except OSError as error:
            errors.append(str(error))
    for opaque_item in opaque_staged:
        try:
            cleanup_opaque_removal(opaque_item)
        except OSError as error:
            errors.append(str(error))
    errors.extend(close_directories(directories))
    if errors:
        return errors
    try:
        clear_journal()
    except OSError as error:
        errors.append(str(error))
    return errors


def _text_journal_record(staged: StagedChange) -> JournalRecord:
    original = None
    if staged.change.original is not None:
        if (
            staged.change.original_device is None
            or staged.change.original_inode is None
            or staged.change.original_mode is None
        ):
            raise OSError(f"Missing original identity for {staged.change.label}")
        original = FileFingerprint.from_text(
            FileSnapshot(
                staged.change.original,
                staged.change.original_device,
                staged.change.original_inode,
                staged.change.original_mode,
            )
        )
    next_value = (
        None
        if staged.temporary_snapshot is None
        else FileFingerprint.from_text(staged.temporary_snapshot)
    )
    temporary_identity = (
        None
        if staged.temporary_reservation is None
        else FileFingerprint.from_text(staged.temporary_reservation)
    )
    rollback = (
        None
        if staged.rollback_reservation is None
        else FileFingerprint.from_text(staged.rollback_reservation)
    )
    return JournalRecord(
        "text",
        staged.change.label,
        os.path.abspath(staged.change.file_path),
        None if staged.temporary_path is None else os.path.abspath(staged.temporary_path),
        None if staged.rollback_path is None else os.path.abspath(staged.rollback_path),
        staged.directory.path,
        staged.directory.snapshot,
        original,
        next_value,
        temporary_identity,
        rollback,
    )


def _opaque_journal_record(staged: StagedOpaqueRemoval) -> JournalRecord:
    original = (
        None
        if staged.change.original is None
        else FileFingerprint.from_opaque(staged.change.original)
    )
    rollback = (
        None
        if staged.rollback_reservation is None
        else FileFingerprint.from_text(staged.rollback_reservation)
    )
    return JournalRecord(
        "opaque",
        staged.change.label,
        os.path.abspath(staged.change.file_path),
        None,
        None if staged.rollback_path is None else os.path.abspath(staged.rollback_path),
        staged.directory.path,
        staged.directory.snapshot,
        original,
        None,
        None,
        rollback,
    )


def _write_changes_locked(
    changes: Sequence[FileChange],
    label: str,
    preconditions: Sequence[FilePrecondition] = (),
    directory_preconditions: Sequence[DirectoryPrecondition] = (),
    opaque_removals: Sequence[OpaqueRemovalChange] = (),
) -> None:
    filtered = [
        change
        for change in changes
        if change.original != change.next_source
        or change.original_mode != change.mode
    ]
    directories: DirectoryMap = {}
    staged: List[StagedChange] = []
    opaque_staged: List[StagedOpaqueRemoval] = []
    journal: Optional[TransactionJournal] = None
    committed_marker_durable = False
    try:
        assert_transaction_preconditions(preconditions, directory_preconditions, label)
        if not filtered and not opaque_removals:
            return
        paths = [
            os.path.normcase(os.path.abspath(change.file_path)) for change in filtered
        ]
        paths.extend(
            os.path.normcase(os.path.abspath(change.file_path))
            for change in opaque_removals
        )
        if len(paths) != len(set(paths)):
            raise ValueError(f"{label} contains duplicate file targets")
        directories = pin_directories(
            filtered,
            preconditions,
            directory_preconditions,
            [
                (
                    os.path.dirname(change.file_path),
                    f"{change.label} directory",
                    True,
                )
                for change in opaque_removals
            ],
        )
        for opaque_change in opaque_removals:
            opaque_staged.append(
                stage_opaque_removal(
                    opaque_change,
                    directory_for(opaque_change.file_path, directories),
                    label,
                )
            )
        for file_change_item in filtered:
            staged.append(
                reserve_change(
                    file_change_item,
                    preconditions,
                    directory_preconditions,
                    label,
                    directories,
                )
            )
        records = [
            *(_opaque_journal_record(item) for item in opaque_staged),
            *(_text_journal_record(item) for item in staged),
        ]
        journal = TransactionJournal(uuid4().hex, label, "preparing", records)
        write_journal(journal)
        for staged_item in staged:
            stage_change(staged_item)
        records = [
            *(_opaque_journal_record(item) for item in opaque_staged),
            *(_text_journal_record(item) for item in staged),
        ]
        journal = TransactionJournal(
            journal.transaction_id,
            journal.label,
            journal.state,
            records,
        )
        write_journal(journal)
        assert_transaction_preconditions(
            preconditions, directory_preconditions, label, directories
        )
        for opaque_item in opaque_staged:
            assert_staged_opaque(opaque_item, label)
        for opaque_item in opaque_staged:
            prepare_opaque_rollback(opaque_item)
        for staged_item in staged:
            prepare_change(staged_item, _capture_physical)
        journal = journal.with_state("committing")
        write_journal(journal)
        for opaque_item in opaque_staged:
            commit_opaque_removal(opaque_item)
        for staged_item in staged:
            _commit(staged_item)
        assert_transaction_preconditions(
            preconditions, directory_preconditions, label, directories
        )
        for opaque_item in opaque_staged:
            assert_staged_opaque(opaque_item, label)
        committed_journal = journal.with_state("committed")
        write_journal(committed_journal)
        journal = committed_journal
        committed_marker_durable = True
        _after_journal_commit()
    except Exception as error:
        if committed_marker_durable:
            cleanup_errors = _finish_committed(
                staged,
                opaque_staged,
                directories,
            )
            suffix = (
                f"; cleanup pending in {active_journal_path()}: "
                f"{'; '.join(cleanup_errors)}"
                if cleanup_errors
                else ""
            )
            raise OSError(
                f"{label} committed before post-commit failure: {error}{suffix}"
            ) from error
        recovery_errors = _recover(
            staged,
            opaque_staged,
            directories,
            directory_preconditions,
        )
        suffix = (
            f"; recovery failed: {'; '.join(recovery_errors)}"
            if recovery_errors
            else ""
        )
        if journal is not None and not recovery_errors:
            try:
                clear_journal()
            except OSError as journal_error:
                suffix += f"; journal cleanup failed: {journal_error}"
        elif journal is not None:
            suffix += f"; recovery journal preserved at {active_journal_path()}"
        raise OSError(f"{label}: {error}{suffix}") from error

    cleanup_errors = _finish_committed(staged, opaque_staged, directories)
    if cleanup_errors:
        raise OSError(
            f"{label} committed; cleanup pending in {active_journal_path()}: "
            f"{'; '.join(cleanup_errors)}"
        )


def write_changes(
    changes: Sequence[FileChange],
    label: str,
    preconditions: Sequence[FilePrecondition] = (),
    directory_preconditions: Sequence[DirectoryPrecondition] = (),
    opaque_removals: Sequence[OpaqueRemovalChange] = (),
) -> None:
    with serialized_transactions():
        recover_pending_locked()
        _write_changes_locked(
            changes,
            label,
            preconditions,
            directory_preconditions,
            opaque_removals,
        )


def regular_file_exists(file_path: str, label: str) -> bool:
    return physical_file_exists(file_path, label)


def require_runtime(file_path: str, label: str) -> None:
    if not file_path:
        raise ValueError(f"{label} path is required")
    if not regular_file_exists(file_path, label):
        raise FileNotFoundError(f"{label} is missing: {file_path}")
