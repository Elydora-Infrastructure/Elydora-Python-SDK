"""Deterministic recovery of a transaction interrupted by process exit."""

from __future__ import annotations

import os
from typing import Dict, Optional

from ._durable_file import atomic_replace
from ._pinned_directory import PinnedDirectory
from ._private_artifact import QuarantinedFile
from ._transaction_journal import (
    FileFingerprint,
    JournalRecord,
    TransactionJournal,
    clear_journal,
    inspect_fingerprint,
    load_journal,
    write_journal,
)
from ._transaction_lock import serialized_transactions, transaction_state_path


def _directory_key(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def _open_directories(journal: TransactionJournal) -> Dict[str, PinnedDirectory]:
    directories: Dict[str, PinnedDirectory] = {}
    try:
        for record in journal.records:
            key = _directory_key(record.directory)
            current = directories.get(key)
            if current is not None:
                if current.snapshot != record.directory_snapshot:
                    raise OSError(
                        f"Conflicting directory identities in transaction journal: "
                        f"{record.directory}"
                    )
                continue
            directories[key] = PinnedDirectory.open(
                record.directory,
                f"{record.label} recovery directory",
                record.directory_snapshot,
            )
        return directories
    except Exception:
        _close_directories(directories)
        raise


def _close_directories(directories: Dict[str, PinnedDirectory]) -> None:
    failures = []
    for directory in reversed(list(directories.values())):
        try:
            directory.close()
        except OSError as error:
            failures.append(str(error))
    if failures:
        raise OSError("; ".join(failures))


def _directory_for(
    record: JournalRecord,
    directories: Dict[str, PinnedDirectory],
) -> PinnedDirectory:
    directory = directories.get(_directory_key(record.directory))
    if directory is None:
        raise OSError(f"Missing recovery directory for {record.label}")
    return directory


def _remove_owned_file(
    directory: PinnedDirectory,
    path: Optional[str],
    expected_identity: Optional[FileFingerprint],
    label: str,
) -> None:
    if path is None or expected_identity is None:
        return
    current = inspect_fingerprint(directory, path, label)
    if current is None:
        return
    if (
        current.device != expected_identity.device
        or current.inode != expected_identity.inode
    ):
        raise OSError(f"{label} changed before recovery cleanup: {path}")
    captured = QuarantinedFile.capture(
        directory,
        path,
        label,
        require_parent_path=False,
    )
    captured_current = inspect_fingerprint(
        captured.container,
        captured.container.path_for("entry"),
        label,
    )
    if (
        captured_current is None
        or captured_current.device != expected_identity.device
        or captured_current.inode != expected_identity.inode
    ):
        preserved = captured.preserve()
        raise OSError(
            f"{label} changed at recovery cleanup boundary; preserved at {preserved}"
        )
    captured.discard()
    directory.sync()


def _cleanup_record(
    record: JournalRecord,
    directories: Dict[str, PinnedDirectory],
) -> None:
    directory = _directory_for(record, directories)
    _remove_owned_file(
        directory,
        record.temporary,
        record.temporary_identity,
        f"staged {record.label}",
    )
    _remove_owned_file(
        directory,
        record.rollback,
        record.rollback_identity,
        f"{record.label} rollback",
    )


def _restore_original(
    record: JournalRecord,
    directory: PinnedDirectory,
) -> None:
    original = record.original
    rollback_path = record.rollback
    rollback_identity = record.rollback_identity
    if original is None or rollback_path is None or rollback_identity is None:
        raise OSError(f"Missing rollback data for {record.label}")
    rollback = inspect_fingerprint(
        directory,
        rollback_path,
        f"{record.label} rollback",
    )
    if (
        rollback is None
        or rollback.device != rollback_identity.device
        or rollback.inode != rollback_identity.inode
        or not original.same_contents(rollback)
    ):
        raise OSError(
            f"{record.label} rollback changed during restart recovery: "
            f"{rollback_path}"
        )
    if rollback.mode != original.mode:
        directory.chmod_file(
            directory.name_for(rollback_path),
            original.mode,
            (rollback.device, rollback.inode),
        )
    atomic_replace(directory, rollback_path, record.target)
    restored = inspect_fingerprint(directory, record.target, record.label)
    if not original.same_visible(restored):
        raise OSError(
            f"{record.label} restoration failed during restart recovery: "
            f"{record.target}"
        )


def _matches_original_state(
    record: JournalRecord,
    current: Optional[FileFingerprint],
) -> bool:
    original = record.original
    if original is None or current is None or not original.same_visible(current):
        return False
    if original.same_exact(current):
        return True
    rollback = record.rollback_identity
    return (
        rollback is not None
        and current.device == rollback.device
        and current.inode == rollback.inode
    )


def _remove_created_target(
    record: JournalRecord,
    directory: PinnedDirectory,
    current: FileFingerprint,
) -> None:
    expected = record.next
    if expected is None or not expected.same_exact(current):
        raise OSError(
            f"{record.label} changed before creation recovery: {record.target}"
        )
    captured = QuarantinedFile.capture(directory, record.target, record.label)
    captured_current = inspect_fingerprint(
        captured.container,
        captured.container.path_for("entry"),
        record.label,
    )
    if not expected.same_exact(captured_current):
        try:
            captured.restore(record.target)
        except Exception as error:
            preserved = captured.preserve() if captured.active else record.target
            raise OSError(
                f"{record.label} changed at creation recovery boundary; "
                f"preserved at {preserved}: {error}"
            ) from error
        raise OSError(
            f"{record.label} changed at creation recovery boundary: {record.target}"
        )
    captured.discard()
    directory.sync()


def _recover_record(
    record: JournalRecord,
    directories: Dict[str, PinnedDirectory],
) -> None:
    directory = _directory_for(record, directories)
    current = inspect_fingerprint(directory, record.target, record.label)
    original = record.original
    next_value = record.next
    if original is None:
        if current is None:
            return
        _remove_created_target(record, directory, current)
        return
    if _matches_original_state(record, current):
        return
    if next_value is None:
        if current is not None:
            raise OSError(
                f"{record.label} changed after transactional removal: {record.target}"
            )
        _restore_original(record, directory)
        return
    if current is None or not next_value.same_exact(current):
        raise OSError(
            f"{record.label} changed after atomic replacement; original content "
            f"preserved at {record.rollback}: {record.target}"
        )
    _restore_original(record, directory)


def _verify_committed_record(
    record: JournalRecord,
    directories: Dict[str, PinnedDirectory],
) -> None:
    directory = _directory_for(record, directories)
    current = inspect_fingerprint(directory, record.target, record.label)
    if record.next is None:
        if current is not None:
            raise OSError(
                f"{record.label} changed after committed removal: {record.target}"
            )
        return
    if not record.next.same_exact(current):
        raise OSError(
            f"{record.label} changed after committed transaction: {record.target}"
        )


def recover_pending_locked() -> None:
    """Recover the active journal while the caller owns the transaction lock."""
    journal = load_journal()
    if journal is None:
        return
    directories = _open_directories(journal)
    try:
        if journal.state == "preparing":
            for record in journal.records:
                current = inspect_fingerprint(
                    _directory_for(record, directories),
                    record.target,
                    record.label,
                )
                if record.original is None:
                    if current is not None:
                        raise OSError(
                            f"{record.label} appeared during transaction preparation: "
                            f"{record.target}"
                        )
                elif not record.original.same_exact(current):
                    raise OSError(
                        f"{record.label} changed during transaction preparation: "
                        f"{record.target}"
                    )
        elif journal.state in {"committing", "recovering"}:
            if journal.state != "recovering":
                journal = journal.with_state("recovering")
                write_journal(journal)
            for record in reversed(journal.records):
                _recover_record(record, directories)
        elif journal.state == "committed":
            for record in journal.records:
                _verify_committed_record(record, directories)
        else:
            raise ValueError(f"Unsupported transaction state: {journal.state}")
        for record in journal.records:
            _cleanup_record(record, directories)
        clear_journal()
    finally:
        _close_directories(directories)


def recover_pending_transactions() -> None:
    """Serialize and recover any transaction left by a terminated process.

    A missing state directory proves no journal exists, so this returns without
    creating runtime directories for commands that may still reject their input.
    """
    if not os.path.isdir(transaction_state_path()):
        return
    with serialized_transactions():
        recover_pending_locked()


__all__ = ["recover_pending_locked", "recover_pending_transactions"]
