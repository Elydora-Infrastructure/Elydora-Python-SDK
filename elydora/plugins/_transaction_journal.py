"""Validated persistent journal for crash-recoverable file transactions."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import os
import stat
from typing import Any, Dict, List, Optional
from uuid import uuid4

from ._managed_files import (
    DirectorySnapshot,
    FileSnapshot,
    same_file_metadata,
    identity_mode_bits,
)
from ._opaque_snapshot import OpaqueFileSnapshot
from ._pinned_directory import PinnedDirectory
from ._transaction_lock import transaction_state_directory


JOURNAL_VERSION = 1
JOURNAL_STATES = {"preparing", "committing", "recovering", "committed"}
MAX_JOURNAL_BYTES = 1024 * 1024
MAX_JOURNAL_RECORDS = 256
_ACTIVE_JOURNAL = "active-v1.json"
_HASH_CHUNK_BYTES = 1024 * 1024


@dataclass(frozen=True)
class FileFingerprint:
    sha256: str
    size: int
    mode: int
    device: int
    inode: int

    @classmethod
    def from_text(cls, snapshot: FileSnapshot) -> "FileFingerprint":
        encoded = snapshot.contents.encode("utf-8")
        return cls(
            hashlib.sha256(encoded).hexdigest(),
            len(encoded),
            snapshot.mode,
            snapshot.device,
            snapshot.inode,
        )

    @classmethod
    def from_opaque(cls, snapshot: OpaqueFileSnapshot) -> "FileFingerprint":
        return cls(
            snapshot.sha256,
            snapshot.size,
            snapshot.mode,
            snapshot.device,
            snapshot.inode,
        )

    def same_contents(self, other: Optional["FileFingerprint"]) -> bool:
        return (
            other is not None
            and self.sha256 == other.sha256
            and self.size == other.size
        )

    def same_visible(self, other: Optional["FileFingerprint"]) -> bool:
        return (
            self.same_contents(other)
            and other is not None
            and identity_mode_bits(self.mode) == identity_mode_bits(other.mode)
        )

    def same_exact(self, other: Optional["FileFingerprint"]) -> bool:
        return (
            self.same_visible(other)
            and other is not None
            and self.device == other.device
            and self.inode == other.inode
        )

    def to_object(self) -> Dict[str, Any]:
        return {
            "sha256": self.sha256,
            "size": self.size,
            "mode": self.mode,
            "device": self.device,
            "inode": self.inode,
        }

    @classmethod
    def from_object(cls, value: object, label: str) -> "FileFingerprint":
        if not isinstance(value, dict) or set(value) != {
            "sha256",
            "size",
            "mode",
            "device",
            "inode",
        }:
            raise ValueError(f"Invalid {label} fingerprint")
        digest = value["sha256"]
        numbers = [value[key] for key in ("size", "mode", "device", "inode")]
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or any(not isinstance(number, int) or number < 0 for number in numbers)
        ):
            raise ValueError(f"Invalid {label} fingerprint")
        return cls(digest, numbers[0], numbers[1], numbers[2], numbers[3])


@dataclass(frozen=True)
class JournalRecord:
    kind: str
    label: str
    target: str
    temporary: Optional[str]
    rollback: Optional[str]
    directory: str
    directory_snapshot: DirectorySnapshot
    original: Optional[FileFingerprint]
    next: Optional[FileFingerprint]
    temporary_identity: Optional[FileFingerprint]
    rollback_identity: Optional[FileFingerprint]

    def to_object(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "label": self.label,
            "target": self.target,
            "temporary": self.temporary,
            "rollback": self.rollback,
            "directory": self.directory,
            "directory_snapshot": {
                "device": self.directory_snapshot.device,
                "inode": self.directory_snapshot.inode,
            },
            "original": None if self.original is None else self.original.to_object(),
            "next": None if self.next is None else self.next.to_object(),
            "temporary_identity": (
                None
                if self.temporary_identity is None
                else self.temporary_identity.to_object()
            ),
            "rollback_identity": (
                None
                if self.rollback_identity is None
                else self.rollback_identity.to_object()
            ),
        }

    @classmethod
    def from_object(cls, value: object, index: int) -> "JournalRecord":
        if not isinstance(value, dict):
            raise ValueError(f"Invalid transaction record {index}")
        required = {
            "kind",
            "label",
            "target",
            "temporary",
            "rollback",
            "directory",
            "directory_snapshot",
            "original",
            "next",
            "temporary_identity",
            "rollback_identity",
        }
        if set(value) != required:
            raise ValueError(f"Invalid transaction record {index}")
        kind = value["kind"]
        label = value["label"]
        target = value["target"]
        temporary = value["temporary"]
        rollback = value["rollback"]
        directory = value["directory"]
        if (
            kind not in {"text", "opaque"}
            or not isinstance(label, str)
            or not label
            or not isinstance(target, str)
            or not isinstance(directory, str)
            or not os.path.isabs(target)
            or not os.path.isabs(directory)
            or os.path.normcase(os.path.dirname(target)) != os.path.normcase(directory)
        ):
            raise ValueError(f"Invalid transaction record {index}")
        for path in (temporary, rollback):
            if path is not None and (
                not isinstance(path, str)
                or not os.path.isabs(path)
                or os.path.normcase(os.path.dirname(path))
                != os.path.normcase(directory)
            ):
                raise ValueError(f"Invalid transaction record {index} path")
        snapshot = value["directory_snapshot"]
        if (
            not isinstance(snapshot, dict)
            or set(snapshot) != {"device", "inode"}
            or not isinstance(snapshot["device"], int)
            or not isinstance(snapshot["inode"], int)
        ):
            raise ValueError(f"Invalid transaction record {index} directory")

        def fingerprint(key: str) -> Optional[FileFingerprint]:
            item = value[key]
            return (
                None
                if item is None
                else FileFingerprint.from_object(item, f"record {index} {key}")
            )

        return cls(
            kind,
            label,
            target,
            temporary,
            rollback,
            directory,
            DirectorySnapshot(snapshot["device"], snapshot["inode"]),
            fingerprint("original"),
            fingerprint("next"),
            fingerprint("temporary_identity"),
            fingerprint("rollback_identity"),
        )


@dataclass(frozen=True)
class TransactionJournal:
    transaction_id: str
    label: str
    state: str
    records: List[JournalRecord]

    def with_state(self, state: str) -> "TransactionJournal":
        if state not in JOURNAL_STATES:
            raise ValueError(f"Invalid transaction state: {state}")
        return replace(self, state=state)

    def to_object(self) -> Dict[str, Any]:
        return {
            "version": JOURNAL_VERSION,
            "transaction_id": self.transaction_id,
            "label": self.label,
            "state": self.state,
            "records": [record.to_object() for record in self.records],
        }

    @classmethod
    def from_object(cls, value: object) -> "TransactionJournal":
        if not isinstance(value, dict) or set(value) != {
            "version",
            "transaction_id",
            "label",
            "state",
            "records",
        }:
            raise ValueError("Invalid transaction journal schema")
        transaction_id = value["transaction_id"]
        label = value["label"]
        state = value["state"]
        records = value["records"]
        if (
            value["version"] != JOURNAL_VERSION
            or not isinstance(transaction_id, str)
            or len(transaction_id) != 32
            or any(character not in "0123456789abcdef" for character in transaction_id)
            or not isinstance(label, str)
            or not label
            or state not in JOURNAL_STATES
            or not isinstance(records, list)
            or not records
            or len(records) > MAX_JOURNAL_RECORDS
        ):
            raise ValueError("Invalid transaction journal")
        return cls(
            transaction_id,
            label,
            state,
            [JournalRecord.from_object(record, index) for index, record in enumerate(records)],
        )


def inspect_fingerprint(
    directory: PinnedDirectory,
    file_path: str,
    label: str,
) -> Optional[FileFingerprint]:
    name = directory.name_for(file_path)
    try:
        before = directory.stat_file(name)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise OSError(f"{label} path is not a physical file: {file_path}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = directory.open_file(name, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not same_file_metadata(before, opened):
            raise OSError(f"{label} changed while opening: {file_path}")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, _HASH_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
        finished = os.fstat(descriptor)
        if not same_file_metadata(finished, opened):
            raise OSError(f"{label} changed while hashing: {file_path}")
    finally:
        os.close(descriptor)
    visible = directory.stat_file(name)
    if not same_file_metadata(visible, finished):
        raise OSError(f"{label} changed while hashing: {file_path}")
    return FileFingerprint(
        digest.hexdigest(),
        size,
        stat.S_IMODE(opened.st_mode),
        opened.st_dev,
        opened.st_ino,
    )


def _journal_path() -> str:
    return os.path.join(transaction_state_directory(), _ACTIVE_JOURNAL)


def active_journal_path() -> str:
    """Return the stable recovery record path for explicit diagnostics."""
    return _journal_path()


def _sync_state_directory() -> None:
    if os.name == "nt":
        return
    descriptor = os.open(
        transaction_state_directory(),
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _replace_journal(temporary: str, path: str) -> None:
    if os.name != "nt":
        os.replace(temporary, path)
        _sync_state_directory()
        return
    import ctypes as ctypes_module
    from ctypes import wintypes

    ctypes: Any = ctypes_module
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    move = kernel32.MoveFileExW
    move.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    move.restype = wintypes.BOOL
    replace_existing = 0x00000001
    write_through = 0x00000008
    if not move(temporary, path, replace_existing | write_through):
        error = ctypes.get_last_error()
        raise OSError(f"Persist transaction journal: {ctypes.WinError(error)}")


def write_journal(journal: TransactionJournal) -> None:
    encoded = (json.dumps(journal.to_object(), sort_keys=True) + "\n").encode("utf-8")
    if len(encoded) > MAX_JOURNAL_BYTES:
        raise ValueError("Transaction journal exceeds its size limit")
    root = transaction_state_directory()
    path = _journal_path()
    temporary = os.path.join(root, f".{_ACTIVE_JOURNAL}.{uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise OSError("Transaction journal write made no progress")
            offset += written
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        _replace_journal(temporary, path)
    except Exception:
        try:
            os.remove(temporary)
        except FileNotFoundError:
            pass
        raise


def load_journal() -> Optional[TransactionJournal]:
    path = _journal_path()
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise OSError(f"Transaction journal is not a physical file: {path}")
    if os.name == "posix" and metadata.st_mode & 0o077:
        raise PermissionError(f"Transaction journal must be owner-only: {path}")
    if metadata.st_size > MAX_JOURNAL_BYTES:
        raise ValueError("Transaction journal exceeds its size limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not same_file_metadata(opened, metadata):
            raise OSError(f"Transaction journal changed while opening: {path}")
        chunks = []
        remaining = MAX_JOURNAL_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        finished = os.fstat(descriptor)
        if not same_file_metadata(finished, opened):
            raise OSError(f"Transaction journal changed while reading: {path}")
    finally:
        os.close(descriptor)
    try:
        visible = os.lstat(path)
    except FileNotFoundError as error:
        raise OSError(f"Transaction journal changed while reading: {path}") from error
    if not same_file_metadata(visible, finished):
        raise OSError(f"Transaction journal changed while reading: {path}")
    if len(raw) > MAX_JOURNAL_BYTES:
        raise ValueError("Transaction journal exceeds its size limit")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"Invalid transaction journal at {path}: {error}") from error
    try:
        return TransactionJournal.from_object(value)
    except ValueError as error:
        raise ValueError(f"Invalid transaction journal at {path}: {error}") from error


def clear_journal() -> None:
    try:
        os.remove(_journal_path())
    except FileNotFoundError:
        return
    _sync_state_directory()


__all__ = [
    "FileFingerprint",
    "JournalRecord",
    "TransactionJournal",
    "active_journal_path",
    "clear_journal",
    "inspect_fingerprint",
    "load_journal",
    "write_journal",
]

