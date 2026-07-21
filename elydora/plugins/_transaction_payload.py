"""Identity-bound population of journaled transaction reservations."""

from __future__ import annotations

import os
import stat

from ._managed_files import FileSnapshot
from ._pinned_directory import PinnedDirectory


def _write_all(descriptor: int, payload: bytes, label: str) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError(f"Stage {label} made no progress")
        offset += written


def populate_reserved_text(
    directory: PinnedDirectory,
    file_path: str,
    reservation: FileSnapshot,
    content: str,
    mode: int,
    label: str,
) -> FileSnapshot:
    """Fill one journal-owned empty file without changing its identity."""
    name = directory.name_for(file_path)
    current = directory.read_file(name, f"{label} reservation", 0)
    if current != reservation or current.contents:
        raise OSError(f"{label} reservation changed before staging: {file_path}")

    flags = os.O_WRONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    payload = content.encode("utf-8")
    try:
        descriptor = directory.open_file(name, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(opened.st_mode)
            or (opened.st_dev, opened.st_ino)
            != (reservation.device, reservation.inode)
            or opened.st_size != 0
        ):
            raise OSError(f"{label} reservation changed while opening: {file_path}")
        os.ftruncate(descriptor, 0)
        _write_all(descriptor, payload, label)
        os.fsync(descriptor)
        directory.chmod_descriptor(descriptor, mode)
        os.fsync(descriptor)
        finished = os.fstat(descriptor)
        if (
            not stat.S_ISREG(finished.st_mode)
            or (finished.st_dev, finished.st_ino)
            != (reservation.device, reservation.inode)
            or finished.st_size != len(payload)
        ):
            raise OSError(f"{label} changed while staging: {file_path}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    directory.sync()
    snapshot = directory.read_file(name, label, len(payload))
    if (
        snapshot is None
        or snapshot.contents != content
        or (snapshot.device, snapshot.inode)
        != (reservation.device, reservation.inode)
        or (os.name != "nt" and snapshot.mode != mode)
    ):
        raise OSError(f"{label} changed after staging: {file_path}")
    return snapshot


__all__ = ["populate_reserved_text"]
