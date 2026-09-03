"""Durable, identity-bound file copy and replacement primitives."""

from __future__ import annotations

import os
import stat
from typing import Any, Optional, Tuple

from ._managed_files import same_file_metadata
from ._pinned_directory import PinnedDirectory


_COPY_CHUNK_BYTES = 1024 * 1024
FileIdentity = Tuple[int, int]


def _regular_identity(
    metadata: os.stat_result,
    expected: FileIdentity,
    path: str,
    label: str,
) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or (metadata.st_dev, metadata.st_ino) != expected
    ):
        raise OSError(f"{label} changed while copying: {path}")


def copy_into_reserved(
    directory: PinnedDirectory,
    source_path: str,
    destination_path: str,
    source_identity: FileIdentity,
    destination_identity: FileIdentity,
    mode: int,
    label: str,
    maximum_bytes: Optional[int] = None,
) -> None:
    """Copy one physical file into an existing private reservation and fsync it."""
    source_name = directory.name_for(source_path)
    destination_name = directory.name_for(destination_path)
    read_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    read_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    write_flags = os.O_WRONLY | getattr(os, "O_BINARY", 0)
    write_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    source_descriptor = -1
    destination_descriptor = -1
    try:
        source_descriptor = directory.open_file(source_name, read_flags)
        before = os.fstat(source_descriptor)
        _regular_identity(before, source_identity, source_path, label)
        destination_descriptor = directory.open_file(destination_name, write_flags)
        destination = os.fstat(destination_descriptor)
        _regular_identity(
            destination,
            destination_identity,
            destination_path,
            f"{label} destination",
        )
        os.ftruncate(destination_descriptor, 0)
        total = 0
        while True:
            chunk = os.read(source_descriptor, _COPY_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if maximum_bytes is not None and total > maximum_bytes:
                raise ValueError(
                    f"{label} exceeds {maximum_bytes} bytes: {source_path}"
                )
            offset = 0
            while offset < len(chunk):
                written = os.write(destination_descriptor, chunk[offset:])
                if written <= 0:
                    raise OSError(f"Copy {label} made no progress: {destination_path}")
                offset += written
        directory.chmod_descriptor(destination_descriptor, mode)
        os.fsync(destination_descriptor)
        after = os.fstat(source_descriptor)
        if not same_file_metadata(after, before):
            raise OSError(f"{label} changed while copying: {source_path}")
    finally:
        for descriptor in (destination_descriptor, source_descriptor):
            if descriptor >= 0:
                os.close(descriptor)
    visible = directory.stat_file(source_name)
    _regular_identity(visible, source_identity, source_path, label)
    directory.sync()


def atomic_replace(
    directory: PinnedDirectory,
    source_path: str,
    destination_path: str,
) -> None:
    """Atomically replace one same-directory name and persist its entry."""
    if os.name == "nt":
        import ctypes as ctypes_module
        from ctypes import wintypes

        ctypes: Any = ctypes_module
        source = directory.path_for(directory.name_for(source_path))
        destination = directory.path_for(directory.name_for(destination_path))
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        move = kernel32.MoveFileExW
        move.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        move.restype = wintypes.BOOL
        replace_existing = 0x00000001
        write_through = 0x00000008
        if not move(source, destination, replace_existing | write_through):
            error = ctypes.get_last_error()
            raise OSError(f"Atomically replace {destination}: {ctypes.WinError(error)}")
        return
    directory.replace_file(
        directory.name_for(source_path),
        directory.name_for(destination_path),
    )
    directory.sync()


__all__ = ["atomic_replace", "copy_into_reserved"]
