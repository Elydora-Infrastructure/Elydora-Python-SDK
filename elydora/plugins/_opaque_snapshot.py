"""Bounded-memory snapshots for identity-sensitive opaque files."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import stat
from typing import Optional

from ._managed_files import same_file_metadata
from ._pinned_directory import PinnedDirectory


_HASH_CHUNK_BYTES = 1024 * 1024


@dataclass(frozen=True)
class OpaqueFileSnapshot:
    """Device, inode, mode, size, and SHA-256 without retaining the bytes."""

    device: int
    inode: int
    mode: int
    size: int
    sha256: str


def _require_regular(
    metadata: os.stat_result,
    file_path: str,
    label: str,
    require_owner_only: bool,
) -> None:
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise OSError(f"{label} path is not a physical file: {file_path}")
    if os.name != "nt" and require_owner_only and metadata.st_mode & 0o077:
        raise PermissionError(
            f"{label} must be accessible only by its owner: {file_path}"
        )


def stream_opaque_snapshot(
    directory: PinnedDirectory,
    file_path: str,
    label: str,
    *,
    require_owner_only: bool = True,
) -> Optional[OpaqueFileSnapshot]:
    """Hash one no-follow regular file in bounded chunks through a pinned parent."""
    name = directory.name_for(file_path)
    try:
        before = directory.stat_file(name)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise OSError(f"Inspect {label} at {file_path}: {error}") from error
    _require_regular(before, file_path, label, require_owner_only)

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = directory.open_file(name, flags)
        opened = os.fstat(descriptor)
        _require_regular(opened, file_path, label, require_owner_only)
        if not same_file_metadata(opened, before):
            raise OSError(f"{label} changed while opening: {file_path}")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, _HASH_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
        finished = os.fstat(descriptor)
        _require_regular(finished, file_path, label, require_owner_only)
        if not same_file_metadata(finished, opened):
            raise OSError(f"{label} changed while hashing: {file_path}")
    except OSError as error:
        raise OSError(f"Read {label} at {file_path}: {error}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    try:
        visible = directory.stat_file(name)
    except FileNotFoundError as error:
        raise OSError(f"{label} changed while hashing: {file_path}") from error
    _require_regular(visible, file_path, label, require_owner_only)
    if not same_file_metadata(visible, finished):
        raise OSError(f"{label} changed while hashing: {file_path}")
    return OpaqueFileSnapshot(
        finished.st_dev,
        finished.st_ino,
        stat.S_IMODE(finished.st_mode),
        finished.st_size,
        digest.hexdigest(),
    )


__all__ = ["OpaqueFileSnapshot", "stream_opaque_snapshot"]
