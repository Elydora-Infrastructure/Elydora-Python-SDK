"""Physical file and directory primitives for managed hook state."""

from __future__ import annotations

from dataclasses import dataclass
import os
import stat
from typing import Optional


MAX_SECRET_BYTES = 64 * 1024
MAX_CONFIG_BYTES = 512 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class FileSnapshot:
    contents: str
    device: int
    inode: int
    mode: int


def _inspect_regular_file(file_path: str, label: str) -> Optional[os.stat_result]:
    try:
        metadata = os.lstat(file_path)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise OSError(f"Inspect {label} at {file_path}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise OSError(f"{label} path is not a physical file: {file_path}")
    return metadata


def read_physical_file(
    file_path: str,
    label: str,
    maximum_bytes: int = MAX_SOURCE_BYTES,
) -> Optional[FileSnapshot]:
    before = _inspect_regular_file(file_path, label)
    if before is None:
        return None
    if before.st_size > maximum_bytes:
        raise ValueError(f"{label} exceeds {maximum_bytes} bytes: {file_path}")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(file_path, flags)
        after = os.fstat(descriptor)
        if not stat.S_ISREG(after.st_mode):
            raise OSError(f"{label} path is not a physical file: {file_path}")
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise OSError(f"{label} changed while opening: {file_path}")
        if after.st_size > maximum_bytes:
            raise ValueError(f"{label} exceeds {maximum_bytes} bytes: {file_path}")
        with os.fdopen(descriptor, "rb") as file:
            descriptor = -1
            raw = file.read(maximum_bytes + 1)
    except OSError as error:
        raise OSError(f"Read {label} at {file_path}: {error}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    if len(raw) > maximum_bytes:
        raise ValueError(f"{label} exceeds {maximum_bytes} bytes: {file_path}")
    try:
        contents = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{label} at {file_path} must contain UTF-8 text") from error
    return FileSnapshot(
        contents=contents,
        device=after.st_dev,
        inode=after.st_ino,
        mode=stat.S_IMODE(after.st_mode),
    )


def physical_file_exists(file_path: str, label: str) -> bool:
    return _inspect_regular_file(file_path, label) is not None


def physical_directory_exists(directory: str, label: str) -> bool:
    try:
        metadata = os.lstat(directory)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise OSError(f"Inspect {label} at {directory}: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise OSError(f"{label} is not a physical directory: {directory}")
    return True


def ensure_physical_directory(directory: str, label: str) -> None:
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    except OSError as error:
        raise OSError(f"Prepare {label} at {directory}: {error}") from error
    if not physical_directory_exists(directory, label):
        raise OSError(f"{label} is missing: {directory}")
