"""Physical file and directory primitives for managed hook state."""

from __future__ import annotations

from dataclasses import dataclass
import os
import stat
from typing import Callable, Optional


MAX_SECRET_BYTES = 64 * 1024
MAX_CONFIG_BYTES = 512 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class FileSnapshot:
    contents: str
    device: int
    inode: int
    mode: int


@dataclass(frozen=True)
class DirectorySnapshot:
    device: int
    inode: int


def identity_mode_bits(mode: int) -> int:
    """Windows synthesizes mode bits, so they are not identity there."""
    return mode if os.name != "nt" else 0


def portable_file_mode(metadata: os.stat_result) -> int:
    """Return the identity-relevant permission bits for one stat result."""
    return identity_mode_bits(stat.S_IMODE(metadata.st_mode))


def stable_file_metadata(metadata: os.stat_result) -> tuple[int, int, int, int]:
    """Identity without timestamps; Windows file times lag across handles."""
    return (
        metadata.st_dev,
        metadata.st_ino,
        portable_file_mode(metadata),
        metadata.st_size,
    )


def same_file_metadata(first: os.stat_result, second: os.stat_result) -> bool:
    return stable_file_metadata(first) == stable_file_metadata(second)


def assert_content_stable(
    opener: Callable[[], int],
    file_path: str,
    label: str,
    expected: os.stat_result,
    raw: bytes,
    maximum_bytes: int,
) -> None:
    """Re-read the file and require identical identity and bytes."""
    descriptor = opener()
    try:
        current = os.fstat(descriptor)
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_dev != expected.st_dev
            or current.st_ino != expected.st_ino
        ):
            raise OSError(f"{label} changed while reading: {file_path}")
        with os.fdopen(descriptor, "rb") as file:
            descriptor = -1
            reread = file.read(maximum_bytes + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if reread != raw:
        raise OSError(f"{label} changed while reading: {file_path}")


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


def read_file_snapshot(
    before: os.stat_result,
    opener: Callable[[int], int],
    file_path: str,
    label: str,
    maximum_bytes: int,
) -> FileSnapshot:
    """Read one regular file through opener and prove it stayed stable."""
    if before.st_size > maximum_bytes:
        raise ValueError(f"{label} exceeds {maximum_bytes} bytes: {file_path}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = opener(flags)
        after = os.fstat(descriptor)
        if not stat.S_ISREG(after.st_mode):
            raise OSError(f"{label} path is not a physical file: {file_path}")
        if not same_file_metadata(before, after):
            raise OSError(f"{label} changed while opening: {file_path}")
        if after.st_size > maximum_bytes:
            raise ValueError(f"{label} exceeds {maximum_bytes} bytes: {file_path}")
        with os.fdopen(descriptor, "rb") as file:
            descriptor = -1
            raw = file.read(maximum_bytes + 1)
            finished = os.fstat(file.fileno())
        if not same_file_metadata(finished, after):
            raise OSError(f"{label} changed while reading: {file_path}")
        assert_content_stable(
            lambda: opener(flags), file_path, label, after, raw, maximum_bytes
        )
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
    return FileSnapshot(contents, after.st_dev, after.st_ino, stat.S_IMODE(after.st_mode))


def read_physical_file(
    file_path: str,
    label: str,
    maximum_bytes: int = MAX_SOURCE_BYTES,
) -> Optional[FileSnapshot]:
    before = _inspect_regular_file(file_path, label)
    if before is None:
        return None
    return read_file_snapshot(
        before, lambda flags: os.open(file_path, flags), file_path, label, maximum_bytes
    )


def physical_file_exists(file_path: str, label: str) -> bool:
    return _inspect_regular_file(file_path, label) is not None


def read_physical_directory(
    directory: str, label: str
) -> Optional[DirectorySnapshot]:
    try:
        metadata = os.lstat(directory)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise OSError(f"Inspect {label} at {directory}: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise OSError(f"{label} is not a physical directory: {directory}")
    return DirectorySnapshot(metadata.st_dev, metadata.st_ino)


def physical_directory_exists(directory: str, label: str) -> bool:
    return read_physical_directory(directory, label) is not None


def ensure_physical_directory(directory: str, label: str) -> None:
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    except OSError as error:
        raise OSError(f"Prepare {label} at {directory}: {error}") from error
    if not physical_directory_exists(directory, label):
        raise OSError(f"{label} is missing: {directory}")
