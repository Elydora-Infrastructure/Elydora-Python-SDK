"""Identity-bound removal for empty physical directories."""

from __future__ import annotations

import os
import stat
from typing import Any, Optional
from uuid import uuid4

from ._managed_files import DirectorySnapshot, read_physical_directory
from ._pinned_directory import PinnedDirectory
from ._private_artifact import _remove_posix_private_directory


def _mark_windows_directory_for_deletion(directory: PinnedDirectory) -> None:
    import ctypes as ctypes_module
    from ctypes import wintypes
    import msvcrt as msvcrt_module

    ctypes: Any = ctypes_module
    msvcrt: Any = msvcrt_module

    class FileDispositionInformation(ctypes.Structure):
        _fields_ = [("delete_file", wintypes.BOOL)]

    if directory.descriptor is None:
        raise OSError(f"Pinned {directory.label} is closed")
    handle = msvcrt.get_osfhandle(directory.descriptor)
    if handle == -1:
        raise OSError("Directory descriptor has no Windows handle")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    set_information = kernel32.SetFileInformationByHandle
    set_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    set_information.restype = wintypes.BOOL
    disposition = FileDispositionInformation(True)
    if not set_information(
        handle,
        4,
        ctypes.byref(disposition),
        ctypes.sizeof(disposition),
    ):
        error = ctypes.get_last_error()
        raise OSError(
            f"Remove empty {directory.label} at {directory.path}: "
            f"{ctypes.WinError(error)}"
        )


def _rename_posix_into_quarantine(
    source_parent_descriptor: int,
    source_name: str,
    quarantine_descriptor: int,
    source_path: str,
    destination_path: str,
) -> None:
    import ctypes
    import errno

    del source_path, destination_path

    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is not None:
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            source_parent_descriptor,
            os.fsencode(source_name),
            quarantine_descriptor,
            b"entry",
            1,
        )
        if result == 0:
            return
        error = ctypes.get_errno()
        if error not in (errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP):
            raise OSError(error, os.strerror(error), source_name, "entry")
    renameatx = getattr(libc, "renameatx_np", None)
    if renameatx is not None:
        renameatx.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameatx.restype = ctypes.c_int
        result = renameatx(
            source_parent_descriptor,
            os.fsencode(source_name),
            quarantine_descriptor,
            b"entry",
            0x00000004,
        )
        if result == 0:
            return
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), source_name, "entry")
    raise OSError(
        "Host does not support atomic no-replace directory quarantine"
    )


def _create_posix_quarantine(
    parent: PinnedDirectory,
    child_name: str,
) -> PinnedDirectory:
    if parent.descriptor is None:
        raise OSError("Pinned directory is closed")
    quarantine_name = f".{child_name}.{uuid4().hex}.elydora-removed"
    try:
        os.mkdir(quarantine_name, mode=0o700, dir_fd=parent.descriptor)
    except OSError as error:
        raise OSError(
            f"Create private directory quarantine at "
            f"{parent.path_for(quarantine_name)}: {error}"
        ) from error
    metadata = parent.stat_file(quarantine_name)
    if not stat.S_ISDIR(metadata.st_mode):
        raise OSError(
            f"Directory quarantine is not physical: "
            f"{parent.path_for(quarantine_name)}"
        )
    snapshot = DirectorySnapshot(metadata.st_dev, metadata.st_ino)
    return PinnedDirectory.open(
        parent.path_for(quarantine_name),
        "Elydora directory quarantine",
        snapshot,
    )


def _quarantine_posix_directory(
    parent: PinnedDirectory,
    child: PinnedDirectory,
    child_name: str,
) -> None:
    if parent.descriptor is None or child.descriptor is None:
        raise OSError("Pinned directory is closed")
    visible = parent.stat_file(child_name)
    opened = os.fstat(child.descriptor)
    if (
        not stat.S_ISDIR(visible.st_mode)
        or (visible.st_dev, visible.st_ino)
        != (opened.st_dev, opened.st_ino)
    ):
        raise OSError(f"{child.label} changed before quarantine: {child.path}")
    quarantine = _create_posix_quarantine(parent, child_name)
    quarantine_name = parent.name_for(quarantine.path)
    try:
        if quarantine.list_names():
            raise OSError(
                f"Directory quarantine is not empty: {quarantine.path}"
            )
        child.close()
        assert quarantine.descriptor is not None
        _rename_posix_into_quarantine(
            parent.descriptor,
            child_name,
            quarantine.descriptor,
            child.path,
            quarantine.path_for("entry"),
        )
        quarantined = quarantine.stat_file("entry")
        preserved_path = quarantine.path_for("entry")
        if (
            not stat.S_ISDIR(quarantined.st_mode)
            or (quarantined.st_dev, quarantined.st_ino)
            != (opened.st_dev, opened.st_ino)
        ):
            raise OSError(
                f"{child.label} changed while quarantining; preserved at "
                f"{preserved_path}"
            )
        try:
            parent.stat_file(child_name)
        except FileNotFoundError:
            pass
        else:
            raise OSError(
                f"A replacement appeared at {child.path}; original preserved at "
                f"{preserved_path}"
            )
        _remove_posix_private_directory(quarantine.descriptor, "entry")
        quarantine_snapshot = quarantine.snapshot
        quarantine.close()
        current = parent.stat_file(quarantine_name)
        if (
            not stat.S_ISDIR(current.st_mode)
            or (current.st_dev, current.st_ino)
            != (quarantine_snapshot.device, quarantine_snapshot.inode)
        ):
            raise OSError(
                "Directory quarantine changed before cleanup: "
                f"{parent.path_for(quarantine_name)}"
            )
        _remove_posix_private_directory(parent.descriptor, quarantine_name)
    finally:
        if quarantine.descriptor is not None:
            quarantine.close()


def remove_pinned_empty_directory(
    parent: PinnedDirectory,
    child: PinnedDirectory,
    *,
    require_empty: bool = True,
) -> Optional[str]:
    """Remove or quarantine the exact child while both handles stay pinned."""
    if require_empty and child.list_names():
        raise OSError(
            f"{child.label} contains entries after managed cleanup: {child.path}"
        )
    child_name = parent.name_for(child.path)
    parent.assert_path_stable("directory removal")
    child.assert_path_stable("directory removal")
    if os.name == "nt":
        _mark_windows_directory_for_deletion(child)
        child.close()
    else:
        _quarantine_posix_directory(parent, child, child_name)
        parent.assert_path_stable("directory quarantine")
    if read_physical_directory(child.path, child.label) is not None:
        raise OSError(f"{child.label} remained after removal: {child.path}")
    parent.assert_path_stable("directory removal")
    return None
