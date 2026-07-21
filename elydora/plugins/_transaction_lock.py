"""Cross-process serialization for durable provider transactions."""

from __future__ import annotations

from contextlib import AbstractContextManager
import errno
import os
import stat
from types import TracebackType
from typing import Any, Optional, Type

from elydora._runtime_paths import (
    ensure_private_directory as ensure_private_parent_directory,
    runtime_root,
)


def _effective_uid() -> int:
    getter: Any = getattr(os, "geteuid", None)
    if getter is None:
        raise OSError("Effective user identity is unavailable")
    return int(getter())


def _ensure_private_posix_directory(path: str) -> None:
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise OSError(
                f"Transaction state path is not a physical directory: {path}"
            ) from error
        raise
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise OSError(
                f"Transaction state path is not a physical directory: {path}"
            )
        if metadata.st_uid != _effective_uid():
            raise PermissionError(
                f"Transaction state directory is not owned by the current user: {path}"
            )
        os.fchmod(descriptor, 0o700)
        secured = os.fstat(descriptor)
        visible = os.lstat(path)
        if (
            not stat.S_ISDIR(visible.st_mode)
            or stat.S_ISLNK(visible.st_mode)
            or visible.st_dev != secured.st_dev
            or visible.st_ino != secured.st_ino
        ):
            raise OSError(
                f"Transaction state path is not a physical directory: {path}"
            )
        if stat.S_IMODE(secured.st_mode) != 0o700:
            raise PermissionError(
                f"Transaction state directory must be owner-only: {path}"
            )
    finally:
        os.close(descriptor)


def transaction_state_path() -> str:
    """Return the transaction state directory path without touching the filesystem."""
    return os.path.join(runtime_root(), "transactions")


def transaction_state_directory() -> str:
    """Return the private per-user state directory inside the Elydora runtime root.

    The journal must share fate with the runtimes it repairs, so it lives next
    to the managed agent directories under ``~/.elydora`` rather than in a
    volatile location such as the system temporary directory.
    """
    root = runtime_root()
    state = transaction_state_path()
    parent = os.path.dirname(root)
    if not os.path.lexists(parent):
        ensure_private_parent_directory(parent)
    if os.name == "nt":
        from ._windows_security import ensure_private_directory

        ensure_private_directory(root)
        ensure_private_directory(state)
        return state
    if os.name != "posix":
        raise OSError(f"Unsupported transaction platform: {os.name}")
    _ensure_private_posix_directory(root)
    _ensure_private_posix_directory(state)
    return state


class _WindowsFileLock(AbstractContextManager["_WindowsFileLock"]):
    def __init__(self) -> None:
        self._handle = 0
        self._overlapped: Any = None

    def __enter__(self) -> "_WindowsFileLock":
        import ctypes as ctypes_module
        from ctypes import wintypes

        ctypes: Any = ctypes_module
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        from ._windows_security import close_handle, open_private_file

        class Overlapped(ctypes.Structure):
            _fields_ = [
                ("Internal", ctypes.c_void_p),
                ("InternalHigh", ctypes.c_void_p),
                ("Offset", wintypes.DWORD),
                ("OffsetHigh", wintypes.DWORD),
                ("hEvent", wintypes.HANDLE),
            ]

        lock = kernel32.LockFileEx
        lock.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(Overlapped),
        ]
        lock.restype = wintypes.BOOL
        path = os.path.join(transaction_state_directory(), "transaction.lock")
        handle = open_private_file(path)
        overlapped = Overlapped()
        if not lock(handle, 0x00000002, 0, 1, 0, ctypes.byref(overlapped)):
            error = ctypes.get_last_error()
            close_handle(handle)
            raise OSError(f"Lock transaction file: {ctypes.WinError(error)}")
        self._handle = handle
        self._overlapped = overlapped
        return self

    def _close(self) -> None:
        if not self._handle:
            return
        from ._windows_security import close_handle

        handle = self._handle
        self._handle = 0
        self._overlapped = None
        close_handle(handle)

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        del exc_type, exc_value, traceback
        import ctypes as ctypes_module
        from ctypes import wintypes

        ctypes: Any = ctypes_module
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        unlock = kernel32.UnlockFileEx
        unlock.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
        ]
        unlock.restype = wintypes.BOOL
        unlock_error: Optional[OSError] = None
        if self._handle and not unlock(
            self._handle,
            0,
            1,
            0,
            ctypes.byref(self._overlapped),
        ):
            error = ctypes.get_last_error()
            unlock_error = OSError(
                f"Unlock transaction file: {ctypes.WinError(error)}"
            )
        self._close()
        if unlock_error is not None:
            raise unlock_error


class _PosixLock(AbstractContextManager["_PosixLock"]):
    def __init__(self) -> None:
        self._descriptor = -1

    def __enter__(self) -> "_PosixLock":
        import fcntl as fcntl_module

        fcntl: Any = fcntl_module

        path = os.path.join(transaction_state_directory(), "transaction.lock")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise OSError(
                    f"Transaction lock is not a physical file: {path}"
                ) from error
            raise
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise OSError(f"Transaction lock is not a physical file: {path}")
            if metadata.st_uid != _effective_uid():
                raise PermissionError(
                    f"Transaction lock is not owned by the current user: {path}"
                )
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            visible = os.lstat(path)
            if (
                not stat.S_ISREG(visible.st_mode)
                or stat.S_ISLNK(visible.st_mode)
                or visible.st_dev != metadata.st_dev
                or visible.st_ino != metadata.st_ino
            ):
                raise OSError(f"Transaction lock is not a physical file: {path}")
            if visible.st_uid != _effective_uid():
                raise PermissionError(
                    f"Transaction lock is not owned by the current user: {path}"
                )
            if stat.S_IMODE(visible.st_mode) != 0o600:
                raise PermissionError(f"Transaction lock must be owner-only: {path}")
        except Exception:
            os.close(descriptor)
            raise
        self._descriptor = descriptor
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        del exc_type, exc_value, traceback
        import fcntl as fcntl_module

        fcntl: Any = fcntl_module

        descriptor = self._descriptor
        self._descriptor = -1
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def serialized_transactions() -> AbstractContextManager[Any]:
    if os.name == "nt":
        return _WindowsFileLock()
    if os.name == "posix":
        return _PosixLock()
    raise OSError(f"Unsupported transaction platform: {os.name}")


__all__ = [
    "serialized_transactions",
    "transaction_state_directory",
    "transaction_state_path",
]
