"""Pinned physical directory handles for transactional file operations."""

from __future__ import annotations

from dataclasses import dataclass
import os
import stat
from typing import Any, Optional, Tuple

from ._managed_files import (
    DirectorySnapshot,
    FileSnapshot,
    _same_file_metadata,
    assert_content_stable,
    read_physical_directory,
)


_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_FILE_ATTRIBUTE_READONLY = 0x00000001
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400


def _close_windows_handle(handle: int) -> None:
    import ctypes as ctypes_module
    from ctypes import wintypes

    ctypes: Any = ctypes_module

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    if not close_handle(handle):
        error = ctypes.get_last_error()
        raise OSError(f"Close Windows handle: {ctypes.WinError(error)}")


def _open_windows_directory(
    directory: str, label: str, delete_access: bool = False
) -> Tuple[int, DirectorySnapshot]:
    import ctypes as ctypes_module
    from ctypes import wintypes
    import msvcrt as msvcrt_module

    ctypes: Any = ctypes_module
    msvcrt: Any = msvcrt_module

    class ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("file_attributes", wintypes.DWORD),
            ("creation_time", wintypes.FILETIME),
            ("last_access_time", wintypes.FILETIME),
            ("last_write_time", wintypes.FILETIME),
            ("volume_serial_number", wintypes.DWORD),
            ("file_size_high", wintypes.DWORD),
            ("file_size_low", wintypes.DWORD),
            ("number_of_links", wintypes.DWORD),
            ("file_index_high", wintypes.DWORD),
            ("file_index_low", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(ByHandleFileInformation),
    ]
    get_information.restype = wintypes.BOOL

    file_list_directory = 0x00000001
    file_read_attributes = 0x00000080
    delete = 0x00010000
    file_share_read = 0x00000001
    file_share_write = 0x00000002
    open_existing = 3
    file_flag_open_reparse_point = 0x00200000
    file_flag_backup_semantics = 0x02000000
    invalid_handle = ctypes.c_void_p(-1).value
    handle = create_file(
        directory,
        file_list_directory
        | file_read_attributes
        | (delete if delete_access else 0),
        file_share_read | file_share_write,
        None,
        open_existing,
        file_flag_open_reparse_point | file_flag_backup_semantics,
        None,
    )
    if handle == invalid_handle:
        error = ctypes.get_last_error()
        raise OSError(f"Open {label} at {directory}: {ctypes.WinError(error)}")
    handle_value = int(handle)
    descriptor = -1
    try:
        information = ByHandleFileInformation()
        if not get_information(handle_value, ctypes.byref(information)):
            error = ctypes.get_last_error()
            raise OSError(
                f"Inspect pinned {label} at {directory}: {ctypes.WinError(error)}"
            )
        attributes = information.file_attributes
        if not attributes & _FILE_ATTRIBUTE_DIRECTORY:
            raise OSError(f"{label} is not a physical directory: {directory}")
        if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise OSError(f"{label} is not a physical directory: {directory}")
        descriptor = msvcrt.open_osfhandle(
            handle_value,
            os.O_RDONLY | getattr(os, "O_NOINHERIT", 0),
        )
        handle_value = 0
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise OSError(f"{label} is not a physical directory: {directory}")
        return descriptor, DirectorySnapshot(metadata.st_dev, metadata.st_ino)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        elif handle_value:
            _close_windows_handle(handle_value)
        raise


def _chmod_windows_descriptor(descriptor: int, mode: int) -> None:
    import ctypes as ctypes_module
    from ctypes import wintypes
    import msvcrt as msvcrt_module

    ctypes: Any = ctypes_module
    msvcrt: Any = msvcrt_module

    class FileBasicInformation(ctypes.Structure):
        _fields_ = [
            ("creation_time", ctypes.c_longlong),
            ("last_access_time", ctypes.c_longlong),
            ("last_write_time", ctypes.c_longlong),
            ("change_time", ctypes.c_longlong),
            ("file_attributes", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_information = kernel32.GetFileInformationByHandleEx
    get_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    get_information.restype = wintypes.BOOL
    set_information = kernel32.SetFileInformationByHandle
    set_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    set_information.restype = wintypes.BOOL

    handle = msvcrt.get_osfhandle(descriptor)
    if handle == -1:
        raise OSError("File descriptor has no Windows handle")
    current = FileBasicInformation()
    file_basic_info = 0
    if not get_information(
        handle,
        file_basic_info,
        ctypes.byref(current),
        ctypes.sizeof(current),
    ):
        error = ctypes.get_last_error()
        raise OSError(f"Inspect open file mode: {ctypes.WinError(error)}")

    attributes = int(current.file_attributes)
    if mode & stat.S_IWRITE:
        attributes &= ~_FILE_ATTRIBUTE_READONLY
        if attributes == 0:
            attributes = _FILE_ATTRIBUTE_NORMAL
    else:
        attributes &= ~_FILE_ATTRIBUTE_NORMAL
        attributes |= _FILE_ATTRIBUTE_READONLY
    if attributes == current.file_attributes:
        return
    update = FileBasicInformation(0, 0, 0, 0, attributes)
    if not set_information(
        handle,
        file_basic_info,
        ctypes.byref(update),
        ctypes.sizeof(update),
    ):
        error = ctypes.get_last_error()
        raise OSError(f"Set open file mode: {ctypes.WinError(error)}")


def chmod_open_file(descriptor: int, mode: int) -> None:
    """Apply a mode to the already-open physical file."""
    if os.name == "nt" and not hasattr(os, "fchmod"):
        _chmod_windows_descriptor(descriptor, mode)
        return
    getattr(os, "fchmod")(descriptor, mode)


@dataclass
class PinnedDirectory:
    """Keep one physical directory stable while path mutations run."""

    path: str
    label: str
    snapshot: DirectorySnapshot
    descriptor: Optional[int] = None
    path_bound: bool = True

    @classmethod
    def open(
        cls,
        directory: str,
        label: str,
        expected: Optional[DirectorySnapshot] = None,
        delete_access: bool = False,
    ) -> "PinnedDirectory":
        normalized = os.path.abspath(directory)
        before = read_physical_directory(normalized, label)
        if before is None:
            raise OSError(f"{label} is missing: {normalized}")
        if expected is not None and before != expected:
            raise OSError(f"{label} changed before pinning: {normalized}")

        descriptor: Optional[int] = None
        try:
            if os.name == "nt":
                if delete_access:
                    descriptor, opened = _open_windows_directory(
                        normalized, label, True
                    )
                else:
                    descriptor, opened = _open_windows_directory(
                        normalized, label
                    )
                if opened != before:
                    raise OSError(f"{label} changed while pinning: {normalized}")
            else:
                flags = (
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                descriptor = os.open(normalized, flags)
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or (metadata.st_dev, metadata.st_ino)
                    != (before.device, before.inode)
                ):
                    raise OSError(f"{label} changed while pinning: {normalized}")
            after = read_physical_directory(normalized, label)
            if after != before:
                raise OSError(f"{label} changed while pinning: {normalized}")
            return cls(normalized, label, before, descriptor)
        except Exception:
            if descriptor is not None:
                os.close(descriptor)
            raise

    def close(self) -> None:
        failures = []
        if self.descriptor is not None:
            try:
                os.close(self.descriptor)
            except OSError as error:
                failures.append(str(error))
            self.descriptor = None
        if failures:
            raise OSError(f"Close {self.label}: {'; '.join(failures)}")

    def _require_open(self) -> None:
        if self.descriptor is None:
            raise OSError(f"Pinned {self.label} is closed")

    def assert_path_stable(self, operation: str = "transaction") -> None:
        """Require the visible path to still name the pinned directory."""
        self._require_open()
        assert self.descriptor is not None
        metadata = os.fstat(self.descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino)
            != (self.snapshot.device, self.snapshot.inode)
        ):
            raise OSError(f"Pinned {self.label} changed during {operation}")
        if not self.path_bound:
            return
        current = read_physical_directory(self.path, self.label)
        if current != self.snapshot:
            raise OSError(
                f"{self.label} changed during {operation}: {self.path}"
            )

    def chmod_descriptor(self, descriptor: int, mode: int) -> None:
        """Apply a mode while this directory remains pinned."""
        self._require_open()
        chmod_open_file(descriptor, mode)

    def name_for(self, file_path: str) -> str:
        absolute = os.path.abspath(file_path)
        if os.path.normcase(os.path.dirname(absolute)) != os.path.normcase(self.path):
            raise ValueError(f"File is outside pinned {self.label}: {file_path}")
        name = os.path.basename(absolute)
        if not name or name in {".", ".."}:
            raise ValueError(f"Invalid file name in pinned {self.label}: {file_path}")
        return name

    def path_for(self, name: str) -> str:
        if not name or name in {".", ".."} or os.path.basename(name) != name:
            raise ValueError(f"Invalid file name in pinned {self.label}: {name}")
        return os.path.join(self.path, name)

    def list_names(self) -> list[str]:
        """List direct entries while retaining the physical directory handle."""
        self._require_open()
        self.assert_path_stable("directory enumeration")
        try:
            if os.name == "nt":
                names = os.listdir(self.path)
            else:
                assert self.descriptor is not None
                names = os.listdir(self.descriptor)
        except OSError as error:
            raise OSError(f"List {self.label} at {self.path}: {error}") from error
        self.assert_path_stable("directory enumeration")
        return sorted(names)

    def open_file(self, name: str, flags: int, mode: int = 0o600) -> int:
        self._require_open()
        if os.name == "nt":
            return os.open(self.path_for(name), flags, mode)
        assert self.descriptor is not None
        return os.open(name, flags, mode, dir_fd=self.descriptor)

    def stat_file(self, name: str) -> os.stat_result:
        self._require_open()
        if os.name == "nt":
            return os.lstat(self.path_for(name))
        assert self.descriptor is not None
        return os.stat(name, dir_fd=self.descriptor, follow_symlinks=False)

    def remove_file(self, name: str) -> None:
        self._require_open()
        if os.name == "nt":
            os.remove(self.path_for(name))
            return
        assert self.descriptor is not None
        os.unlink(name, dir_fd=self.descriptor)

    def replace_file(self, source_name: str, destination_name: str) -> None:
        self._require_open()
        if os.name == "nt":
            os.replace(self.path_for(source_name), self.path_for(destination_name))
            return
        assert self.descriptor is not None
        os.replace(
            source_name,
            destination_name,
            src_dir_fd=self.descriptor,
            dst_dir_fd=self.descriptor,
        )

    def sync(self) -> None:
        """Persist directory entries where the host exposes directory fsync."""
        self._require_open()
        if os.name == "nt":
            # NTFS journals atomic rename metadata. Windows directory handles do
            # not support FlushFileBuffers, while every staged file is flushed.
            return
        if os.name != "posix":
            raise OSError(f"Unsupported transaction platform: {os.name}")
        assert self.descriptor is not None
        os.fsync(self.descriptor)

    def link_file(self, source_name: str, destination_name: str) -> None:
        """Create a no-clobber hard link within the pinned directory."""
        self._require_open()
        if os.name == "nt":
            os.link(self.path_for(source_name), self.path_for(destination_name))
            return
        assert self.descriptor is not None
        os.link(
            source_name,
            destination_name,
            src_dir_fd=self.descriptor,
            dst_dir_fd=self.descriptor,
            follow_symlinks=False,
        )

    def read_file(
        self,
        name: str,
        label: str,
        maximum_bytes: int,
    ) -> Optional[FileSnapshot]:
        try:
            before = self.stat_file(name)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise OSError(f"Inspect {label} at {self.path_for(name)}: {error}") from error
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
            raise OSError(f"{label} path is not a physical file: {self.path_for(name)}")
        if before.st_size > maximum_bytes:
            raise ValueError(
                f"{label} exceeds {maximum_bytes} bytes: {self.path_for(name)}"
            )

        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        try:
            descriptor = self.open_file(name, flags)
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or not _same_file_metadata(
                before,
                opened,
            ):
                raise OSError(f"{label} changed while opening: {self.path_for(name)}")
            if opened.st_size > maximum_bytes:
                raise ValueError(
                    f"{label} exceeds {maximum_bytes} bytes: {self.path_for(name)}"
                )
            with os.fdopen(descriptor, "rb") as file:
                descriptor = -1
                raw = file.read(maximum_bytes + 1)
                finished = os.fstat(file.fileno())
            if not _same_file_metadata(finished, opened):
                raise OSError(
                    f"{label} changed while reading: {self.path_for(name)}"
                )
            assert_content_stable(
                lambda: self.open_file(name, flags),
                self.path_for(name),
                label,
                opened,
                raw,
                maximum_bytes,
            )
        except OSError as error:
            raise OSError(f"Read {label} at {self.path_for(name)}: {error}") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)

        if len(raw) > maximum_bytes:
            raise ValueError(
                f"{label} exceeds {maximum_bytes} bytes: {self.path_for(name)}"
            )
        try:
            contents = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(
                f"{label} at {self.path_for(name)} must contain UTF-8 text"
            ) from error
        return FileSnapshot(
            contents,
            opened.st_dev,
            opened.st_ino,
            stat.S_IMODE(opened.st_mode),
        )

    def chmod_file(
        self,
        name: str,
        mode: int,
        expected_identity: Tuple[int, int],
    ) -> None:
        flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        try:
            descriptor = self.open_file(name, flags)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or (metadata.st_dev, metadata.st_ino) != expected_identity
            ):
                raise OSError(f"File changed before chmod: {self.path_for(name)}")
            chmod_open_file(descriptor, mode)
            os.fsync(descriptor)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
