"""Windows owner-only security boundary for durable transaction state."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from typing import Any, Tuple


_kernel32: Any = ctypes.WinDLL("kernel32", use_last_error=True)
_advapi32: Any = ctypes.WinDLL("advapi32", use_last_error=True)

_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_ERROR_ALREADY_EXISTS = 183
_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1
_SE_FILE_OBJECT = 1
_OWNER_SECURITY_INFORMATION = 0x00000001
_DACL_SECURITY_INFORMATION = 0x00000004
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_SE_DACL_PROTECTED = 0x1000
_ACL_SIZE_INFORMATION_CLASS = 2
_ACCESS_ALLOWED_ACE_TYPE = 0
_OBJECT_INHERIT_ACE = 0x01
_CONTAINER_INHERIT_ACE = 0x02
_FILE_ALL_ACCESS = 0x001F01FF
_SDDL_REVISION_1 = 1
_READ_CONTROL = 0x00020000
_WRITE_DAC = 0x00040000
_FILE_READ_ATTRIBUTES = 0x0080
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_OPEN_EXISTING = 3
_OPEN_ALWAYS = 4
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_TYPE_DISK = 1


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", wintypes.LPVOID),
        ("bInheritHandle", wintypes.BOOL),
    ]


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("Sid", wintypes.LPVOID), ("Attributes", wintypes.DWORD)]


class _TokenUser(ctypes.Structure):
    _fields_ = [("User", _SidAndAttributes)]


class _AclSizeInformation(ctypes.Structure):
    _fields_ = [
        ("AceCount", wintypes.DWORD),
        ("AclBytesInUse", wintypes.DWORD),
        ("AclBytesFree", wintypes.DWORD),
    ]


class _AceHeader(ctypes.Structure):
    _fields_ = [
        ("AceType", wintypes.BYTE),
        ("AceFlags", wintypes.BYTE),
        ("AceSize", wintypes.WORD),
    ]


class _AccessAllowedAce(ctypes.Structure):
    _fields_ = [
        ("Header", _AceHeader),
        ("Mask", wintypes.DWORD),
        ("SidStart", wintypes.DWORD),
    ]


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", wintypes.FILETIME),
        ("ftLastAccessTime", wintypes.FILETIME),
        ("ftLastWriteTime", wintypes.FILETIME),
        ("dwVolumeSerialNumber", wintypes.DWORD),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("nNumberOfLinks", wintypes.DWORD),
        ("nFileIndexHigh", wintypes.DWORD),
        ("nFileIndexLow", wintypes.DWORD),
    ]


def _declare(function: Any, arguments: list[Any], result: Any) -> None:
    function.argtypes = arguments
    function.restype = result


_declare(_kernel32.GetCurrentProcess, [], wintypes.HANDLE)
_declare(_advapi32.OpenProcessToken, [wintypes.HANDLE, wintypes.DWORD,
         ctypes.POINTER(wintypes.HANDLE)], wintypes.BOOL)
_declare(_advapi32.GetTokenInformation,
         [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
          ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL)
_declare(_advapi32.GetLengthSid, [wintypes.LPVOID], wintypes.DWORD)
_declare(_advapi32.CopySid,
         [wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID], wintypes.BOOL)
_declare(_advapi32.ConvertSidToStringSidW,
         [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)], wintypes.BOOL)
_declare(_advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW,
         [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID),
          ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL)
_declare(_advapi32.GetSecurityDescriptorDacl,
         [wintypes.LPVOID, ctypes.POINTER(wintypes.BOOL),
          ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.BOOL)],
         wintypes.BOOL)
_declare(_advapi32.GetSecurityDescriptorControl,
         [wintypes.LPVOID, ctypes.POINTER(wintypes.WORD),
          ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL)
_declare(
    _advapi32.GetSecurityInfo,
    [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD,
     ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID),
     ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID),
     ctypes.POINTER(wintypes.LPVOID)],
    wintypes.DWORD,
)
_declare(
    _advapi32.SetSecurityInfo,
    [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, wintypes.LPVOID,
     wintypes.LPVOID, wintypes.LPVOID, wintypes.LPVOID],
    wintypes.DWORD,
)
_declare(_advapi32.GetAclInformation,
         [wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.c_int],
         wintypes.BOOL)
_declare(_advapi32.GetAce,
         [wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID)],
         wintypes.BOOL)
_declare(_advapi32.EqualSid, [wintypes.LPVOID, wintypes.LPVOID], wintypes.BOOL)
_declare(_kernel32.LocalFree, [wintypes.HLOCAL], wintypes.HLOCAL)
_declare(_kernel32.CloseHandle, [wintypes.HANDLE], wintypes.BOOL)
_declare(_kernel32.CreateDirectoryW,
         [wintypes.LPCWSTR, ctypes.POINTER(_SecurityAttributes)], wintypes.BOOL)
_declare(_kernel32.CreateFileW,
         [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
          ctypes.POINTER(_SecurityAttributes), wintypes.DWORD, wintypes.DWORD,
          wintypes.HANDLE], wintypes.HANDLE)
_declare(_kernel32.GetFileType, [wintypes.HANDLE], wintypes.DWORD)
_declare(_kernel32.GetFileInformationByHandle,
         [wintypes.HANDLE, ctypes.POINTER(_ByHandleFileInformation)], wintypes.BOOL)


def _winerror(action: str, code: int | None = None) -> OSError:
    error = ctypes.get_last_error() if code is None else code
    return OSError(f"{action}: {ctypes.WinError(error)}")


def close_handle(handle: int) -> None:
    if not _kernel32.CloseHandle(handle):
        raise _winerror("Close transaction state handle")


def _current_user_sid() -> Tuple[Any, str]:
    token = wintypes.HANDLE()
    if not _advapi32.OpenProcessToken(
        _kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)
    ):
        raise _winerror("Open current process token")
    try:
        required = wintypes.DWORD()
        _advapi32.GetTokenInformation(
            token, _TOKEN_USER, None, 0, ctypes.byref(required)
        )
        token_data = ctypes.create_string_buffer(required.value)
        if not _advapi32.GetTokenInformation(
            token,
            _TOKEN_USER,
            token_data,
            required,
            ctypes.byref(required),
        ):
            raise _winerror("Read current process token")
        sid = ctypes.cast(token_data, ctypes.POINTER(_TokenUser)).contents.User.Sid
        sid_length = _advapi32.GetLengthSid(sid)
        if not sid_length:
            raise _winerror("Measure current user SID")
        sid_copy = ctypes.create_string_buffer(sid_length)
        if not _advapi32.CopySid(sid_length, sid_copy, sid):
            raise _winerror("Copy current user SID")
        sid_text = wintypes.LPWSTR()
        if not _advapi32.ConvertSidToStringSidW(sid_copy, ctypes.byref(sid_text)):
            raise _winerror("Format current user SID")
        try:
            sid_string = sid_text.value
            if sid_string is None:
                raise OSError("Current user SID string is unavailable")
            return sid_copy, sid_string
        finally:
            _kernel32.LocalFree(sid_text)
    finally:
        token_value = token.value
        if token_value is not None:
            close_handle(int(token_value))


def _security_descriptor(directory: bool) -> Tuple[int, int]:
    _sid, sid_text = _current_user_sid()
    inheritance = "OICI" if directory else ""
    descriptor = wintypes.LPVOID()
    sddl = f"O:{sid_text}D:P(A;{inheritance};FA;;;{sid_text})"
    if not _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        _SDDL_REVISION_1,
        ctypes.byref(descriptor),
        None,
    ):
        raise _winerror("Build transaction security descriptor")
    present = wintypes.BOOL()
    defaulted = wintypes.BOOL()
    dacl = wintypes.LPVOID()
    if not _advapi32.GetSecurityDescriptorDacl(
        descriptor,
        ctypes.byref(present),
        ctypes.byref(dacl),
        ctypes.byref(defaulted),
    ):
        _kernel32.LocalFree(descriptor)
        raise _winerror("Read transaction security descriptor")
    if not present.value or not dacl.value:
        _kernel32.LocalFree(descriptor)
        raise OSError("Transaction security descriptor has no DACL")
    descriptor_value = descriptor.value
    dacl_value = dacl.value
    if descriptor_value is None or dacl_value is None:
        _kernel32.LocalFree(descriptor)
        raise OSError("Transaction security descriptor has no DACL")
    return int(descriptor_value), int(dacl_value)


def _file_information(handle: int, directory: bool) -> _ByHandleFileInformation:
    if _kernel32.GetFileType(handle) != _FILE_TYPE_DISK:
        raise OSError("Transaction state path is not a disk file")
    information = _ByHandleFileInformation()
    if not _kernel32.GetFileInformationByHandle(handle, ctypes.byref(information)):
        raise _winerror("Inspect transaction state path")
    attributes = information.dwFileAttributes
    expected_directory = bool(attributes & _FILE_ATTRIBUTE_DIRECTORY)
    if attributes & _FILE_ATTRIBUTE_REPARSE_POINT or expected_directory != directory:
        kind = "directory" if directory else "file"
        raise OSError(f"Transaction state path is not a physical {kind}")
    return information


def _identity(information: _ByHandleFileInformation) -> Tuple[int, int, int]:
    return (
        int(information.dwVolumeSerialNumber),
        int(information.nFileIndexHigh),
        int(information.nFileIndexLow),
    )


def _open_path(
    path: str,
    directory: bool,
    access: int,
    disposition: int,
    security: _SecurityAttributes | None = None,
) -> int:
    flags = _FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        flags |= _FILE_FLAG_BACKUP_SEMANTICS
    else:
        flags |= _FILE_ATTRIBUTE_NORMAL
    security_pointer = None if security is None else ctypes.byref(security)
    handle = _kernel32.CreateFileW(
        path,
        access,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE,
        security_pointer,
        disposition,
        flags,
        None,
    )
    if int(handle) == _INVALID_HANDLE_VALUE:
        raise _winerror("Open transaction state path")
    return int(handle)


def _verify_owner_and_dacl(handle: int, directory: bool) -> None:
    current_sid, _sid_text = _current_user_sid()
    owner = wintypes.LPVOID()
    dacl = wintypes.LPVOID()
    descriptor = wintypes.LPVOID()
    result = _advapi32.GetSecurityInfo(
        handle,
        _SE_FILE_OBJECT,
        _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if result:
        raise _winerror("Read transaction state security", int(result))
    try:
        if not owner.value or not _advapi32.EqualSid(owner, current_sid):
            raise PermissionError("Transaction state path is not owned by current user")
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not _advapi32.GetSecurityDescriptorControl(
            descriptor, ctypes.byref(control), ctypes.byref(revision)
        ):
            raise _winerror("Read transaction DACL control")
        if not control.value & _SE_DACL_PROTECTED or not dacl.value:
            raise PermissionError("Transaction state DACL is not protected owner-only")
        size = _AclSizeInformation()
        if not _advapi32.GetAclInformation(
            dacl,
            ctypes.byref(size),
            ctypes.sizeof(size),
            _ACL_SIZE_INFORMATION_CLASS,
        ):
            raise _winerror("Inspect transaction DACL")
        if size.AceCount != 1:
            raise PermissionError("Transaction state DACL is not protected owner-only")
        ace_pointer = wintypes.LPVOID()
        if not _advapi32.GetAce(dacl, 0, ctypes.byref(ace_pointer)):
            raise _winerror("Read transaction DACL entry")
        ace = ctypes.cast(ace_pointer, ctypes.POINTER(_AccessAllowedAce)).contents
        expected_flags = (
            _OBJECT_INHERIT_ACE | _CONTAINER_INHERIT_ACE if directory else 0
        )
        ace_address = ace_pointer.value
        if ace_address is None:
            raise OSError("Transaction DACL entry is unavailable")
        sid_pointer = ctypes.c_void_p(
            int(ace_address) + _AccessAllowedAce.SidStart.offset
        )
        if (
            ace.Header.AceType != _ACCESS_ALLOWED_ACE_TYPE
            or ace.Header.AceFlags != expected_flags
            or ace.Mask != _FILE_ALL_ACCESS
            or not _advapi32.EqualSid(sid_pointer, current_sid)
        ):
            raise PermissionError("Transaction state DACL is not protected owner-only")
    finally:
        _kernel32.LocalFree(descriptor)


def _apply_private_dacl(handle: int, directory: bool) -> None:
    current_sid, _sid_text = _current_user_sid()
    owner = wintypes.LPVOID()
    descriptor = wintypes.LPVOID()
    result = _advapi32.GetSecurityInfo(
        handle,
        _SE_FILE_OBJECT,
        _OWNER_SECURITY_INFORMATION,
        ctypes.byref(owner),
        None,
        None,
        None,
        ctypes.byref(descriptor),
    )
    if result:
        raise _winerror("Read transaction state owner", int(result))
    try:
        if not owner.value or not _advapi32.EqualSid(owner, current_sid):
            raise PermissionError("Transaction state path is not owned by current user")
    finally:
        _kernel32.LocalFree(descriptor)

    security_descriptor, dacl = _security_descriptor(directory)
    try:
        result = _advapi32.SetSecurityInfo(
            handle,
            _SE_FILE_OBJECT,
            _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            dacl,
            None,
        )
        if result:
            raise _winerror("Protect transaction state DACL", int(result))
    finally:
        _kernel32.LocalFree(security_descriptor)
    _verify_owner_and_dacl(handle, directory)


def _verify_path_identity(path: str, handle: int, directory: bool) -> None:
    expected = _identity(_file_information(handle, directory))
    visible = _open_path(
        path,
        directory,
        _READ_CONTROL | _FILE_READ_ATTRIBUTES,
        _OPEN_EXISTING,
    )
    try:
        if _identity(_file_information(visible, directory)) != expected:
            raise OSError("Transaction state path changed while opening")
    finally:
        close_handle(visible)


def ensure_private_directory(path: str) -> None:
    """Create or harden one physical current-user transaction directory."""
    descriptor, _dacl = _security_descriptor(True)
    security = _SecurityAttributes(
        ctypes.sizeof(_SecurityAttributes),
        descriptor,
        False,
    )
    try:
        if not _kernel32.CreateDirectoryW(path, ctypes.byref(security)):
            error = ctypes.get_last_error()
            if error != _ERROR_ALREADY_EXISTS:
                raise _winerror("Create transaction state directory", error)
    finally:
        _kernel32.LocalFree(descriptor)
    handle = _open_path(
        path,
        True,
        _READ_CONTROL | _WRITE_DAC | _FILE_READ_ATTRIBUTES,
        _OPEN_EXISTING,
    )
    try:
        _file_information(handle, True)
        _apply_private_dacl(handle, True)
        _verify_path_identity(path, handle, True)
    finally:
        close_handle(handle)


def open_private_file(path: str) -> int:
    """Open one physical current-user file with a protected owner-only DACL."""
    descriptor, _dacl = _security_descriptor(False)
    security = _SecurityAttributes(
        ctypes.sizeof(_SecurityAttributes),
        descriptor,
        False,
    )
    try:
        handle = _open_path(
            path,
            False,
            _GENERIC_READ | _GENERIC_WRITE | _READ_CONTROL | _WRITE_DAC,
            _OPEN_ALWAYS,
            security,
        )
    finally:
        _kernel32.LocalFree(descriptor)
    try:
        _file_information(handle, False)
        _apply_private_dacl(handle, False)
        _verify_path_identity(path, handle, False)
    except Exception:
        close_handle(handle)
        raise
    return handle


def verify_private_path(path: str, *, directory: bool) -> None:
    """Verify a physical current-user path has the exact private DACL contract."""
    handle = _open_path(
        path,
        directory,
        _READ_CONTROL | _FILE_READ_ATTRIBUTES,
        _OPEN_EXISTING,
    )
    try:
        _file_information(handle, directory)
        _verify_owner_and_dacl(handle, directory)
        _verify_path_identity(path, handle, directory)
    finally:
        close_handle(handle)


__all__ = [
    "close_handle",
    "ensure_private_directory",
    "open_private_file",
    "verify_private_path",
]
