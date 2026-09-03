"""Shell quoting and parsing for generated hook commands."""

from __future__ import annotations

import base64
import ntpath
import os
import re
import sys
from typing import Optional, Tuple

CommandParts = Tuple[str, str]
POWERSHELL_EXIT_SUFFIX = "; exit $LASTEXITCODE"
_POSIX_APOSTROPHE = "'\"'\"'"
_ENCODED_COMMAND = re.compile(
    r'"([^"\r\n]+)" -NoLogo -NoProfile -NonInteractive '
    r"-EncodedCommand ([A-Za-z0-9+/]+={0,2})"
)
_PYTHON_EXECUTABLE = re.compile(
    r"(?:python(?:[0-9]+(?:\.[0-9]+)*)?[td]?|pypy(?:[0-9]+(?:\.[0-9]+)*)?)(?:\.exe)?",
    re.IGNORECASE,
)


def quote_posix(value: str) -> str:
    return "'" + value.replace("'", _POSIX_APOSTROPHE) + "'"


def quote_powershell(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def posix_source(script_path: str) -> str:
    return f"{quote_posix(sys.executable)} {quote_posix(script_path)}"


def powershell_source(script_path: str) -> str:
    return (
        f"& {quote_powershell(sys.executable)} {quote_powershell(script_path)}"
        f"{POWERSHELL_EXIT_SUFFIX}"
    )


def windows_powershell_path() -> str:
    configured = os.environ.get("SystemRoot") if os.name == "nt" else None
    system_root = (
        configured
        if configured
        and ntpath.isabs(configured)
        and re.search(r'["%\r\n]', configured) is None
        else r"C:\Windows"
    )
    return ntpath.join(system_root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")


def encode_powershell_source(source: str) -> str:
    return base64.b64encode(source.encode("utf-16le")).decode("ascii")


def encoded_windows_command(script_path: str, preamble: str = "") -> str:
    encoded = encode_powershell_source(preamble + powershell_source(script_path))
    return (
        f'"{windows_powershell_path()}" -NoLogo -NoProfile -NonInteractive '
        f"-EncodedCommand {encoded}"
    )


def is_python_executable(file_path: str) -> bool:
    return _PYTHON_EXECUTABLE.fullmatch(os.path.basename(file_path)) is not None


def is_powershell_executable(file_path: str) -> bool:
    return ntpath.isabs(file_path) and ntpath.basename(file_path).lower() == "powershell.exe"


def read_posix_argument(command: str, start: int) -> Optional[Tuple[str, int]]:
    if start >= len(command) or command[start] != "'":
        return None
    value = ""
    index = start + 1
    while index < len(command):
        if command.startswith(_POSIX_APOSTROPHE, index):
            value += "'"
            index += len(_POSIX_APOSTROPHE)
            continue
        if command[index] == "'":
            return value, index + 1
        value += command[index]
        index += 1
    return None


def parse_posix_command(command: str) -> Optional[CommandParts]:
    executable = read_posix_argument(command, 0)
    if executable is None or command[executable[1] : executable[1] + 1] != " ":
        return None
    script = read_posix_argument(command, executable[1] + 1)
    if script is None or script[1] != len(command):
        return None
    return executable[0], script[0]


def read_powershell_argument(command: str, start: int) -> Optional[Tuple[str, int]]:
    if start >= len(command) or command[start] != "'":
        return None
    value = ""
    index = start + 1
    while index < len(command):
        if command[index] != "'":
            value += command[index]
            index += 1
            continue
        if index + 1 < len(command) and command[index + 1] == "'":
            value += "'"
            index += 2
            continue
        return value, index + 1
    return None


def parse_powershell_source(source: str, prefix: str = "& ") -> Optional[CommandParts]:
    if not source.startswith(prefix):
        return None
    executable = read_powershell_argument(source, len(prefix))
    if executable is None or source[executable[1] : executable[1] + 1] != " ":
        return None
    script = read_powershell_argument(source, executable[1] + 1)
    if script is None or source[script[1] :] != POWERSHELL_EXIT_SUFFIX:
        return None
    return executable[0], script[0]


def decode_powershell_source(encoded: str) -> Optional[str]:
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", encoded) is None:
        return None
    try:
        payload = base64.b64decode(encoded, validate=True)
        if base64.b64encode(payload).decode("ascii") != encoded or len(payload) % 2:
            return None
        return payload.decode("utf-16le")
    except (ValueError, UnicodeDecodeError):
        return None


def same_windows_path(left: str, right: str) -> bool:
    return ntpath.normcase(ntpath.abspath(left)) == ntpath.normcase(ntpath.abspath(right))


def parse_encoded_windows_command(
    command: str,
    prefix: str = "& ",
    powershell_path: Optional[str] = None,
) -> Optional[CommandParts]:
    match = _ENCODED_COMMAND.fullmatch(command)
    if match is None or not is_powershell_executable(match.group(1)):
        return None
    if powershell_path is not None and not same_windows_path(match.group(1), powershell_path):
        return None
    source = decode_powershell_source(match.group(2))
    return None if source is None else parse_powershell_source(source, prefix)
