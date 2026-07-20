"""Grok hook command rendering and exact runtime ownership."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import ntpath
import os
import re
import shlex
import subprocess  # nosec B404 - used only for legacy command rendering
import sys
from typing import Optional, Tuple


@dataclass(frozen=True)
class GrokRuntimeReference:
    agent_id: str
    script_path: str


@dataclass(frozen=True)
class _ParsedArgument:
    value: str
    next_index: int


def runtime_root() -> str:
    return os.path.join(os.path.expanduser("~"), ".elydora")


def same_grok_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(
        os.path.abspath(right)
    )


def same_grok_agent_id(left: str, right: str) -> bool:
    return os.path.normcase(left) == os.path.normcase(right)


def _quote_posix(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _quote_powershell(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _windows_powershell_path() -> str:
    configured = os.environ.get("SystemRoot") if os.name == "nt" else None
    system_root = (
        configured
        if configured
        and ntpath.isabs(configured)
        and re.search(r'["%\r\n]', configured) is None
        else r"C:\Windows"
    )
    return ntpath.join(
        system_root,
        "System32",
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe",
    )


def _windows_command(script_path: str) -> str:
    source = (
        f"& {_quote_powershell(sys.executable)} "
        f"{_quote_powershell(script_path)}; exit $LASTEXITCODE"
    )
    encoded = base64.b64encode(source.encode("utf-16le")).decode("ascii")
    return (
        f'"{_windows_powershell_path()}" -NoLogo -NoProfile '
        f"-NonInteractive -EncodedCommand {encoded}"
    )


def build_grok_command(script_path: str) -> str:
    if not os.path.isabs(sys.executable) or not os.path.isabs(script_path):
        raise ValueError(
            "Grok hook commands require absolute executable and script paths"
        )
    if os.name == "nt":
        return _windows_command(script_path)
    return f"{_quote_posix(sys.executable)} {_quote_posix(script_path)}"


def _read_posix_argument(command: str, start: int) -> Optional[_ParsedArgument]:
    if start >= len(command) or command[start] != "'":
        return None
    apostrophe = "'\"'\"'"
    value = ""
    index = start + 1
    while index < len(command):
        if command.startswith(apostrophe, index):
            value += "'"
            index += len(apostrophe)
            continue
        if command[index] == "'":
            return _ParsedArgument(value, index + 1)
        value += command[index]
        index += 1
    return None


def _parse_posix_command(command: str) -> Optional[Tuple[str, str]]:
    executable = _read_posix_argument(command, 0)
    if executable is None or command[executable.next_index : executable.next_index + 1] != " ":
        return None
    script = _read_posix_argument(command, executable.next_index + 1)
    if script is None or script.next_index != len(command):
        return None
    return executable.value, script.value


def _read_powershell_argument(
    command: str, start: int
) -> Optional[_ParsedArgument]:
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
        return _ParsedArgument(value, index + 1)
    return None


def _parse_powershell_source(source: str) -> Optional[Tuple[str, str]]:
    if not source.startswith("& "):
        return None
    executable = _read_powershell_argument(source, 2)
    if executable is None or source[executable.next_index : executable.next_index + 1] != " ":
        return None
    script = _read_powershell_argument(source, executable.next_index + 1)
    if script is None or source[script.next_index :] != "; exit $LASTEXITCODE":
        return None
    return executable.value, script.value


def _parse_windows_command(command: str) -> Optional[Tuple[str, str]]:
    match = re.fullmatch(
        r'"([^"\r\n]+)" -NoLogo -NoProfile -NonInteractive '
        r"-EncodedCommand ([A-Za-z0-9+/]+={0,2})",
        command,
    )
    if (
        match is None
        or not ntpath.isabs(match.group(1))
        or ntpath.basename(match.group(1)).lower() != "powershell.exe"
    ):
        return None
    try:
        raw = base64.b64decode(match.group(2), validate=True)
        if base64.b64encode(raw).decode("ascii") != match.group(2):
            return None
        source = raw.decode("utf-16le")
    except (UnicodeDecodeError, ValueError):
        return None
    return _parse_powershell_source(source)


def _parse_legacy_posix_command(command: str) -> Optional[Tuple[str, str]]:
    try:
        arguments = shlex.split(command, posix=True)
    except ValueError:
        return None
    if len(arguments) != 2 or shlex.join(arguments) != command:
        return None
    return arguments[0], arguments[1]


def _parse_legacy_windows_command(command: str) -> Optional[Tuple[str, str]]:
    match = re.fullmatch(
        r'(?:(?:"([^"\r\n]+)")|([^\s"\r\n]+)) '
        r'(?:(?:"([^"\r\n]+)")|([^\s"\r\n]+))',
        command,
    )
    if match is None:
        return None
    arguments = [match.group(1) or match.group(2), match.group(3) or match.group(4)]
    if subprocess.list2cmdline(arguments) != command:
        return None
    return arguments[0], arguments[1]


def _is_python_executable(file_path: str) -> bool:
    return (
        re.fullmatch(
            r"python(?:[0-9]+(?:\.[0-9]+)*)?(?:\.exe)?",
            os.path.basename(file_path),
            re.IGNORECASE,
        )
        is not None
    )


def grok_runtime_reference(
    command: str, script_name: str
) -> Optional[GrokRuntimeReference]:
    parsed = (
        _parse_posix_command(command)
        or _parse_windows_command(command)
        or _parse_legacy_posix_command(command)
        or _parse_legacy_windows_command(command)
    )
    if parsed is None:
        return None
    executable, script_path = parsed
    if (
        not os.path.isabs(executable)
        or not os.path.isabs(script_path)
        or not _is_python_executable(executable)
        or os.path.basename(script_path) != script_name
    ):
        return None
    agent_directory = os.path.dirname(script_path)
    if not same_grok_path(os.path.dirname(agent_directory), runtime_root()):
        return None
    agent_id = os.path.basename(agent_directory)
    if agent_id in {"", ".", ".."}:
        return None
    return GrokRuntimeReference(agent_id, script_path)
