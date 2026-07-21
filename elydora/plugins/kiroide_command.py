"""Kiro IDE command rendering and exact runtime ownership."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import ntpath
import os
import re
import sys
from typing import Optional, Tuple

from elydora._runtime_paths import runtime_root


@dataclass(frozen=True)
class KiroIdeRuntimeReference:
    agent_id: str
    script_path: str


@dataclass(frozen=True)
class _ParsedArgument:
    value: str
    next_index: int


def same_kiroide_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(
        os.path.abspath(right)
    )


def same_kiroide_agent_id(left: str, right: str) -> bool:
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


def _same_windows_path(left: str, right: str) -> bool:
    return ntpath.normcase(ntpath.abspath(left)) == ntpath.normcase(
        ntpath.abspath(right)
    )


def _windows_command(script_path: str) -> str:
    source = (
        "$ErrorActionPreference = 'Stop'; $global:LASTEXITCODE = 1; "
        f"& {_quote_powershell(sys.executable)} "
        f"{_quote_powershell(script_path)}; exit $LASTEXITCODE"
    )
    encoded = base64.b64encode(source.encode("utf-16le")).decode("ascii")
    return (
        f'"{_windows_powershell_path()}" -NoLogo -NoProfile '
        f"-NonInteractive -EncodedCommand {encoded}"
    )


def build_kiroide_command(script_path: str) -> str:
    if (
        not os.path.isabs(sys.executable)
        or not _is_python_executable(sys.executable)
        or not os.path.isabs(script_path)
    ):
        raise ValueError(
            "Kiro IDE hook commands require an absolute Python executable "
            "and script path"
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
    if (
        executable is None
        or command[executable.next_index : executable.next_index + 1] != " "
    ):
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
    prefix = "$ErrorActionPreference = 'Stop'; $global:LASTEXITCODE = 1; & "
    if not source.startswith(prefix):
        return None
    executable = _read_powershell_argument(source, len(prefix))
    if (
        executable is None
        or source[executable.next_index : executable.next_index + 1] != " "
    ):
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
        or not _same_windows_path(match.group(1), _windows_powershell_path())
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


def _is_python_executable(file_path: str) -> bool:
    return (
        re.fullmatch(
            r"(?:python(?:[0-9]+(?:\.[0-9]+)*)?[td]?|"
            r"pypy(?:[0-9]+(?:\.[0-9]+)*)?)(?:\.exe)?",
            os.path.basename(file_path),
            re.IGNORECASE,
        )
        is not None
    )


def _runtime_reference(
    executable: str, script_path: str, script_name: str
) -> Optional[KiroIdeRuntimeReference]:
    if (
        not os.path.isabs(executable)
        or not _is_python_executable(executable)
        or not os.path.isabs(script_path)
        or os.path.basename(script_path) != script_name
    ):
        return None
    agent_directory = os.path.dirname(script_path)
    if not same_kiroide_path(os.path.dirname(agent_directory), runtime_root()):
        return None
    agent_id = os.path.basename(agent_directory)
    if agent_id in {"", ".", ".."}:
        return None
    return KiroIdeRuntimeReference(agent_id, script_path)


def _parse_kiroide_command(command: str) -> Optional[Tuple[str, str]]:
    return (
        _parse_windows_command(command)
        if os.name == "nt"
        else _parse_posix_command(command)
    )


def owned_kiroide_runtime_reference(
    command: str, script_name: str
) -> Optional[KiroIdeRuntimeReference]:
    parsed = _parse_kiroide_command(command)
    if parsed is None:
        return None
    return _runtime_reference(parsed[0], parsed[1], script_name)


def kiroide_runtime_reference(
    command: str, script_name: str
) -> Optional[KiroIdeRuntimeReference]:
    parsed = _parse_kiroide_command(command)
    if parsed is None:
        return None
    if not same_kiroide_path(parsed[0], sys.executable):
        return None
    return _runtime_reference(parsed[0], parsed[1], script_name)


def legacy_guard_reference(
    command: object, script_name: str
) -> Optional[KiroIdeRuntimeReference]:
    if not isinstance(command, str):
        return None
    match = re.fullmatch(r'"([^"\r\n]+)" (.+)', command)
    if match is None:
        return None
    return _runtime_reference(match.group(1), match.group(2), script_name)


def legacy_audit_reference(
    command: object, script_name: str
) -> Optional[KiroIdeRuntimeReference]:
    if not isinstance(command, str):
        return None
    return _runtime_reference(sys.executable, command, script_name)
