"""Gemini CLI hook command construction and exact runtime ownership."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import ntpath
import os
import re
import sys
from typing import Optional, Tuple


@dataclass(frozen=True)
class GeminiRuntimeReference:
    agent_id: str
    script_path: str


def same_gemini_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(
        os.path.abspath(right)
    )


def same_gemini_agent_id(left: str, right: str) -> bool:
    return os.path.normcase(left) == os.path.normcase(right)


def _quote_posix(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _quote_powershell(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _windows_powershell_path() -> str:
    configured = os.environ.get("SystemRoot")
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
        f"& {_quote_powershell(_windows_powershell_path())} "
        "-NoLogo -NoProfile -NonInteractive -EncodedCommand "
        f"{encoded}"
    )


def build_gemini_command(script_path: str) -> str:
    if not os.path.isabs(sys.executable) or not os.path.isabs(script_path):
        raise ValueError(
            "Gemini CLI hook commands require absolute executable and script paths"
        )
    if os.name == "nt":
        return _windows_command(script_path)
    return f"{_quote_posix(sys.executable)} {_quote_posix(script_path)}"


def _read_posix_argument(command: str, start: int) -> Optional[Tuple[str, int]]:
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
            return value, index + 1
        value += command[index]
        index += 1
    return None


def _parse_posix_command(command: str) -> Optional[Tuple[str, str]]:
    executable = _read_posix_argument(command, 0)
    if executable is None or executable[1] >= len(command):
        return None
    if command[executable[1]] != " ":
        return None
    script = _read_posix_argument(command, executable[1] + 1)
    if script is None or script[1] != len(command):
        return None
    return executable[0], script[0]


def _read_powershell_argument(
    command: str, start: int
) -> Optional[Tuple[str, int]]:
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


def _parse_powershell_source(source: str) -> Optional[Tuple[str, str]]:
    if not source.startswith("& "):
        return None
    executable = _read_powershell_argument(source, 2)
    if executable is None or executable[1] >= len(source):
        return None
    if source[executable[1]] != " ":
        return None
    script = _read_powershell_argument(source, executable[1] + 1)
    if script is None or source[script[1] :] != "; exit $LASTEXITCODE":
        return None
    return executable[0], script[0]


def _parse_windows_command(command: str) -> Optional[Tuple[str, str]]:
    if not command.startswith("& "):
        return None
    powershell = _read_powershell_argument(command, 2)
    if (
        powershell is None
        or not ntpath.isabs(powershell[0])
        or ntpath.basename(powershell[0]).lower() != "powershell.exe"
    ):
        return None
    prefix = " -NoLogo -NoProfile -NonInteractive -EncodedCommand "
    if not command.startswith(prefix, powershell[1]):
        return None
    encoded = command[powershell[1] + len(prefix) :]
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", encoded) is None:
        return None
    try:
        payload = base64.b64decode(encoded, validate=True)
        if base64.b64encode(payload).decode("ascii") != encoded:
            return None
        if len(payload) % 2:
            return None
        source = payload.decode("utf-16le")
    except (ValueError, UnicodeDecodeError):
        return None
    return _parse_powershell_source(source)


def _parse_legacy_command(
    command: str, script_name: str
) -> Optional[Tuple[str, str]]:
    if script_name == "guard.py":
        match = re.fullmatch(r'"([^"\r\n]+)" ([^\r\n]+)', command)
        if match is None or not same_gemini_path(match.group(1), sys.executable):
            return None
        return match.group(1), match.group(2)
    if "\r" in command or "\n" in command:
        return None
    return sys.executable, command


def gemini_runtime_reference(
    command: str,
    script_name: str,
    include_legacy: bool = False,
) -> Optional[GeminiRuntimeReference]:
    parsed = _parse_posix_command(command) or _parse_windows_command(command)
    if parsed is None and include_legacy:
        parsed = _parse_legacy_command(command, script_name)
    if (
        parsed is None
        or not same_gemini_path(parsed[0], sys.executable)
        or not os.path.isabs(parsed[1])
        or os.path.basename(parsed[1]) != script_name
    ):
        return None
    agent_directory = os.path.dirname(parsed[1])
    runtime_root = os.path.join(os.path.expanduser("~"), ".elydora")
    if not same_gemini_path(os.path.dirname(agent_directory), runtime_root):
        return None
    agent_id = os.path.basename(agent_directory)
    if agent_id in {"", ".", ".."}:
        return None
    return GeminiRuntimeReference(agent_id, parsed[1])
