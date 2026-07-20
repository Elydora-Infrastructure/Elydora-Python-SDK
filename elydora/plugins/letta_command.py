"""Letta Code command construction and exact runtime ownership."""

from __future__ import annotations

from dataclasses import dataclass
import os
import re
import sys
from typing import Optional, Tuple

from elydora._runtime_paths import runtime_root


@dataclass(frozen=True)
class LettaRuntimeReference:
    agent_id: str
    script_path: str
    executable_path: Optional[str] = None


def same_letta_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(
        os.path.abspath(right)
    )


def same_letta_agent_id(left: str, right: str) -> bool:
    return os.path.normcase(left) == os.path.normcase(right)


def _quote_posix(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _quote_powershell(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def build_letta_command(script_path: str) -> str:
    if not os.path.isabs(sys.executable) or not os.path.isabs(script_path):
        raise ValueError(
            "Letta Code hook commands require absolute executable and script paths"
        )
    invocation = (
        f"{_quote_powershell(sys.executable)} {_quote_powershell(script_path)}"
        if os.name == "nt"
        else f"{_quote_posix(sys.executable)} {_quote_posix(script_path)}"
    )
    return f"& {invocation}; exit $LASTEXITCODE" if os.name == "nt" else invocation


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


def _parse_powershell_command(command: str) -> Optional[Tuple[str, str]]:
    if not command.startswith("& "):
        return None
    executable = _read_powershell_argument(command, 2)
    if executable is None or executable[1] >= len(command):
        return None
    if command[executable[1]] != " ":
        return None
    script = _read_powershell_argument(command, executable[1] + 1)
    if script is None or command[script[1] :] != "; exit $LASTEXITCODE":
        return None
    return executable[0], script[0]


def _is_python_executable(file_path: str) -> bool:
    return bool(re.fullmatch(r"python(?:3(?:\.\d+)?)?(?:\.exe)?", os.path.basename(file_path), re.IGNORECASE))


def _runtime_reference(
    script_path: str,
    script_name: str,
    executable_path: Optional[str] = None,
) -> Optional[LettaRuntimeReference]:
    if not os.path.isabs(script_path) or os.path.basename(script_path) != script_name:
        return None
    agent_directory = os.path.dirname(script_path)
    if not same_letta_path(os.path.dirname(agent_directory), runtime_root()):
        return None
    agent_id = os.path.basename(agent_directory)
    if agent_id in {"", ".", ".."}:
        return None
    return LettaRuntimeReference(agent_id, script_path, executable_path)


def letta_runtime_reference(
    command: str, script_name: str
) -> Optional[LettaRuntimeReference]:
    parsed = (
        _parse_powershell_command(command)
        if os.name == "nt"
        else _parse_posix_command(command)
    )
    if (
        parsed is None
        or not os.path.isabs(parsed[0])
        or not _is_python_executable(parsed[0])
    ):
        return None
    return _runtime_reference(parsed[1], script_name, parsed[0])


def letta_legacy_guard_reference(
    command: str, script_name: str
) -> Optional[LettaRuntimeReference]:
    if not command.startswith('"'):
        return None
    closing = command.find('"', 1)
    if closing < 0 or closing + 1 >= len(command) or command[closing + 1] != " ":
        return None
    executable = command[1:closing]
    script_path = command[closing + 2 :]
    if (
        not os.path.isabs(executable)
        or not _is_python_executable(executable)
        or not script_path
    ):
        return None
    return _runtime_reference(script_path, script_name, executable)


def letta_legacy_audit_reference(
    command: str, script_name: str
) -> Optional[LettaRuntimeReference]:
    return _runtime_reference(command, script_name)
