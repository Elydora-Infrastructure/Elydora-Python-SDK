"""Qwen Code command construction and exact runtime ownership."""

from __future__ import annotations

from dataclasses import dataclass
import os
import sys
from typing import Optional, Tuple


@dataclass(frozen=True)
class QwenRuntimeReference:
    agent_id: str
    script_path: str


def same_qwen_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(
        os.path.abspath(right)
    )


def same_qwen_agent_id(left: str, right: str) -> bool:
    return os.path.normcase(left) == os.path.normcase(right)


def _quote_posix(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _quote_powershell(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def build_qwen_command(script_path: str) -> str:
    if not os.path.isabs(sys.executable) or not os.path.isabs(script_path):
        raise ValueError(
            "Qwen Code hook commands require absolute executable and script paths"
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


def qwen_runtime_reference(
    command: str, script_name: str
) -> Optional[QwenRuntimeReference]:
    parsed = (
        _parse_powershell_command(command)
        if os.name == "nt"
        else _parse_posix_command(command)
    )
    if (
        parsed is None
        or not same_qwen_path(parsed[0], sys.executable)
        or not os.path.isabs(parsed[1])
        or os.path.basename(parsed[1]) != script_name
    ):
        return None
    agent_directory = os.path.dirname(parsed[1])
    runtime_root = os.path.join(os.path.expanduser("~"), ".elydora")
    if not same_qwen_path(os.path.dirname(agent_directory), runtime_root):
        return None
    agent_id = os.path.basename(agent_directory)
    if agent_id in {"", ".", ".."}:
        return None
    return QwenRuntimeReference(agent_id, parsed[1])
