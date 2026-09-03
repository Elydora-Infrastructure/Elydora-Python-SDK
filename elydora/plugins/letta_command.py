"""Letta Code command construction and exact runtime ownership."""

from __future__ import annotations

from dataclasses import dataclass
import os
import sys
from typing import Optional

from ._runtime import managed_script_reference
from ._shell_command import (
    is_python_executable,
    parse_posix_command,
    parse_powershell_source,
    posix_source,
    powershell_source,
)


@dataclass(frozen=True)
class LettaRuntimeReference:
    agent_id: str
    script_path: str
    executable_path: Optional[str] = None


def build_letta_command(script_path: str) -> str:
    if not os.path.isabs(sys.executable) or not os.path.isabs(script_path):
        raise ValueError(
            "Letta Code hook commands require absolute executable and script paths"
        )
    return powershell_source(script_path) if os.name == "nt" else posix_source(script_path)


def _runtime_reference(
    script_path: str,
    script_name: str,
    executable_path: Optional[str] = None,
) -> Optional[LettaRuntimeReference]:
    reference = managed_script_reference(script_path, script_name)
    if reference is None:
        return None
    return LettaRuntimeReference(reference[0], reference[1], executable_path)


def letta_runtime_reference(
    command: str, script_name: str
) -> Optional[LettaRuntimeReference]:
    parsed = (
        parse_powershell_source(command)
        if os.name == "nt"
        else parse_posix_command(command)
    )
    if parsed is None or not os.path.isabs(parsed[0]) or not is_python_executable(parsed[0]):
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
    if not os.path.isabs(executable) or not is_python_executable(executable) or not script_path:
        return None
    return _runtime_reference(script_path, script_name, executable)


def letta_legacy_audit_reference(
    command: str, script_name: str
) -> Optional[LettaRuntimeReference]:
    return _runtime_reference(command, script_name)
