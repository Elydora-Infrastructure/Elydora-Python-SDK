"""Kiro IDE command rendering and exact runtime ownership."""

from __future__ import annotations

from dataclasses import dataclass
import os
import re
import sys
from typing import Optional, Tuple

from ._runtime import managed_script_reference, same_path
from ._shell_command import (
    encoded_windows_command,
    is_python_executable,
    parse_encoded_windows_command,
    parse_posix_command,
    posix_source,
    windows_powershell_path,
)

_PREAMBLE = "$ErrorActionPreference = 'Stop'; $global:LASTEXITCODE = 1; "


@dataclass(frozen=True)
class KiroIdeRuntimeReference:
    agent_id: str
    script_path: str


def build_kiroide_command(script_path: str) -> str:
    if (
        not os.path.isabs(sys.executable)
        or not is_python_executable(sys.executable)
        or not os.path.isabs(script_path)
    ):
        raise ValueError(
            "Kiro IDE hook commands require an absolute Python executable "
            "and script path"
        )
    if os.name == "nt":
        return encoded_windows_command(script_path, _PREAMBLE)
    return posix_source(script_path)


def _runtime_reference(
    executable: str, script_path: str, script_name: str
) -> Optional[KiroIdeRuntimeReference]:
    if not os.path.isabs(executable) or not is_python_executable(executable):
        return None
    reference = managed_script_reference(script_path, script_name)
    return None if reference is None else KiroIdeRuntimeReference(*reference)


def _parse_kiroide_command(command: str) -> Optional[Tuple[str, str]]:
    if os.name == "nt":
        return parse_encoded_windows_command(
            command, _PREAMBLE + "& ", windows_powershell_path()
        )
    return parse_posix_command(command)


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
    if parsed is None or not same_path(parsed[0], sys.executable):
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
