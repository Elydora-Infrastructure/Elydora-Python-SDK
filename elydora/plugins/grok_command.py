"""Grok hook command rendering and exact runtime ownership."""

from __future__ import annotations

from dataclasses import dataclass
import os
import re
import shlex
import subprocess
import sys
from typing import Optional, Tuple

from ._runtime import managed_script_reference
from ._shell_command import (
    encoded_windows_command,
    is_python_executable,
    parse_encoded_windows_command,
    parse_posix_command,
    posix_source,
)


@dataclass(frozen=True)
class GrokRuntimeReference:
    agent_id: str
    script_path: str


def build_grok_command(script_path: str) -> str:
    if not os.path.isabs(sys.executable) or not os.path.isabs(script_path):
        raise ValueError(
            "Grok hook commands require absolute executable and script paths"
        )
    if os.name == "nt":
        return encoded_windows_command(script_path)
    return posix_source(script_path)


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


def grok_runtime_reference(
    command: str, script_name: str
) -> Optional[GrokRuntimeReference]:
    parsed = (
        parse_posix_command(command)
        or parse_encoded_windows_command(command)
        or _parse_legacy_posix_command(command)
        or _parse_legacy_windows_command(command)
    )
    if parsed is None:
        return None
    executable, script_path = parsed
    if not os.path.isabs(executable) or not is_python_executable(executable):
        return None
    reference = managed_script_reference(script_path, script_name)
    return None if reference is None else GrokRuntimeReference(*reference)
