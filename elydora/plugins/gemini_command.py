"""Gemini CLI hook command construction and exact runtime ownership."""

from __future__ import annotations

from dataclasses import dataclass
import os
import re
import sys
from typing import Optional, Tuple

from ._runtime import managed_script_reference, same_path
from ._shell_command import (
    decode_powershell_source,
    encode_powershell_source,
    is_powershell_executable,
    parse_posix_command,
    parse_powershell_source,
    posix_source,
    powershell_source,
    quote_powershell,
    read_powershell_argument,
    windows_powershell_path,
)

_ENCODED_FLAGS = " -NoLogo -NoProfile -NonInteractive -EncodedCommand "


@dataclass(frozen=True)
class GeminiRuntimeReference:
    agent_id: str
    script_path: str


def build_gemini_command(script_path: str) -> str:
    if not os.path.isabs(sys.executable) or not os.path.isabs(script_path):
        raise ValueError(
            "Gemini CLI hook commands require absolute executable and script paths"
        )
    if os.name == "nt":
        encoded = encode_powershell_source(powershell_source(script_path))
        return f"& {quote_powershell(windows_powershell_path())}{_ENCODED_FLAGS}{encoded}"
    return posix_source(script_path)


def _parse_windows_command(command: str) -> Optional[Tuple[str, str]]:
    if not command.startswith("& "):
        return None
    powershell = read_powershell_argument(command, 2)
    if powershell is None or not is_powershell_executable(powershell[0]):
        return None
    if not command.startswith(_ENCODED_FLAGS, powershell[1]):
        return None
    source = decode_powershell_source(command[powershell[1] + len(_ENCODED_FLAGS) :])
    return None if source is None else parse_powershell_source(source)


def _parse_legacy_command(command: str, script_name: str) -> Optional[Tuple[str, str]]:
    if script_name == "guard.py":
        match = re.fullmatch(r'"([^"\r\n]+)" ([^\r\n]+)', command)
        if match is None or not same_path(match.group(1), sys.executable):
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
    parsed = parse_posix_command(command) or _parse_windows_command(command)
    if parsed is None and include_legacy:
        parsed = _parse_legacy_command(command, script_name)
    if parsed is None or not same_path(parsed[0], sys.executable):
        return None
    reference = managed_script_reference(parsed[1], script_name)
    return None if reference is None else GeminiRuntimeReference(*reference)
