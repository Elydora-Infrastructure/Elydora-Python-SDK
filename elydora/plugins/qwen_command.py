"""Qwen Code command construction and exact runtime ownership."""

from __future__ import annotations

from dataclasses import dataclass
import os
import sys
from typing import Optional

from ._runtime import managed_script_reference, same_path
from ._shell_command import (
    parse_posix_command,
    parse_powershell_source,
    posix_source,
    powershell_source,
)


@dataclass(frozen=True)
class QwenRuntimeReference:
    agent_id: str
    script_path: str


def build_qwen_command(script_path: str) -> str:
    if not os.path.isabs(sys.executable) or not os.path.isabs(script_path):
        raise ValueError(
            "Qwen Code hook commands require absolute executable and script paths"
        )
    return powershell_source(script_path) if os.name == "nt" else posix_source(script_path)


def qwen_runtime_reference(
    command: str, script_name: str
) -> Optional[QwenRuntimeReference]:
    parsed = (
        parse_powershell_source(command)
        if os.name == "nt"
        else parse_posix_command(command)
    )
    if parsed is None or not same_path(parsed[0], sys.executable):
        return None
    reference = managed_script_reference(parsed[1], script_name)
    return None if reference is None else QwenRuntimeReference(*reference)
