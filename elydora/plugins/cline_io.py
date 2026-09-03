"""Physical Cline hook and managed runtime validation."""

from __future__ import annotations

import os

from ._managed_files import physical_directory_exists, read_physical_file
from ._runtime import expected_runtime_scripts, runtime_contract_exists
from .cline_contract import AGENT_KEY, HookFile, RuntimeContract, parse_metadata


def validate_hook_tree(hooks_directory: str) -> None:
    physical_directory_exists(os.path.dirname(hooks_directory), "Cline configuration directory")
    physical_directory_exists(hooks_directory, "Cline hooks directory")


def read_hook_file(file_path: str) -> HookFile:
    validate_hook_tree(os.path.dirname(file_path))
    snapshot = read_physical_file(file_path, "Cline hook")
    if snapshot is None:
        return HookFile(False, file_path)
    return HookFile(
        exists=True,
        file_path=file_path,
        source=snapshot.contents,
        metadata=parse_metadata(file_path, snapshot.contents),
    )


def require_available_hook_file(file: HookFile) -> None:
    if file.exists and file.metadata is None:
        raise ValueError(
            f"Cline hook at {file.file_path} already exists and is owned "
            "by another integration"
        )


def runtime_files_exist(contract: RuntimeContract) -> bool:
    return runtime_contract_exists(
        contract, AGENT_KEY, "Cline", expected_runtime_scripts(AGENT_KEY, contract.agent_id)
    )
