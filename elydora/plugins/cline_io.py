"""Fail-fast Cline hook I/O and runtime validation."""

from __future__ import annotations

from dataclasses import dataclass
import os
import tempfile
from typing import List, Sequence, Tuple

from ._file_io import (
    read_json,
    regular_file_exists,
    remove_file,
    require_runtime,
    write_text_atomic,
)
from .cline_contract import (
    AGENT_KEY,
    HookFile,
    RuntimeContract,
    parse_metadata,
    same_agent_id,
)


@dataclass(frozen=True)
class PendingWrite:
    state: HookFile
    source: str


@dataclass(frozen=True)
class StagedFile:
    state: HookFile
    temporary_path: str


def read_hook_file(file_path: str) -> HookFile:
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            source = file.read()
    except FileNotFoundError:
        return HookFile(False, file_path)
    except OSError as error:
        raise OSError(f"Read Cline hook at {file_path}: {error}") from error
    return HookFile(
        exists=True,
        file_path=file_path,
        source=source,
        metadata=parse_metadata(file_path, source),
    )


def require_available_hook_file(file: HookFile) -> None:
    if file.exists and file.metadata is None:
        raise ValueError(
            f"Cline hook at {file.file_path} already exists and is owned "
            "by another integration"
        )


def _remove_temporary(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        return


def _stage_file(write: PendingWrite) -> StagedFile:
    directory = os.path.dirname(write.state.file_path)
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    except OSError as error:
        raise OSError(f"Create Cline hooks directory at {directory}: {error}") from error
    descriptor = -1
    temporary_path = ""
    try:
        descriptor, temporary_path = tempfile.mkstemp(
            prefix=f".{os.path.basename(write.state.file_path)}.",
            suffix=".tmp",
            dir=directory,
            text=True,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as file:
            descriptor = -1
            file.write(write.source)
            file.flush()
            os.fsync(file.fileno())
        os.chmod(temporary_path, 0o700)
        return StagedFile(write.state, temporary_path)
    except Exception as error:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as close_error:
                _remove_temporary(temporary_path)
                raise OSError(
                    f"Stage Cline hook at {write.state.file_path}: {error}; "
                    f"close failed: {close_error}"
                ) from error
        _remove_temporary(temporary_path)
        raise OSError(
            f"Stage Cline hook at {write.state.file_path}: {error}"
        ) from error


def _rollback_file(state: HookFile) -> None:
    if state.exists:
        if state.source is None:
            raise RuntimeError("Existing Cline hook rollback state is missing source")
        write_text_atomic(
            state.file_path,
            state.source,
            0o700,
            "Cline hook rollback",
        )
    else:
        remove_file(state.file_path, "Cline hook rollback")


def write_hook_pair(guard: PendingWrite, audit: PendingWrite) -> None:
    staged: List[StagedFile] = []
    try:
        staged.append(_stage_file(guard))
        staged.append(_stage_file(audit))
    except Exception as error:
        cleanup_errors: List[str] = []
        for item in staged:
            try:
                _remove_temporary(item.temporary_path)
            except OSError as cleanup_error:
                cleanup_errors.append(str(cleanup_error))
        suffix = f"; cleanup failed: {'; '.join(cleanup_errors)}" if cleanup_errors else ""
        raise OSError(f"Stage Cline hook pair: {error}{suffix}") from error

    committed: List[StagedFile] = []
    try:
        for item in staged:
            os.replace(item.temporary_path, item.state.file_path)
            committed.append(item)
    except Exception as error:
        recovery_errors: List[str] = []
        for item in reversed(committed):
            try:
                _rollback_file(item.state)
            except (OSError, RuntimeError) as rollback_error:
                recovery_errors.append(str(rollback_error))
        for item in staged[len(committed):]:
            try:
                _remove_temporary(item.temporary_path)
            except OSError as cleanup_error:
                recovery_errors.append(str(cleanup_error))
        suffix = f"; recovery failed: {'; '.join(recovery_errors)}" if recovery_errors else ""
        raise OSError(f"Write Cline hook pair: {error}{suffix}") from error


def remove_owned_hooks(files: Sequence[HookFile], agent_id: str = "") -> None:
    for file in files:
        owned_agent_id = file.metadata.agent_id if file.metadata else ""
        if not owned_agent_id or (
            agent_id and not same_agent_id(owned_agent_id, agent_id)
        ):
            continue
        remove_file(file.file_path, "Cline hook")


def runtime_files_exist(contract: RuntimeContract) -> bool:
    config_path = os.path.join(contract.agent_directory, "config.json")
    config = read_json(config_path, "Elydora runtime config")
    if config is None:
        return False
    config_agent_id = config.get("agent_id")
    if (
        config.get("agent_name") != AGENT_KEY
        or not isinstance(config_agent_id, str)
        or not same_agent_id(config_agent_id, contract.agent_id)
    ):
        return False
    files: Tuple[Tuple[str, str], ...] = (
        (contract.guard_path, "Elydora guard runtime"),
        (contract.audit_path, "Elydora audit runtime"),
    )
    return all(regular_file_exists(path, label) for path, label in files)


__all__ = [
    "PendingWrite",
    "read_hook_file",
    "remove_owned_hooks",
    "require_available_hook_file",
    "require_runtime",
    "runtime_files_exist",
    "write_hook_pair",
]
