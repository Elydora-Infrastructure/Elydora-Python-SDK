"""Cursor hook source and runtime I/O."""

from __future__ import annotations

import os
import stat
from typing import Any, List, Optional

from ._transaction import FileChange, source_change, write_changes
from .cursor_contract import (
    AGENT_KEY,
    CursorDocument,
    JsonObject,
    RenderedDocument,
    RuntimeContract,
    create_document,
    parse_document,
    parse_json_object,
)


CONFIG_FILE = "hooks.json"


def config_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".cursor", CONFIG_FILE)


def _read_optional_physical(file_path: str, label: str) -> Optional[str]:
    try:
        metadata = os.lstat(file_path)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise OSError(f"Inspect {label} at {file_path}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise OSError(f"{label} path is not a physical file: {file_path}")
    try:
        with open(file_path, "r", encoding="utf-8", newline="") as file:
            return file.read()
    except OSError as error:
        raise OSError(f"Read {label} at {file_path}: {error}") from error


def read_document() -> CursorDocument:
    file_path = config_path()
    raw = _read_optional_physical(file_path, "Cursor user hooks")
    return create_document(file_path) if raw is None else parse_document(file_path, raw)


def validate_config_directory() -> None:
    directory = os.path.dirname(config_path())
    try:
        metadata = os.lstat(directory)
    except FileNotFoundError:
        return
    except OSError as error:
        raise OSError(f"Inspect Cursor hooks directory at {directory}: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise OSError(f"Cursor hooks directory is not a physical directory: {directory}")


def rendered_change(rendered: RenderedDocument) -> Optional[FileChange]:
    if not rendered.changed:
        return None
    return source_change(
        rendered.document.file_path,
        "Cursor user hooks",
        rendered.document.raw,
        rendered.next_source,
        0o600,
    )


def runtime_change(
    file_path: str,
    label: str,
    next_source: str,
    mode: int,
) -> Optional[FileChange]:
    original = _read_optional_physical(file_path, label)
    return source_change(file_path, label, original, next_source, mode)


def physical_file_exists(file_path: str, label: str) -> bool:
    try:
        metadata = os.lstat(file_path)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise OSError(f"Inspect {label} at {file_path}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise OSError(f"{label} path is not a physical file: {file_path}")
    return True


def require_runtime(file_path: str, label: str) -> None:
    if not file_path:
        raise ValueError(f"{label} path is required")
    if not physical_file_exists(file_path, label):
        raise FileNotFoundError(f"{label} is missing: {file_path}")


def physical_directory_exists(directory: str) -> bool:
    try:
        metadata = os.lstat(directory)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise OSError(
            f"Inspect Elydora agent runtime directory at {directory}: {error}"
        ) from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise OSError(
            f"Elydora agent runtime path is not a physical directory: {directory}"
        )
    return True


def require_runtime_directory(directory: str) -> None:
    if not physical_directory_exists(directory):
        raise FileNotFoundError(
            f"Elydora agent runtime directory is missing: {directory}"
        )


def _read_runtime_config(file_path: str) -> Optional[JsonObject]:
    raw = _read_optional_physical(file_path, "Elydora runtime config")
    if raw is None:
        return None
    return parse_json_object(raw, f"Elydora runtime config at {file_path}")


def validate_runtime_identity(
    file_path: str,
    agent_id: str,
) -> bool:
    config = _read_runtime_config(file_path)
    if config is None:
        return False
    if config.get("agent_name") != AGENT_KEY or not _same_agent_id(
        config.get("agent_id"), agent_id
    ):
        raise ValueError(
            f"Elydora runtime config identity does not match Cursor agent {agent_id}: "
            f"{file_path}"
        )
    return True


def _same_agent_id(value: Any, expected: str) -> bool:
    return isinstance(value, str) and os.path.normcase(value) == os.path.normcase(
        expected
    )


def runtime_files_exist(contracts: List[RuntimeContract]) -> bool:
    for contract in contracts:
        agent_directory = os.path.dirname(contract.guard_path)
        if not physical_directory_exists(agent_directory):
            continue
        config_path_value = os.path.join(agent_directory, "config.json")
        config = _read_runtime_config(config_path_value)
        if (
            config is None
            or config.get("agent_name") != AGENT_KEY
            or not _same_agent_id(config.get("agent_id"), contract.agent_id)
        ):
            continue
        if physical_file_exists(
            contract.guard_path,
            "Elydora guard runtime",
        ) and physical_file_exists(
            contract.audit_path,
            "Elydora audit runtime",
        ) and physical_file_exists(
            os.path.join(agent_directory, "private.key"),
            "Elydora private key",
        ):
            return True
    return False


def _ensure_physical_directory(directory: str, label: str) -> None:
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        metadata = os.lstat(directory)
    except OSError as error:
        raise OSError(f"Prepare {label} directory at {directory}: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise OSError(f"{label} directory is not a physical directory: {directory}")


def write_cursor_changes(changes: List[FileChange], label: str) -> None:
    effective = [change for change in changes if change.original != change.next_source]
    if not effective:
        return
    directories = {
        os.path.normcase(os.path.abspath(os.path.dirname(change.file_path))):
        os.path.dirname(change.file_path)
        for change in effective
    }
    for directory in directories.values():
        _ensure_physical_directory(directory, label)
    write_changes(effective, label)
