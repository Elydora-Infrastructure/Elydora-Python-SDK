"""Codex hook source and managed runtime I/O."""

from __future__ import annotations

import os
import stat
from typing import Any, List, Optional

from ._managed_files import (
    MAX_CONFIG_BYTES,
    MAX_SOURCE_BYTES,
    physical_directory_exists,
    physical_file_exists,
    read_physical_file,
)
from ._strict_json import JsonObject, parse_json_object
from ._transaction import FileChange, source_change, write_changes
from .codex_contract import (
    AGENT_KEY,
    CONFIG_FILE,
    CodexDocument,
    RenderedDocument,
    RuntimeContract,
    create_document,
    parse_document,
)


def _same_agent_id(value: Any, expected: str) -> bool:
    return isinstance(value, str) and os.path.normcase(value) == os.path.normcase(
        expected
    )


def codex_home_path() -> str:
    configured = os.environ.get("CODEX_HOME")
    if configured is None or configured == "":
        return os.path.join(os.path.expanduser("~"), ".codex")
    try:
        metadata = os.stat(configured)
    except OSError as error:
        raise OSError(f"Resolve CODEX_HOME at {configured}: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise OSError(f"CODEX_HOME is not a directory: {configured}")
    try:
        canonical = os.path.realpath(configured, strict=True)
    except OSError as error:
        raise OSError(f"Canonicalize CODEX_HOME at {configured}: {error}") from error
    if not physical_directory_exists(canonical, "CODEX_HOME"):
        raise OSError(f"CODEX_HOME is missing: {canonical}")
    return canonical


def config_path() -> str:
    return os.path.join(codex_home_path(), CONFIG_FILE)


def read_document() -> CodexDocument:
    file_path = config_path()
    snapshot = read_physical_file(file_path, "Codex user hooks", MAX_SOURCE_BYTES)
    if snapshot is None:
        return create_document(file_path)
    return parse_document(file_path, snapshot.contents)


def validate_hooks_directory(file_path: str) -> None:
    directory = os.path.dirname(file_path)
    physical_directory_exists(directory, "Codex hooks directory")


def rendered_change(rendered: RenderedDocument) -> Optional[FileChange]:
    if not rendered.changed:
        return None
    return source_change(
        rendered.document.file_path,
        "Codex user hooks",
        rendered.document.raw,
        rendered.next_source,
        0o600,
        MAX_SOURCE_BYTES,
    )


def runtime_change(
    file_path: str,
    label: str,
    next_source: str,
    mode: int,
    maximum_bytes: int = MAX_SOURCE_BYTES,
) -> Optional[FileChange]:
    snapshot = read_physical_file(file_path, label, maximum_bytes)
    return source_change(
        file_path,
        label,
        None if snapshot is None else snapshot.contents,
        next_source,
        mode,
        maximum_bytes,
    )


def _read_runtime_config(file_path: str) -> Optional[JsonObject]:
    snapshot = read_physical_file(
        file_path,
        "Elydora runtime config",
        MAX_CONFIG_BYTES,
    )
    if snapshot is None:
        return None
    return parse_json_object(
        snapshot.contents,
        f"Elydora runtime config at {file_path}",
    )


def validate_runtime_identity(agent_directory: str, agent_id: str) -> bool:
    config_path_value = os.path.join(agent_directory, "config.json")
    config = _read_runtime_config(config_path_value)
    artifacts = [
        ("private.key", "Elydora private key"),
        ("guard.py", "Elydora guard runtime"),
        ("hook.py", "Elydora audit runtime"),
        ("chain-state.json", "Elydora chain state"),
        ("status-cache.json", "Elydora status cache"),
        ("error.log", "Elydora error log"),
    ]
    artifact_states = [
        physical_file_exists(os.path.join(agent_directory, name), label)
        for name, label in artifacts
    ]
    artifact_exists = any(artifact_states)
    if config is None:
        if artifact_exists:
            raise ValueError(
                "Elydora runtime identity cannot be verified without config.json: "
                f"{agent_directory}"
            )
        return False
    if config.get("agent_name") != AGENT_KEY or not _same_agent_id(
        config.get("agent_id"),
        agent_id,
    ):
        raise ValueError(
            f"Elydora runtime config identity does not match Codex agent {agent_id}: "
            f"{config_path_value}"
        )
    return True


def validate_runtime_tree(
    runtime_root: str, agent_directory: str, agent_id: str
) -> None:
    if not physical_directory_exists(runtime_root, "Elydora runtime directory"):
        return
    if not physical_directory_exists(
        agent_directory,
        "Elydora agent runtime directory",
    ):
        return
    validate_runtime_identity(agent_directory, agent_id)


def runtime_files_exist(contracts: List[RuntimeContract]) -> bool:
    for contract in contracts:
        agent_directory = os.path.dirname(contract.guard_path)
        if not physical_directory_exists(
            agent_directory,
            "Elydora agent runtime directory",
        ):
            continue
        config = _read_runtime_config(os.path.join(agent_directory, "config.json"))
        if (
            config is None
            or config.get("agent_name") != AGENT_KEY
            or not _same_agent_id(config.get("agent_id"), contract.agent_id)
        ):
            continue
        if all(
            (
                physical_file_exists(contract.guard_path, "Elydora guard runtime"),
                physical_file_exists(contract.audit_path, "Elydora audit runtime"),
                physical_file_exists(
                    os.path.join(agent_directory, "private.key"),
                    "Elydora private key",
                ),
            )
        ):
            return True
    return False


def write_codex_changes(changes: List[FileChange], label: str) -> None:
    write_changes(changes, label)
