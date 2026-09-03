"""Codex hook source and managed runtime I/O."""

from __future__ import annotations

import os
import stat
from typing import List, Optional

from ._managed_files import MAX_SOURCE_BYTES, physical_directory_exists, read_physical_file
from ._runtime import rendered_source_change, runtime_present
from ._transaction import FileChange
from .codex_contract import (
    AGENT_KEY,
    CONFIG_FILE,
    CodexDocument,
    RenderedDocument,
    RuntimeContract,
    create_document,
    parse_document,
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
    physical_directory_exists(os.path.dirname(file_path), "Codex hooks directory")


def rendered_change(rendered: RenderedDocument) -> Optional[FileChange]:
    if not rendered.changed:
        return None
    return rendered_source_change(
        rendered.document.file_path,
        "Codex user hooks",
        rendered.document.raw,
        rendered.next_source,
    )


def runtime_files_exist(contracts: List[RuntimeContract]) -> bool:
    return any(runtime_present(contract, AGENT_KEY) for contract in contracts)
