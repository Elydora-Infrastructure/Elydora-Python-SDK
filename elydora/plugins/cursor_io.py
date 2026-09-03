"""Cursor hook source and runtime I/O."""

from __future__ import annotations

import os
from typing import List, Optional

from ._managed_files import MAX_SOURCE_BYTES, physical_directory_exists, read_physical_file
from ._runtime import rendered_source_change, runtime_present
from ._transaction import FileChange
from .cursor_contract import (
    AGENT_KEY,
    CursorDocument,
    RenderedDocument,
    RuntimeContract,
    create_document,
    parse_document,
)


CONFIG_FILE = "hooks.json"


def config_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".cursor", CONFIG_FILE)


def read_document() -> CursorDocument:
    file_path = config_path()
    snapshot = read_physical_file(file_path, "Cursor user hooks", MAX_SOURCE_BYTES)
    if snapshot is None:
        return create_document(file_path)
    return parse_document(file_path, snapshot.contents)


def validate_config_directory() -> None:
    physical_directory_exists(os.path.dirname(config_path()), "Cursor hooks directory")


def rendered_change(rendered: RenderedDocument) -> Optional[FileChange]:
    if not rendered.changed:
        return None
    return rendered_source_change(
        rendered.document.file_path,
        "Cursor user hooks",
        rendered.document.raw,
        rendered.next_source,
    )


def runtime_files_exist(contracts: List[RuntimeContract]) -> bool:
    return any(runtime_present(contract, AGENT_KEY) for contract in contracts)
