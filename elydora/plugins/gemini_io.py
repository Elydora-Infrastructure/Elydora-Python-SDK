"""Gemini CLI settings discovery and strict managed runtime inspection."""

from __future__ import annotations

import os
from typing import List, Optional

from ._managed_files import MAX_SOURCE_BYTES, physical_directory_exists, read_physical_file
from ._runtime import rendered_source_change, runtime_contract_exists
from ._transaction import FileChange, write_changes
from .gemini_config import (
    GeminiDocument,
    RenderedGeminiDocument,
    create_gemini_document,
    parse_gemini_document,
)
from .gemini_contract import AGENT_KEY, CONFIG_FILE, GeminiRuntimeContract


def gemini_configuration_directory() -> str:
    configured_home = os.environ.get("GEMINI_CLI_HOME")
    home = configured_home if configured_home else os.path.expanduser("~")
    return os.path.join(home, ".gemini")


def gemini_settings_path() -> str:
    return os.path.join(gemini_configuration_directory(), CONFIG_FILE)


def read_gemini_document() -> GeminiDocument:
    file_path = gemini_settings_path()
    physical_directory_exists(os.path.dirname(file_path), "Gemini CLI configuration directory")
    snapshot = read_physical_file(file_path, "Gemini CLI user settings", MAX_SOURCE_BYTES)
    if snapshot is None:
        return create_gemini_document(file_path)
    return parse_gemini_document(exists=True, file_path=file_path, raw=snapshot.contents)


def rendered_change(rendered: RenderedGeminiDocument) -> Optional[FileChange]:
    if not rendered.changed:
        return None
    return rendered_source_change(
        rendered.document.file_path,
        "Gemini CLI user settings",
        rendered.document.raw if rendered.document.exists else None,
        rendered.next_source,
    )


def write_gemini_document(rendered: RenderedGeminiDocument) -> None:
    change = rendered_change(rendered)
    if change is not None:
        write_changes([change], "Uninstall Gemini CLI hooks")


def gemini_runtime_files_exist(contracts: List[GeminiRuntimeContract]) -> bool:
    return any(
        runtime_contract_exists(contract, AGENT_KEY, "Gemini CLI") for contract in contracts
    )
