"""Claude Code settings discovery and managed runtime I/O."""

from __future__ import annotations

import os
from typing import List, Optional

from ._managed_files import MAX_SOURCE_BYTES, physical_directory_exists, read_physical_file
from ._runtime import rendered_source_change, runtime_contract_exists
from ._transaction import FileChange, write_changes
from .claudecode_contract import (
    AGENT_KEY,
    CONFIG_FILE,
    ClaudeDocument,
    ClaudeRuntimeContract,
    RenderedClaudeDocument,
    create_claude_document,
    parse_claude_document,
)


def claude_config_directory() -> str:
    if "CLAUDE_CONFIG_DIR" not in os.environ:
        return os.path.join(os.path.expanduser("~"), ".claude")
    return os.path.abspath(os.environ["CLAUDE_CONFIG_DIR"])


def claude_settings_path() -> str:
    return os.path.join(claude_config_directory(), CONFIG_FILE)


def read_claude_document() -> ClaudeDocument:
    file_path = claude_settings_path()
    physical_directory_exists(os.path.dirname(file_path), "Claude Code configuration directory")
    snapshot = read_physical_file(file_path, "Claude Code user settings", MAX_SOURCE_BYTES)
    if snapshot is None:
        return create_claude_document(file_path)
    return parse_claude_document(file_path, snapshot.contents)


def rendered_change(rendered: RenderedClaudeDocument) -> Optional[FileChange]:
    if not rendered.changed:
        return None
    return rendered_source_change(
        rendered.document.file_path,
        "Claude Code user settings",
        rendered.document.raw,
        rendered.next_source,
    )


def write_claude_document(rendered: RenderedClaudeDocument) -> None:
    change = rendered_change(rendered)
    if change is not None:
        write_changes([change], "Uninstall Claude Code hooks")


def claude_runtime_files_exist(contracts: List[ClaudeRuntimeContract]) -> bool:
    return any(
        runtime_contract_exists(contract, AGENT_KEY, "Claude Code") for contract in contracts
    )
