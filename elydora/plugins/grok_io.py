"""Grok user-hook discovery and managed runtime I/O."""

from __future__ import annotations

import os
from typing import List, Optional

from ._managed_files import physical_directory_exists, read_physical_file
from ._runtime import rendered_source_change, runtime_contract_exists
from ._transaction import FileChange
from .grok_contract import (
    AGENT_KEY,
    GrokDocument,
    GrokRuntimeContract,
    RenderedGrokDocument,
    create_grok_document,
    parse_grok_document,
)


CONFIG_FILE = "elydora-audit.json"


def grok_config_path() -> str:
    configured = os.environ.get("GROK_HOME")
    grok_home = (
        os.path.join(os.path.expanduser("~"), ".grok")
        if configured is None or configured == ""
        else os.path.abspath(configured)
    )
    return os.path.join(grok_home, "hooks", CONFIG_FILE)


def read_grok_document() -> GrokDocument:
    config_path = grok_config_path()
    hooks_directory = os.path.dirname(config_path)
    physical_directory_exists(os.path.dirname(hooks_directory), "Grok home directory")
    physical_directory_exists(hooks_directory, "Grok hooks directory")
    snapshot = read_physical_file(config_path, "Grok user hooks")
    if snapshot is None:
        return create_grok_document(config_path)
    return parse_grok_document(config_path, snapshot.contents)


def rendered_change(rendered: RenderedGrokDocument) -> Optional[FileChange]:
    if not rendered.changed:
        return None
    return rendered_source_change(
        rendered.document.config_path,
        "Grok user hooks",
        rendered.document.raw,
        rendered.next_source,
    )


def grok_runtime_files_exist(contracts: List[GrokRuntimeContract]) -> bool:
    return any(runtime_contract_exists(contract, AGENT_KEY, "Grok") for contract in contracts)
