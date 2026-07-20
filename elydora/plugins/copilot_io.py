"""GitHub Copilot hook source and runtime I/O."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from ._transaction import (
    FileChange,
    read_optional,
    regular_file_exists,
    source_change,
)
from .copilot_contract import (
    AGENT_KEY,
    CONFIG_FILE,
    CopilotDocument,
    CopilotSources,
    RenderedDocument,
    RuntimeContract,
    create_document,
    parse_document,
)


JsonObject = Dict[str, Any]


def config_paths(home_dir: str) -> tuple[str, str]:
    override = os.environ.get("COPILOT_HOME", "").strip()
    copilot_home = override or os.path.join(home_dir, ".copilot")
    user_path = os.path.join(copilot_home, "hooks", CONFIG_FILE)
    legacy_path = os.path.join(os.getcwd(), ".github", "hooks", "hooks.json")
    return user_path, legacy_path


def _read_document(file_path: str, label: str) -> Optional[CopilotDocument]:
    raw = read_optional(file_path, label)
    return None if raw is None else parse_document(file_path, raw, label)


def read_sources(home_dir: str) -> CopilotSources:
    user_path, legacy_path = config_paths(home_dir)
    user = _read_document(user_path, "GitHub Copilot user hooks")
    legacy = _read_document(legacy_path, "GitHub Copilot legacy project hooks")
    return CopilotSources(user or create_document(user_path), legacy)


def rendered_change(rendered: RenderedDocument) -> Optional[FileChange]:
    if not rendered.changed:
        return None
    return source_change(
        rendered.document.file_path,
        "GitHub Copilot hook source",
        rendered.document.raw,
        rendered.next_source,
        0o600,
    )


def _read_runtime_config(file_path: str) -> Optional[JsonObject]:
    raw = read_optional(file_path, "Elydora runtime config")
    if raw is None:
        return None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError(
            f"Failed to parse Elydora runtime config at {file_path}: {error}"
        ) from error
    if not isinstance(value, dict):
        raise ValueError(
            f"Elydora runtime config at {file_path} must contain a JSON object"
        )
    return value


def runtime_files_exist(contracts: List[RuntimeContract]) -> bool:
    for contract in contracts:
        agent_directory = os.path.dirname(contract.guard_path)
        config_path = os.path.join(agent_directory, "config.json")
        config = _read_runtime_config(config_path)
        if (
            config is None
            or config.get("agent_name") != AGENT_KEY
            or config.get("agent_id") != contract.agent_id
        ):
            continue
        if regular_file_exists(
            contract.guard_path, "Elydora guard runtime"
        ) and regular_file_exists(
            contract.audit_path, "Elydora audit runtime"
        ):
            return True
    return False
