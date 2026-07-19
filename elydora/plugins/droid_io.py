"""Factory Droid source discovery and runtime inspection."""

from __future__ import annotations

import json
import os
from typing import Optional

from ._transaction import (
    FileChange,
    read_optional,
    regular_file_exists,
    source_change,
)
from .droid_config import (
    DroidSources,
    RenderedDocument,
    create_settings_document,
    parse_document,
)
from .droid_contract import AGENT_KEY, JsonObject, RuntimeContract, same_agent_id


def _factory_paths() -> tuple[str, str, str]:
    directory = os.path.join(os.path.expanduser("~"), ".factory")
    return (
        os.path.join(directory, "hooks.json"),
        os.path.join(directory, "hooks", "hooks.json"),
        os.path.join(directory, "settings.json"),
    )


def read_sources() -> DroidSources:
    root_path, legacy_path, settings_path = _factory_paths()
    root_raw = read_optional(root_path, "Factory Droid hooks")
    settings_raw = read_optional(settings_path, "Factory Droid settings")
    primary = None
    if root_raw is not None:
        primary = parse_document(
            exists=True,
            file_path=root_path,
            kind="hooks",
            raw=root_raw,
        )
    else:
        legacy_raw = read_optional(legacy_path, "Factory Droid legacy hooks")
        if legacy_raw is not None:
            primary = parse_document(
                exists=True,
                file_path=legacy_path,
                kind="legacy",
                raw=legacy_raw,
            )
    settings = (
        create_settings_document(settings_path)
        if settings_raw is None
        else parse_document(
            exists=True,
            file_path=settings_path,
            kind="settings",
            raw=settings_raw,
        )
    )
    return DroidSources(root_path, primary, settings)


def rendered_change(rendered: RenderedDocument) -> Optional[FileChange]:
    if not rendered.changed:
        return None
    if rendered.document.kind == "settings":
        label = "Factory Droid settings"
    elif rendered.document.kind == "legacy":
        label = "Factory Droid legacy hooks"
    else:
        label = "Factory Droid hooks"
    return source_change(
        rendered.document.file_path,
        label,
        rendered.document.raw if rendered.document.exists else None,
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


def runtime_files_exist(contracts: list[RuntimeContract]) -> bool:
    for contract in contracts:
        agent_directory = os.path.dirname(contract.guard_path)
        config = _read_runtime_config(os.path.join(agent_directory, "config.json"))
        config_agent_id = config.get("agent_id") if config else None
        if (
            config is None
            or config.get("agent_name") != AGENT_KEY
            or not isinstance(config_agent_id, str)
            or not same_agent_id(config_agent_id, contract.agent_id)
        ):
            continue
        if regular_file_exists(
            contract.guard_path, "Elydora guard runtime"
        ) and regular_file_exists(contract.audit_path, "Elydora audit runtime"):
            return True
    return False


def display_config_path(sources: DroidSources) -> str:
    if sources.primary is not None:
        return sources.primary.file_path
    if sources.settings.exists and sources.settings.has_hooks_container:
        return sources.settings.file_path
    return sources.root_path
