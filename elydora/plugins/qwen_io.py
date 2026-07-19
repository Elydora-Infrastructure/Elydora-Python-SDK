"""Qwen Code home discovery, settings I/O, and runtime inspection."""

from __future__ import annotations

import json
import os
import re
import tempfile
from typing import Optional

from ._dotenv import parse_dotenv
from ._transaction import (
    FileChange,
    read_optional,
    regular_file_exists,
    require_runtime,
    source_change,
)
from .qwen_config import (
    QwenDocument,
    RenderedDocument,
    create_owned_document,
    parse_document,
)
from .qwen_contract import AGENT_KEY, JsonObject, RuntimeContract, same_agent_id


def _default_qwen_home() -> str:
    home_dir = os.path.expanduser("~")
    if not home_dir or home_dir == "~":
        home_dir = tempfile.gettempdir()
    return os.path.join(home_dir, ".qwen")


def _resolve_storage_path(value: str) -> str:
    resolved = value
    if value == "~":
        resolved = os.path.expanduser("~")
    elif value.startswith(("~/", "~\\")):
        segments = [item for item in re.split(r"[/\\]+", value[2:]) if item]
        resolved = os.path.join(os.path.expanduser("~"), *segments)
    return resolved if os.path.isabs(resolved) else os.path.abspath(resolved)


def _qwen_home_from_env_file(file_path: str) -> Optional[str]:
    raw = read_optional(file_path, "Qwen home environment")
    if raw is None:
        return None
    value = parse_dotenv(raw).get("QWEN_HOME")
    return value or None


def resolve_qwen_home() -> str:
    initial_value = os.environ.get("QWEN_HOME")
    initial_home = (
        _resolve_storage_path(initial_value) if initial_value else _default_qwen_home()
    )
    if "QWEN_HOME" in os.environ:
        return initial_home
    candidates = (
        os.path.join(initial_home, ".env"),
        os.path.join(os.path.dirname(initial_home), ".env"),
    )
    for candidate in candidates:
        discovered = _qwen_home_from_env_file(candidate)
        if discovered:
            return _resolve_storage_path(discovered)
    return initial_home


def read_document() -> QwenDocument:
    config_path = os.path.join(resolve_qwen_home(), "settings.json")
    raw = read_optional(config_path, "Qwen Code settings")
    if raw is None:
        return create_owned_document(config_path)
    return parse_document(exists=True, file_path=config_path, raw=raw)


def rendered_change(rendered: RenderedDocument) -> Optional[FileChange]:
    if not rendered.changed:
        return None
    return source_change(
        rendered.document.file_path,
        "Qwen Code settings",
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
        runtime_config = _read_runtime_config(
            os.path.join(agent_directory, "config.json")
        )
        config_agent_id = runtime_config.get("agent_id") if runtime_config else None
        if (
            runtime_config is None
            or runtime_config.get("agent_name") != AGENT_KEY
            or not isinstance(config_agent_id, str)
            or not same_agent_id(config_agent_id, contract.agent_id)
        ):
            continue
        if regular_file_exists(
            contract.guard_path,
            "Elydora guard runtime",
        ) and regular_file_exists(
            contract.audit_path,
            "Elydora audit runtime",
        ):
            return True
    return False


__all__ = [
    "read_document",
    "rendered_change",
    "require_runtime",
    "resolve_qwen_home",
    "runtime_files_exist",
]
