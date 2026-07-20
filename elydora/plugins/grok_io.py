"""Grok user-hook discovery and managed runtime I/O."""

from __future__ import annotations

import base64
import os
from typing import Any, List, Optional
import urllib.parse

from ._managed_files import (
    MAX_CONFIG_BYTES,
    MAX_SECRET_BYTES,
    physical_directory_exists,
    physical_file_exists,
    read_physical_file,
)
from ._strict_json import JsonObject, parse_json_object
from .grok_command import runtime_root, same_grok_agent_id, same_grok_path
from .grok_contract import (
    AGENT_KEY,
    GrokDocument,
    GrokRuntimeContract,
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
    physical_directory_exists(
        os.path.dirname(hooks_directory), "Grok home directory"
    )
    physical_directory_exists(hooks_directory, "Grok hooks directory")
    snapshot = read_physical_file(config_path, "Grok user hooks")
    if snapshot is None:
        return create_grok_document(config_path)
    return parse_grok_document(config_path, snapshot.contents)


def validate_api_origin(value: str, label: str = "base_url") -> None:
    try:
        parsed = urllib.parse.urlsplit(value)
        hostname = parsed.hostname
        parsed.port
    except ValueError as error:
        raise ValueError(f"{label} must be an absolute HTTP or HTTPS URL") from error
    invalid_character = "\\" in value or any(
        character.isspace() or ord(character) < 32 for character in value
    )
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.netloc
        or hostname is None
        or invalid_character
    ):
        raise ValueError(f"{label} must be an absolute HTTP or HTTPS URL")
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            f"{label} must exclude credentials, query parameters, and fragments"
        )


def validate_private_key(value: str, label: str = "private_key") -> None:
    try:
        padded = value + "=" * ((4 - len(value) % 4) % 4)
        seed = base64.b64decode(
            padded.replace("-", "+").replace("_", "/"),
            validate=True,
        )
        canonical = base64.urlsafe_b64encode(seed).rstrip(b"=").decode("ascii")
    except (ValueError, UnicodeEncodeError) as error:
        raise ValueError(
            f"{label} must be a canonical 32-byte base64url value"
        ) from error
    if len(seed) != 32 or canonical != value:
        raise ValueError(f"{label} must be a canonical 32-byte base64url value")


def _require_non_empty_string(value: Any, field: str, config_path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"Elydora runtime config {field} is invalid: {config_path}"
        )
    return value


def _validate_runtime_config(
    config: JsonObject, expected_agent_id: str, config_path: str
) -> None:
    supported = {"org_id", "agent_id", "kid", "base_url", "token", "agent_name"}
    extra = next((key for key in config if key not in supported), None)
    if extra is not None:
        raise ValueError(
            f'Elydora runtime config has unsupported field "{extra}": {config_path}'
        )
    _require_non_empty_string(config.get("org_id"), "org_id", config_path)
    _require_non_empty_string(config.get("kid"), "kid", config_path)
    agent_id = _require_non_empty_string(
        config.get("agent_id"), "agent_id", config_path
    )
    if (
        not same_grok_agent_id(agent_id, expected_agent_id)
        or config.get("agent_name") != AGENT_KEY
    ):
        raise ValueError(
            f"Elydora runtime identity does not match Grok hooks: {config_path}"
        )
    if "token" in config:
        _require_non_empty_string(config.get("token"), "token", config_path)
    base_url = _require_non_empty_string(
        config.get("base_url"), "base_url", config_path
    )
    validate_api_origin(base_url, "Elydora runtime config base_url")


def _read_runtime_config(file_path: str) -> Optional[JsonObject]:
    snapshot = read_physical_file(
        file_path, "Elydora runtime config", MAX_CONFIG_BYTES
    )
    if snapshot is None:
        return None
    return parse_json_object(
        snapshot.contents, f"Elydora runtime config at {file_path}"
    )


def validate_runtime_tree(agent_directory: str, agent_id: str) -> None:
    root = runtime_root()
    if not physical_directory_exists(root, "Elydora runtime directory"):
        return
    if not physical_directory_exists(
        agent_directory, "Elydora agent runtime directory"
    ):
        return
    config_path = os.path.join(agent_directory, "config.json")
    config = _read_runtime_config(config_path)
    artifacts = (
        ("private.key", "Elydora private key"),
        ("guard.py", "Elydora guard runtime"),
        ("hook.py", "Elydora audit runtime"),
        ("chain-state.json", "Elydora chain state"),
        ("status-cache.json", "Elydora status cache"),
        ("error.log", "Elydora error log"),
    )
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
        return
    configured_id = config.get("agent_id")
    if (
        not isinstance(configured_id, str)
        or not same_grok_agent_id(configured_id, agent_id)
        or config.get("agent_name") != AGENT_KEY
    ):
        raise ValueError(
            f"Elydora runtime config identity does not match Grok agent {agent_id}: "
            f"{config_path}"
        )


def _runtime_contract_exists(contract: GrokRuntimeContract) -> bool:
    root = runtime_root()
    agent_directory = os.path.dirname(contract.guard_path)
    if (
        not same_grok_path(os.path.dirname(agent_directory), root)
        or not same_grok_path(
            contract.audit_path, os.path.join(agent_directory, "hook.py")
        )
    ):
        return False
    if not physical_directory_exists(root, "Elydora runtime directory"):
        return False
    if not physical_directory_exists(
        agent_directory, "Elydora agent runtime directory"
    ):
        return False
    config_path = os.path.join(agent_directory, "config.json")
    key_path = os.path.join(agent_directory, "private.key")
    config = _read_runtime_config(config_path)
    key = read_physical_file(key_path, "Elydora private key", MAX_SECRET_BYTES)
    guard = read_physical_file(contract.guard_path, "Elydora guard runtime")
    audit = read_physical_file(contract.audit_path, "Elydora audit runtime")
    if config is None or key is None or guard is None or audit is None:
        return False
    _validate_runtime_config(config, contract.agent_id, config_path)
    validate_private_key(key.contents, "Elydora private key")
    return bool(guard.contents) and bool(audit.contents)


def grok_runtime_files_exist(contracts: List[GrokRuntimeContract]) -> bool:
    return any(_runtime_contract_exists(contract) for contract in contracts)
