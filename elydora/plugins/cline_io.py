"""Physical Cline hook and managed runtime validation."""

from __future__ import annotations

import base64
import os
from typing import Any, Optional
import urllib.parse

from ._managed_files import (
    MAX_CONFIG_BYTES,
    MAX_SECRET_BYTES,
    physical_directory_exists,
    physical_file_exists,
    read_physical_file,
)
from ._strict_json import JsonObject, parse_json_object
from .cline_contract import (
    AGENT_KEY,
    AUDIT_SCRIPT,
    GUARD_SCRIPT,
    HookFile,
    RuntimeContract,
    elydora_dir,
    parse_metadata,
    same_agent_id,
)
from .guard_template import generate_guard_script
from .hook_template import generate_hook_script


def _same_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(
        os.path.abspath(right)
    )


def validate_hook_tree(hooks_directory: str) -> None:
    physical_directory_exists(
        os.path.dirname(hooks_directory), "Cline configuration directory"
    )
    physical_directory_exists(hooks_directory, "Cline hooks directory")


def read_hook_file(file_path: str) -> HookFile:
    validate_hook_tree(os.path.dirname(file_path))
    snapshot = read_physical_file(file_path, "Cline hook")
    if snapshot is None:
        return HookFile(False, file_path)
    return HookFile(
        exists=True,
        file_path=file_path,
        source=snapshot.contents,
        metadata=parse_metadata(file_path, snapshot.contents),
    )


def require_available_hook_file(file: HookFile) -> None:
    if file.exists and file.metadata is None:
        raise ValueError(
            f"Cline hook at {file.file_path} already exists and is owned "
            "by another integration"
        )


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
            padded.replace("-", "+").replace("_", "/"), validate=True
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
        raise ValueError(f"Elydora runtime config {field} is invalid: {config_path}")
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
        not same_agent_id(agent_id, expected_agent_id)
        or config.get("agent_name") != AGENT_KEY
    ):
        raise ValueError(
            f"Elydora runtime identity does not match Cline hooks: {config_path}"
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
    root = elydora_dir()
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
        (GUARD_SCRIPT, "Elydora guard runtime"),
        (AUDIT_SCRIPT, "Elydora audit runtime"),
        ("chain-state.json", "Elydora chain state"),
        ("status-cache.json", "Elydora status cache"),
        ("error.log", "Elydora error log"),
    )
    artifact_exists = any(
        physical_file_exists(os.path.join(agent_directory, name), label)
        for name, label in artifacts
    )
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
        or not same_agent_id(configured_id, agent_id)
        or config.get("agent_name") != AGENT_KEY
    ):
        raise ValueError(
            "Elydora runtime config identity does not match Cline agent "
            f"{agent_id}: {config_path}"
        )


def _valid_contract_paths(contract: RuntimeContract) -> bool:
    return (
        _same_path(os.path.dirname(contract.agent_directory), elydora_dir())
        and _same_path(
            contract.guard_path,
            os.path.join(contract.agent_directory, GUARD_SCRIPT),
        )
        and _same_path(
            contract.audit_path,
            os.path.join(contract.agent_directory, AUDIT_SCRIPT),
        )
    )


def runtime_files_exist(contract: RuntimeContract) -> bool:
    if not _valid_contract_paths(contract):
        return False
    root = elydora_dir()
    if not physical_directory_exists(root, "Elydora runtime directory"):
        return False
    if not physical_directory_exists(
        contract.agent_directory, "Elydora agent runtime directory"
    ):
        return False
    config_path = os.path.join(contract.agent_directory, "config.json")
    key_path = os.path.join(contract.agent_directory, "private.key")
    config = _read_runtime_config(config_path)
    key = read_physical_file(key_path, "Elydora private key", MAX_SECRET_BYTES)
    guard = read_physical_file(contract.guard_path, "Elydora guard runtime")
    audit = read_physical_file(contract.audit_path, "Elydora audit runtime")
    if any(item is None for item in (config, key, guard, audit)):
        return False
    assert config is not None
    assert key is not None
    assert guard is not None
    assert audit is not None
    _validate_runtime_config(config, contract.agent_id, config_path)
    validate_private_key(key.contents, "Elydora private key")
    expected_audit = generate_hook_script(
        org_id="",
        agent_id=contract.agent_id,
        kid="",
        base_url="",
        native_payload=True,
        agent_name=AGENT_KEY,
    )
    return (
        guard.contents == generate_guard_script(AGENT_KEY, contract.agent_id)
        and audit.contents == expected_audit
    )


__all__ = [
    "read_hook_file",
    "require_available_hook_file",
    "runtime_files_exist",
    "validate_api_origin",
    "validate_hook_tree",
    "validate_private_key",
    "validate_runtime_tree",
]
