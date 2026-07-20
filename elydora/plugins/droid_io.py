"""Factory Droid source discovery and managed runtime validation."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import os
from typing import Any, Optional
import urllib.parse

from ._managed_files import (
    MAX_CONFIG_BYTES,
    MAX_SECRET_BYTES,
    MAX_SOURCE_BYTES,
    physical_directory_exists,
    physical_file_exists,
    read_physical_file,
)
from ._strict_json import JsonObject, parse_json_object
from .droid_config import (
    DroidDocument,
    DroidSources,
    active_document,
    create_legacy_hook_document,
    create_owned_hook_document,
    create_settings_document,
    hook_block,
    parse_document,
)
from .droid_contract import (
    AGENT_KEY,
    AUDIT_SCRIPT,
    GUARD_SCRIPT,
    RuntimeContract,
    elydora_dir,
    same_agent_id,
    same_path,
)
from .droid_policy import read_droid_policy
from .guard_template import generate_guard_script
from .hook_template import generate_hook_script


@dataclass(frozen=True)
class FactoryPaths:
    directory: str
    root: str
    legacy_directory: str
    legacy: str
    settings: str
    local_settings: str


def _factory_paths() -> FactoryPaths:
    directory = os.path.join(os.path.expanduser("~"), ".factory")
    legacy_directory = os.path.join(directory, "hooks")
    return FactoryPaths(
        directory,
        os.path.join(directory, "hooks.json"),
        legacy_directory,
        os.path.join(legacy_directory, "hooks.json"),
        os.path.join(directory, "settings.json"),
        os.path.join(directory, "settings.local.json"),
    )


def _read_document(
    file_path: str,
    kind: str,
    label: str,
) -> Optional[DroidDocument]:
    snapshot = read_physical_file(file_path, label, MAX_SOURCE_BYTES)
    if snapshot is None:
        return None
    return parse_document(
        exists=True,
        file_path=file_path,
        kind=kind,
        raw=snapshot.contents,
        snapshot=snapshot,
    )


def read_sources() -> DroidSources:
    paths = _factory_paths()
    physical_directory_exists(
        paths.directory,
        "Factory Droid user configuration directory",
    )
    physical_directory_exists(
        paths.legacy_directory,
        "Factory Droid legacy hooks directory",
    )
    root = _read_document(paths.root, "hooks", "Factory Droid user hooks")
    legacy = _read_document(
        paths.legacy,
        "legacy",
        "Factory Droid legacy hooks",
    )
    settings = _read_document(
        paths.settings,
        "settings",
        "Factory Droid user settings",
    )
    local_settings = _read_document(
        paths.local_settings,
        "local-settings",
        "Factory Droid local settings",
    )
    return DroidSources(
        root or create_owned_hook_document(paths.root),
        legacy or create_legacy_hook_document(paths.legacy),
        settings or create_settings_document(paths.settings),
        local_settings or create_settings_document(
            paths.local_settings,
            "local-settings",
        ),
        read_droid_policy(),
    )


def require_hooks_enabled(sources: DroidSources) -> None:
    blocked = hook_block(sources)
    if blocked is not None:
        raise ValueError(
            "Factory Droid user hooks are disabled by "
            f"{blocked.field} in {blocked.label} at {blocked.file_path}"
        )


def validate_api_origin(value: str, label: str = "base_url") -> None:
    try:
        parsed = urllib.parse.urlsplit(value)
        hostname = parsed.hostname
        parsed.port
    except ValueError as error:
        raise ValueError(
            f"{label} must be an absolute HTTP or HTTPS URL"
        ) from error
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


def _require_string(value: Any, field: str, config_path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"Elydora runtime config {field} is invalid: {config_path}"
        )
    return value


def _validate_runtime_config(
    config: JsonObject,
    contract: RuntimeContract,
    config_path: str,
) -> None:
    supported = {"org_id", "agent_id", "kid", "base_url", "token", "agent_name"}
    extra = next((key for key in config if key not in supported), None)
    if extra is not None:
        raise ValueError(
            f'Elydora runtime config has unsupported field "{extra}": '
            f"{config_path}"
        )
    _require_string(config.get("org_id"), "org_id", config_path)
    _require_string(config.get("kid"), "kid", config_path)
    agent_id = _require_string(config.get("agent_id"), "agent_id", config_path)
    if (
        not same_agent_id(agent_id, contract.agent_id)
        or config.get("agent_name") != AGENT_KEY
    ):
        raise ValueError(
            "Elydora runtime identity does not match Factory Droid hooks: "
            f"{config_path}"
        )
    if "token" in config:
        _require_string(config.get("token"), "token", config_path)
    base_url = _require_string(config.get("base_url"), "base_url", config_path)
    validate_api_origin(base_url, "Elydora runtime config base_url")


def _read_runtime_config(file_path: str) -> Optional[JsonObject]:
    snapshot = read_physical_file(
        file_path,
        "Elydora runtime config",
        MAX_CONFIG_BYTES,
    )
    if snapshot is None:
        return None
    return parse_json_object(
        snapshot.contents,
        f"Elydora runtime config at {file_path}",
    )


def validate_runtime_tree(agent_directory: str, agent_id: str) -> None:
    root = elydora_dir()
    if not physical_directory_exists(root, "Elydora runtime directory"):
        return
    if not physical_directory_exists(
        agent_directory,
        "Elydora agent runtime directory",
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
            "Elydora runtime config identity does not match Factory Droid agent "
            f"{agent_id}: {config_path}"
        )


def _valid_contract_paths(contract: RuntimeContract) -> bool:
    agent_directory = os.path.dirname(contract.guard_path)
    return (
        same_path(os.path.dirname(agent_directory), elydora_dir())
        and same_path(
            contract.guard_path,
            os.path.join(agent_directory, GUARD_SCRIPT),
        )
        and same_path(
            contract.audit_path,
            os.path.join(agent_directory, AUDIT_SCRIPT),
        )
    )


def _runtime_contract_exists(contract: RuntimeContract) -> bool:
    if not _valid_contract_paths(contract):
        return False
    root = elydora_dir()
    agent_directory = os.path.dirname(contract.guard_path)
    if not physical_directory_exists(root, "Elydora runtime directory"):
        return False
    if not physical_directory_exists(
        agent_directory,
        "Elydora agent runtime directory",
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
    _validate_runtime_config(config, contract, config_path)
    validate_private_key(key.contents, "Elydora private key")
    expected_guard = generate_guard_script(AGENT_KEY, contract.agent_id)
    expected_audit = generate_hook_script(
        org_id="",
        agent_id=contract.agent_id,
        kid="",
        base_url="",
        native_payload=True,
        agent_name=AGENT_KEY,
    )
    return guard.contents == expected_guard and audit.contents == expected_audit


def runtime_files_exist(contracts: list[RuntimeContract]) -> bool:
    return any(_runtime_contract_exists(contract) for contract in contracts)


def display_config_path(sources: DroidSources) -> str:
    return active_document(sources).file_path
