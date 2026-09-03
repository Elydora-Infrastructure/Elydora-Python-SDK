"""Runtime directory identity, config validation, and status checks shared by providers."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import json
import os
from typing import Any, List, Optional, Protocol, Tuple
import urllib.parse

from elydora._runtime_paths import resolve_agent_directory, runtime_root

from ._managed_files import (
    MAX_CONFIG_BYTES,
    MAX_SECRET_BYTES,
    MAX_SOURCE_BYTES,
    physical_directory_exists,
    physical_file_exists,
    read_physical_file,
)
from ._strict_json import JsonObject, parse_json_object
from ._transaction import FileChange, file_change, source_change
from .base import InstallConfig
from .guard_template import generate_guard_script
from .hook_template import generate_hook_script


GUARD_SCRIPT = "guard.py"
AUDIT_SCRIPT = "hook.py"
DEFAULT_BASE_URL = "https://api.elydora.com"
RUNTIME_CONFIG_FIELDS = frozenset(
    {"org_id", "agent_id", "kid", "base_url", "token", "agent_name"}
)
RUNTIME_ARTIFACTS = (
    ("private.key", "Elydora private key"),
    ("guard.py", "Elydora guard runtime"),
    ("hook.py", "Elydora audit runtime"),
    ("chain-state.json", "Elydora chain state"),
    ("status-cache.json", "Elydora status cache"),
    ("error.log", "Elydora error log"),
)


@dataclass(frozen=True)
class RuntimePaths:
    agent_id: str
    agent_directory: str
    guard_path: str
    audit_path: str


class RuntimeContractLike(Protocol):
    @property
    def agent_id(self) -> str: ...

    @property
    def guard_path(self) -> str: ...

    @property
    def audit_path(self) -> str: ...


def same_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(
        os.path.abspath(right)
    )


def same_agent_id(value: Any, expected: str) -> bool:
    return isinstance(value, str) and os.path.normcase(value) == os.path.normcase(
        expected
    )


def managed_script_reference(
    script_path: str, script_name: str
) -> Optional[Tuple[str, str]]:
    """Return (agent_id, script_path) for an absolute ~/.elydora/<id>/<script_name>."""
    if not os.path.isabs(script_path) or os.path.basename(script_path) != script_name:
        return None
    agent_directory = os.path.dirname(script_path)
    if not same_path(os.path.dirname(agent_directory), runtime_root()):
        return None
    agent_id = os.path.basename(agent_directory)
    if agent_id in ("", ".", ".."):
        return None
    return agent_id, script_path


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


def require_non_empty_string(value: Any, field: str, config_path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Elydora runtime config {field} is invalid: {config_path}")
    return value


def read_runtime_config(file_path: str) -> Optional[JsonObject]:
    snapshot = read_physical_file(file_path, "Elydora runtime config", MAX_CONFIG_BYTES)
    if snapshot is None:
        return None
    return parse_json_object(snapshot.contents, f"Elydora runtime config at {file_path}")


def validate_runtime_config(
    config: JsonObject,
    expected_agent_id: str,
    config_path: str,
    agent_key: str,
    product_label: str,
) -> None:
    extra = next((key for key in config if key not in RUNTIME_CONFIG_FIELDS), None)
    if extra is not None:
        raise ValueError(
            f'Elydora runtime config has unsupported field "{extra}": {config_path}'
        )
    require_non_empty_string(config.get("org_id"), "org_id", config_path)
    require_non_empty_string(config.get("kid"), "kid", config_path)
    agent_id = require_non_empty_string(config.get("agent_id"), "agent_id", config_path)
    if not same_agent_id(agent_id, expected_agent_id) or config.get("agent_name") != agent_key:
        raise ValueError(
            f"Elydora runtime identity does not match {product_label} hooks: {config_path}"
        )
    if "token" in config:
        require_non_empty_string(config.get("token"), "token", config_path)
    base_url = require_non_empty_string(config.get("base_url"), "base_url", config_path)
    validate_api_origin(base_url, "Elydora runtime config base_url")


def runtime_config_source(config: InstallConfig, agent_id: str, agent_key: str) -> str:
    value = {
        "org_id": config.get("org_id", ""),
        "agent_id": agent_id,
        "kid": config.get("kid", ""),
        "base_url": config.get("base_url", DEFAULT_BASE_URL),
        "agent_name": agent_key,
    }
    token = config.get("token")
    if token:
        value["token"] = token
    return json.dumps(value, indent=2) + "\n"


def resolve_runtime_paths(config: InstallConfig) -> RuntimePaths:
    agent_id = config.get("agent_id", "")
    if not agent_id:
        raise ValueError("agent_id is required")
    agent_directory = resolve_agent_directory(runtime_root(), agent_id)
    guard_path = os.path.join(agent_directory, GUARD_SCRIPT)
    if not same_path(config.get("guard_script_path", ""), guard_path):
        raise ValueError(
            f"Elydora guard runtime must use the managed agent directory: {guard_path}"
        )
    return RuntimePaths(
        agent_id, agent_directory, guard_path, os.path.join(agent_directory, AUDIT_SCRIPT)
    )


def validate_install_config(
    config: InstallConfig, agent_key: str, product_label: str
) -> None:
    for field in ("org_id", "agent_id", "kid", "private_key", "base_url"):
        value = config.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{field} is required")
    if config.get("agent_name") != agent_key:
        raise ValueError(f"{product_label} installation requires agent_name {agent_key}")
    validate_private_key(config["private_key"])
    validate_api_origin(config["base_url"])
    if "token" in config:
        token = config["token"]
        if not isinstance(token, str) or not token:
            raise ValueError("token must be a non-empty string when provided")
    resolve_runtime_paths(config)


def validate_runtime_tree(
    agent_directory: str,
    agent_id: str,
    agent_key: str,
    product_label: str,
    extra_artifacts: Tuple[Tuple[str, str], ...] = (),
) -> None:
    """Reject an existing agent directory that belongs to another identity."""
    if not physical_directory_exists(runtime_root(), "Elydora runtime directory"):
        return
    if not physical_directory_exists(agent_directory, "Elydora agent runtime directory"):
        return
    config_path = os.path.join(agent_directory, "config.json")
    config = read_runtime_config(config_path)
    artifact_states = [
        physical_file_exists(os.path.join(agent_directory, name), label)
        for name, label in (*RUNTIME_ARTIFACTS, *extra_artifacts)
    ]
    artifact_exists = any(artifact_states)
    if config is None:
        if artifact_exists:
            raise ValueError(
                "Elydora runtime identity cannot be verified without config.json: "
                f"{agent_directory}"
            )
        return
    if (
        not same_agent_id(config.get("agent_id"), agent_id)
        or config.get("agent_name") != agent_key
    ):
        raise ValueError(
            f"Elydora runtime config identity does not match {product_label} agent "
            f"{agent_id}: {config_path}"
        )


def expected_runtime_scripts(agent_key: str, agent_id: str) -> Tuple[str, str]:
    return (
        generate_guard_script(agent_key, agent_id),
        generate_hook_script(
            org_id="",
            agent_id=agent_id,
            kid="",
            base_url="",
            native_payload=True,
            agent_name=agent_key,
        ),
    )


def runtime_contract_exists(
    contract: RuntimeContractLike,
    agent_key: str,
    product_label: str,
    expected_scripts: Optional[Tuple[str, str]] = None,
) -> bool:
    """Strict status check: valid config and key plus runtime scripts."""
    root = runtime_root()
    agent_directory = os.path.dirname(contract.guard_path)
    if not same_path(os.path.dirname(agent_directory), root) or not same_path(
        contract.audit_path, os.path.join(agent_directory, AUDIT_SCRIPT)
    ):
        return False
    if not physical_directory_exists(root, "Elydora runtime directory"):
        return False
    if not physical_directory_exists(agent_directory, "Elydora agent runtime directory"):
        return False
    config_path = os.path.join(agent_directory, "config.json")
    config = read_runtime_config(config_path)
    key = read_physical_file(
        os.path.join(agent_directory, "private.key"), "Elydora private key", MAX_SECRET_BYTES
    )
    guard = read_physical_file(contract.guard_path, "Elydora guard runtime")
    audit = read_physical_file(contract.audit_path, "Elydora audit runtime")
    if config is None or key is None or guard is None or audit is None:
        return False
    validate_runtime_config(config, contract.agent_id, config_path, agent_key, product_label)
    validate_private_key(key.contents, "Elydora private key")
    if expected_scripts is None:
        return bool(guard.contents) and bool(audit.contents)
    return guard.contents == expected_scripts[0] and audit.contents == expected_scripts[1]


def runtime_present(contract: RuntimeContractLike, agent_key: str) -> bool:
    """Presence-only status check; identity mismatch reports False."""
    agent_directory = os.path.dirname(contract.guard_path)
    if not physical_directory_exists(agent_directory, "Elydora agent runtime directory"):
        return False
    config = read_runtime_config(os.path.join(agent_directory, "config.json"))
    if (
        config is None
        or config.get("agent_name") != agent_key
        or not same_agent_id(config.get("agent_id"), contract.agent_id)
    ):
        return False
    return all(
        (
            physical_file_exists(contract.guard_path, "Elydora guard runtime"),
            physical_file_exists(contract.audit_path, "Elydora audit runtime"),
            physical_file_exists(
                os.path.join(agent_directory, "private.key"), "Elydora private key"
            ),
        )
    )


def present(changes: List[Optional[FileChange]]) -> List[FileChange]:
    return [change for change in changes if change is not None]


def runtime_file_changes(
    config: InstallConfig,
    paths: RuntimePaths,
    agent_key: str,
    guard_script: str,
    audit_script: str,
) -> List[FileChange]:
    """Changes for the guard, config, key, and audit runtime files."""
    return present([
        file_change(paths.guard_path, "Elydora guard runtime", guard_script, 0o700),
        file_change(
            os.path.join(paths.agent_directory, "config.json"),
            "Elydora runtime config",
            runtime_config_source(config, paths.agent_id, agent_key),
            0o600,
            MAX_CONFIG_BYTES,
        ),
        file_change(
            os.path.join(paths.agent_directory, "private.key"),
            "Elydora private key",
            config.get("private_key", ""),
            0o600,
            MAX_SECRET_BYTES,
        ),
        file_change(paths.audit_path, "Elydora audit runtime", audit_script, 0o700),
    ])


def rendered_source_change(
    file_path: str,
    label: str,
    original: Optional[str],
    next_source: Optional[str],
) -> Optional[FileChange]:
    return source_change(file_path, label, original, next_source, 0o600, MAX_SOURCE_BYTES)
