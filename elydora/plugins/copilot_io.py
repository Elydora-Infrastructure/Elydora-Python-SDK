"""GitHub Copilot CLI source discovery and managed runtime validation."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import os
from typing import Any, List, Optional, Tuple
import urllib.parse

from ._jsonc import parse_jsonc
from ._managed_files import (
    FileSnapshot,
    MAX_CONFIG_BYTES,
    MAX_SECRET_BYTES,
    MAX_SOURCE_BYTES,
    physical_directory_exists,
    physical_file_exists,
    read_physical_file,
)
from ._strict_json import JsonObject, parse_json_object
from .copilot_contract import (
    AGENT_KEY,
    AUDIT_SCRIPT,
    CONFIG_FILE,
    GUARD_SCRIPT,
    CopilotDocument,
    CopilotSources,
    RuntimeContract,
    SourcePrecondition,
    create_document,
    parse_document,
    runtime_root,
    same_agent_id,
    same_path,
)
from .guard_template import generate_guard_script
from .hook_template import generate_hook_script


@dataclass(frozen=True)
class SettingsLayer:
    file_path: str
    label: str
    jsonc: bool


@dataclass(frozen=True)
class CopilotPaths:
    copilot_home: str
    user_hooks_directory: str
    user_hook_path: str
    legacy_hook_path: str
    settings_layers: Tuple[SettingsLayer, ...]
    inspected_directories: Tuple[Tuple[str, str], ...]


@dataclass(frozen=True)
class _ParsedSettingsLayer:
    layer: SettingsLayer
    disable_all_hooks: Optional[bool]
    snapshot: Optional[FileSnapshot]


def resolve_copilot_paths(home_dir: Optional[str] = None) -> CopilotPaths:
    home = home_dir if home_dir is not None else os.path.expanduser("~")
    override = os.environ.get("COPILOT_HOME")
    copilot_home = override if override else os.path.join(home, ".copilot")
    project = os.getcwd()
    github = os.path.join(project, ".github")
    github_copilot = os.path.join(github, "copilot")
    github_hooks = os.path.join(github, "hooks")
    claude = os.path.join(project, ".claude")
    user_hooks = os.path.join(copilot_home, "hooks")
    return CopilotPaths(
        copilot_home=copilot_home,
        user_hooks_directory=user_hooks,
        user_hook_path=os.path.join(user_hooks, CONFIG_FILE),
        legacy_hook_path=os.path.join(github_hooks, "hooks.json"),
        settings_layers=(
            SettingsLayer(
                os.path.join(copilot_home, "config.json"),
                "legacy Copilot user config",
                False,
            ),
            SettingsLayer(
                os.path.join(copilot_home, "settings.json"),
                "Copilot user settings",
                True,
            ),
            SettingsLayer(
                os.path.join(claude, "settings.json"),
                "Claude repository settings",
                True,
            ),
            SettingsLayer(
                os.path.join(claude, "settings.local.json"),
                "Claude local settings",
                True,
            ),
            SettingsLayer(
                os.path.join(github_copilot, "settings.json"),
                "Copilot repository settings",
                True,
            ),
            SettingsLayer(
                os.path.join(github_copilot, "settings.local.json"),
                "Copilot local settings",
                True,
            ),
        ),
        inspected_directories=(
            (project, "Copilot working directory"),
            (copilot_home, "COPILOT_HOME"),
            (user_hooks, "Copilot user hooks directory"),
            (github, "GitHub configuration directory"),
            (github_hooks, "GitHub repository hooks directory"),
            (github_copilot, "Copilot repository settings directory"),
            (claude, "Claude repository settings directory"),
        ),
    )


def _inspect_directories(locations: Tuple[Tuple[str, str], ...]) -> None:
    for directory, label in locations:
        physical_directory_exists(directory, label)


def _read_hook_document(
    file_path: str, label: str
) -> Optional[CopilotDocument]:
    snapshot = read_physical_file(file_path, label, MAX_SOURCE_BYTES)
    return None if snapshot is None else parse_document(file_path, snapshot, label)


def _parse_settings(raw: str, layer: SettingsLayer) -> JsonObject:
    if not raw.strip():
        return {}
    label = f"{layer.label} at {layer.file_path}"
    value = (
        parse_jsonc(raw, label, allow_trailing_commas=True)
        if layer.jsonc
        else parse_json_object(raw, label)
    )
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return value


def _read_settings_layer(layer: SettingsLayer) -> _ParsedSettingsLayer:
    snapshot = read_physical_file(
        layer.file_path, layer.label, MAX_SOURCE_BYTES
    )
    if snapshot is None:
        return _ParsedSettingsLayer(layer, None, None)
    root = _parse_settings(snapshot.contents, layer)
    disabled = root.get("disableAllHooks")
    if "disableAllHooks" in root and not isinstance(disabled, bool):
        raise ValueError(
            f'{layer.label} at {layer.file_path} field "disableAllHooks" '
            "must be a boolean"
        )
    return _ParsedSettingsLayer(layer, disabled, snapshot)


def _effective_disabled_source(
    layers: List[_ParsedSettingsLayer],
) -> Optional[str]:
    disabled_by: Optional[str] = None
    for item in layers:
        source = f"{item.layer.label} at {item.layer.file_path}"
        if item.disable_all_hooks is True:
            disabled_by = source
        elif item.disable_all_hooks is False:
            disabled_by = None
    return disabled_by


def read_sources(home_dir: Optional[str] = None) -> CopilotSources:
    paths = resolve_copilot_paths(home_dir)
    _inspect_directories(paths.inspected_directories)
    user = _read_hook_document(
        paths.user_hook_path, "GitHub Copilot user hooks"
    )
    legacy = _read_hook_document(
        paths.legacy_hook_path, "GitHub Copilot legacy project hooks"
    )
    layers = [_read_settings_layer(layer) for layer in paths.settings_layers]
    user_document = user or create_document(paths.user_hook_path)
    disabled_by = (
        f"GitHub Copilot user hooks at {paths.user_hook_path}"
        if user_document.hooks_disabled
        else _effective_disabled_source(layers)
    )
    preconditions = tuple(
        SourcePrecondition(
            item.layer.file_path,
            item.layer.label,
            item.snapshot,
        )
        for item in layers
    )
    return CopilotSources(
        user_document,
        legacy,
        disabled_by,
        preconditions,
    )


def require_hooks_enabled(sources: CopilotSources) -> None:
    if sources.disabled_by:
        raise ValueError(
            "GitHub Copilot hooks are disabled by "
            f"{sources.disabled_by}; set disableAllHooks to false before installation"
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
            f'Elydora runtime config has unsupported field "{extra}": {config_path}'
        )
    _require_string(config.get("org_id"), "org_id", config_path)
    _require_string(config.get("kid"), "kid", config_path)
    agent_id = _require_string(config.get("agent_id"), "agent_id", config_path)
    if (
        not same_agent_id(agent_id, contract.agent_id)
        or config.get("agent_name") != AGENT_KEY
    ):
        raise ValueError(
            f"Elydora runtime identity does not match Copilot hooks: {config_path}"
        )
    if "token" in config:
        _require_string(config.get("token"), "token", config_path)
    base_url = _require_string(config.get("base_url"), "base_url", config_path)
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
            "Elydora runtime config identity does not match Copilot agent "
            f"{agent_id}: {config_path}"
        )


def _valid_contract_paths(contract: RuntimeContract) -> bool:
    agent_directory = os.path.dirname(contract.guard_path)
    return (
        same_path(os.path.dirname(agent_directory), runtime_root())
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
    root = runtime_root()
    agent_directory = os.path.dirname(contract.guard_path)
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


def runtime_files_exist(contracts: List[RuntimeContract]) -> bool:
    return any(_runtime_contract_exists(contract) for contract in contracts)
