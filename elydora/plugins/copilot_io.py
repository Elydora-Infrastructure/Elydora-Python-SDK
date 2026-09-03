"""GitHub Copilot CLI source discovery and managed runtime validation."""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import List, Optional, Tuple

from ._jsonc import parse_jsonc
from ._managed_files import (
    FileSnapshot,
    MAX_SOURCE_BYTES,
    physical_directory_exists,
    read_physical_file,
)
from ._runtime import expected_runtime_scripts, runtime_contract_exists
from ._strict_json import JsonObject, parse_json_object
from .copilot_contract import (
    AGENT_KEY,
    CONFIG_FILE,
    CopilotDocument,
    CopilotSources,
    RuntimeContract,
    SourcePrecondition,
    create_document,
    parse_document,
)


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


def runtime_files_exist(contracts: List[RuntimeContract]) -> bool:
    return any(
        runtime_contract_exists(
            contract,
            AGENT_KEY,
            "Copilot",
            expected_runtime_scripts(AGENT_KEY, contract.agent_id),
        )
        for contract in contracts
    )
