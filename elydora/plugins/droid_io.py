"""Factory Droid source discovery and managed runtime validation."""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import List, Optional

from ._managed_files import MAX_SOURCE_BYTES, physical_directory_exists, read_physical_file
from ._runtime import expected_runtime_scripts, runtime_contract_exists
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
from .droid_contract import AGENT_KEY, RuntimeContract
from .droid_policy import read_droid_policy


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


def runtime_files_exist(contracts: List[RuntimeContract]) -> bool:
    return any(
        runtime_contract_exists(
            contract,
            AGENT_KEY,
            "Factory Droid",
            expected_runtime_scripts(AGENT_KEY, contract.agent_id),
        )
        for contract in contracts
    )


def display_config_path(sources: DroidSources) -> str:
    return active_document(sources).file_path
