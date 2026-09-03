"""Kimi configuration discovery and managed runtime I/O."""

from __future__ import annotations

import os
from typing import List

from ._managed_files import physical_directory_exists, read_physical_file
from ._runtime import runtime_contract_exists, same_path
from .kimi_contract import (
    AGENT_KEY,
    LEGACY_EVENTS,
    STABLE_EVENTS,
    KimiContract,
    KimiDocument,
    KimiRuntimeContract,
    create_kimi_document,
    parse_kimi_document,
)


def _entry_exists(file_path: str, label: str) -> bool:
    try:
        os.lstat(file_path)
        return True
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError as error:
        raise OSError(f"Inspect {label} at {file_path}: {error}") from error


def _stable_contract(config_path: str) -> KimiContract:
    return KimiContract(
        generation="stable",
        runtime_name="Kimi Code",
        label="Kimi Code hooks config",
        directory_label="Kimi Code home directory",
        config_path=config_path,
        events=frozenset(STABLE_EVENTS),
    )


def _legacy_contract(config_path: str) -> KimiContract:
    return KimiContract(
        generation="legacy",
        runtime_name="kimi-cli",
        label="kimi-cli legacy hooks config",
        directory_label="kimi-cli legacy home directory",
        config_path=config_path,
        events=frozenset(LEGACY_EVENTS),
    )


def resolve_kimi_contracts() -> List[KimiContract]:
    home = os.path.expanduser("~")
    configured_home = os.environ.get("KIMI_CODE_HOME")
    explicit_home = (
        None
        if configured_home is None or configured_home == ""
        else os.path.abspath(configured_home)
    )
    stable_home = explicit_home or os.path.join(home, ".kimi-code")
    legacy_home = os.path.join(home, ".kimi")
    stable = _stable_contract(os.path.join(stable_home, "config.toml"))
    legacy = _legacy_contract(os.path.join(legacy_home, "config.toml"))
    if same_path(stable.config_path, legacy.config_path):
        return [stable]

    stable_detected = explicit_home is not None or _entry_exists(
        stable_home, "Kimi Code home"
    )
    legacy_detected = _entry_exists(legacy_home, "kimi-cli legacy home")
    if legacy_detected and not stable_detected:
        return [legacy]
    return [stable, legacy] if legacy_detected else [stable]


def _read_kimi_document(contract: KimiContract) -> KimiDocument:
    directory = os.path.dirname(contract.config_path)
    physical_directory_exists(directory, contract.directory_label)
    snapshot = read_physical_file(contract.config_path, contract.label)
    if snapshot is None:
        return create_kimi_document(contract)
    return parse_kimi_document(contract, snapshot.contents)


def read_kimi_documents() -> List[KimiDocument]:
    return [_read_kimi_document(contract) for contract in resolve_kimi_contracts()]


def kimi_runtime_files_exist(contracts: List[KimiRuntimeContract]) -> bool:
    return any(runtime_contract_exists(contract, AGENT_KEY, "Kimi") for contract in contracts)
