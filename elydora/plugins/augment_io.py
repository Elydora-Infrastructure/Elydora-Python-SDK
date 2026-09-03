"""Auggie settings discovery and managed runtime I/O."""

from __future__ import annotations

import os
from typing import List, Optional

from ._managed_files import MAX_CONFIG_BYTES, physical_directory_exists, read_physical_file
from ._runtime import runtime_contract_exists, same_path
from ._transaction import FileChange, source_change, write_changes
from .augment_contract import (
    AGENT_KEY,
    AUDIT_WRAPPER,
    GUARD_WRAPPER,
    AugmentDocument,
    RenderedAugmentDocument,
    RuntimeContract,
    build_wrapper,
    create_augment_document,
    parse_augment_document,
    resolve_config_path,
)


def read_augment_document() -> AugmentDocument:
    config_path = resolve_config_path()
    physical_directory_exists(os.path.dirname(config_path), "Auggie configuration directory")
    snapshot = read_physical_file(config_path, "Auggie user settings", MAX_CONFIG_BYTES)
    if snapshot is None:
        return create_augment_document(config_path)
    return parse_augment_document(config_path, snapshot.contents)


def rendered_change(rendered: RenderedAugmentDocument) -> Optional[FileChange]:
    if not rendered.changed:
        return None
    return source_change(
        rendered.document.config_path,
        "Auggie user settings",
        rendered.document.raw,
        rendered.next_source,
        0o600,
        MAX_CONFIG_BYTES,
    )


def write_augment_document(rendered: RenderedAugmentDocument) -> None:
    change = rendered_change(rendered)
    if change is not None:
        write_changes([change], "Uninstall Augment Code CLI hooks")


def _wrappers_exist(contract: RuntimeContract) -> bool:
    agent_directory = os.path.dirname(contract.guard_path)
    if not same_path(
        contract.guard_wrapper_path, os.path.join(agent_directory, GUARD_WRAPPER)
    ) or not same_path(
        contract.audit_wrapper_path, os.path.join(agent_directory, AUDIT_WRAPPER)
    ):
        return False
    guard_wrapper = read_physical_file(contract.guard_wrapper_path, "Auggie guard wrapper")
    audit_wrapper = read_physical_file(contract.audit_wrapper_path, "Auggie audit wrapper")
    return (
        guard_wrapper is not None
        and audit_wrapper is not None
        and guard_wrapper.contents == build_wrapper(contract.guard_path)
        and audit_wrapper.contents == build_wrapper(contract.audit_path)
    )


def augment_runtime_files_exist(contracts: List[RuntimeContract]) -> bool:
    return any(
        runtime_contract_exists(contract, AGENT_KEY, "Auggie") and _wrappers_exist(contract)
        for contract in contracts
    )
