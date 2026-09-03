"""Kiro IDE workspace discovery and managed runtime inspection."""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import List, Optional

from elydora._runtime_paths import resolve_agent_directory, runtime_root

from ._managed_files import (
    DirectorySnapshot,
    FileSnapshot,
    MAX_CONFIG_BYTES,
    MAX_SECRET_BYTES,
    physical_directory_exists,
    physical_file_exists,
    read_physical_directory,
    read_physical_file,
)
from ._runtime import (
    RUNTIME_ARTIFACTS,
    RUNTIME_CONFIG_FIELDS,
    expected_runtime_scripts,
    require_non_empty_string,
    same_agent_id,
    same_path,
    validate_api_origin,
    validate_private_key,
)
from ._strict_json import JsonObject, parse_json_object
from .kiroide_contract import (
    AGENT_KEY,
    CONFIG_FILE,
    LEGACY_CONFIG_FILE,
    KiroIdeDocument,
    KiroIdeRuntimeContract,
    create_kiroide_document,
    legacy_kiroide_runtime_contract,
    parse_kiroide_document,
)


@dataclass(frozen=True)
class KiroIdePaths:
    workspace_root: str
    kiro_directory: str
    hooks_directory: str
    config_path: str
    legacy_config_path: str


@dataclass(frozen=True)
class LegacyKiroIdeDocument:
    exists: bool
    file_path: str
    raw: Optional[str] = None
    snapshot: Optional[FileSnapshot] = None
    contract: Optional[KiroIdeRuntimeContract] = None


@dataclass(frozen=True)
class KiroIdeSources:
    paths: KiroIdePaths
    directories: KiroIdeDirectoryState
    document: KiroIdeDocument
    legacy: LegacyKiroIdeDocument


@dataclass(frozen=True)
class KiroIdeDirectoryState:
    workspace: DirectorySnapshot
    kiro: Optional[DirectorySnapshot]
    hooks: Optional[DirectorySnapshot]


def resolve_kiroide_paths(
    workspace_root: Optional[str] = None,
    home_directory: Optional[str] = None,
) -> KiroIdePaths:
    workspace = os.path.abspath(workspace_root or os.getcwd())
    home = home_directory or os.path.expanduser("~")
    kiro_directory = os.path.join(workspace, ".kiro")
    hooks_directory = os.path.join(kiro_directory, "hooks")
    return KiroIdePaths(
        workspace,
        kiro_directory,
        hooks_directory,
        os.path.join(hooks_directory, CONFIG_FILE),
        os.path.join(home, ".kiro", "hooks", LEGACY_CONFIG_FILE),
    )


def _inspect_workspace(paths: KiroIdePaths) -> KiroIdeDirectoryState:
    workspace = read_physical_directory(
        paths.workspace_root, "Kiro IDE workspace"
    )
    if workspace is None:
        raise OSError(f"Kiro IDE workspace is missing: {paths.workspace_root}")
    kiro = read_physical_directory(
        paths.kiro_directory, "Kiro IDE configuration directory"
    )
    hooks = read_physical_directory(
        paths.hooks_directory, "Kiro IDE hooks directory"
    )
    return KiroIdeDirectoryState(workspace, kiro, hooks)


def require_kiroide_directory_state(
    paths: KiroIdePaths,
    expected: KiroIdeDirectoryState,
    operation: str,
) -> None:
    current = _inspect_workspace(paths)
    for label, path, before, after in (
        (
            "Kiro IDE workspace",
            paths.workspace_root,
            expected.workspace,
            current.workspace,
        ),
        (
            "Kiro IDE configuration directory",
            paths.kiro_directory,
            expected.kiro,
            current.kiro,
        ),
        (
            "Kiro IDE hooks directory",
            paths.hooks_directory,
            expected.hooks,
            current.hooks,
        ),
    ):
        if before != after:
            raise OSError(f"{label} changed during {operation}: {path}")


def _read_document(paths: KiroIdePaths) -> KiroIdeDocument:
    snapshot = read_physical_file(paths.config_path, "Kiro IDE hooks")
    if snapshot is None:
        return create_kiroide_document(paths.config_path)
    return parse_kiroide_document(
        paths.config_path,
        snapshot.contents,
        snapshot,
    )


def _read_legacy(paths: KiroIdePaths) -> LegacyKiroIdeDocument:
    snapshot = read_physical_file(paths.legacy_config_path, "legacy Kiro IDE hook")
    if snapshot is None:
        return LegacyKiroIdeDocument(False, paths.legacy_config_path)
    return LegacyKiroIdeDocument(
        True,
        paths.legacy_config_path,
        snapshot.contents,
        snapshot,
        legacy_kiroide_runtime_contract(
            snapshot.contents, paths.legacy_config_path
        ),
    )


def read_kiroide_sources() -> KiroIdeSources:
    paths = resolve_kiroide_paths()
    directories = _inspect_workspace(paths)
    document = _read_document(paths)
    legacy = _read_legacy(paths)
    require_kiroide_directory_state(
        paths, directories, "Kiro IDE source discovery"
    )
    return KiroIdeSources(paths, directories, document, legacy)


def require_physical_legacy_directory(legacy: LegacyKiroIdeDocument) -> None:
    if not legacy.exists:
        return
    hooks_directory = os.path.dirname(legacy.file_path)
    kiro_directory = os.path.dirname(hooks_directory)
    if not physical_directory_exists(
        kiro_directory, "legacy Kiro IDE configuration directory"
    ):
        raise OSError(
            f"Legacy Kiro IDE configuration directory is missing: {kiro_directory}"
        )
    if not physical_directory_exists(
        hooks_directory, "legacy Kiro IDE hooks directory"
    ):
        raise OSError(
            f"Legacy Kiro IDE hooks directory is missing: {hooks_directory}"
        )


def validate_kiroide_runtime_config(
    config: JsonObject,
    expected_agent_id: str,
    config_path: str,
    expected_workspace_root: str,
    allow_missing_workspace_root: bool = False,
    allow_legacy_ownerless_config: bool = False,
) -> None:
    supported = RUNTIME_CONFIG_FIELDS | {"workspace_root"}
    extra = next((key for key in config if key not in supported), None)
    if extra is not None:
        raise ValueError(
            f'Elydora runtime config has unsupported field "{extra}": {config_path}'
        )
    require_non_empty_string(config.get("org_id"), "org_id", config_path)
    require_non_empty_string(config.get("kid"), "kid", config_path)
    agent_id = require_non_empty_string(
        config.get("agent_id"), "agent_id", config_path
    )
    if (
        not same_agent_id(agent_id, expected_agent_id)
        or config.get("agent_name") != AGENT_KEY
    ):
        raise ValueError(
            "Elydora runtime identity does not match Kiro IDE hooks: "
            f"{config_path}"
        )
    configured_workspace = config.get("workspace_root")
    legacy_ownerless_config = (
        allow_legacy_ownerless_config and configured_workspace is None
    )
    if "token" in config and not (
        legacy_ownerless_config and config.get("token") == ""
    ):
        require_non_empty_string(config.get("token"), "token", config_path)
    base_url = require_non_empty_string(
        config.get("base_url"), "base_url", config_path
    )
    validate_api_origin(base_url, "Elydora runtime config base_url")
    if configured_workspace is None and (
        allow_missing_workspace_root or legacy_ownerless_config
    ):
        return
    workspace_root = require_non_empty_string(
        configured_workspace, "workspace_root", config_path
    )
    if not os.path.isabs(workspace_root):
        raise ValueError(
            f"Elydora runtime config workspace_root must be absolute: {config_path}"
        )
    if not same_path(workspace_root, expected_workspace_root):
        raise ValueError(
            "Elydora Kiro IDE agent is bound to another workspace: "
            f"{workspace_root}"
        )


def validate_runtime_tree(
    agent_directory: str,
    agent_id: str,
    workspace_root: str,
    allow_missing_workspace_root: bool = False,
    allow_legacy_ownerless_config: bool = False,
) -> None:
    root = runtime_root()
    if not physical_directory_exists(root, "Elydora runtime directory"):
        return
    if not physical_directory_exists(
        agent_directory, "Elydora agent runtime directory"
    ):
        return
    config_path = os.path.join(agent_directory, "config.json")
    config_snapshot = read_physical_file(config_path, "Elydora runtime config", MAX_CONFIG_BYTES)
    artifact_states = [
        physical_file_exists(os.path.join(agent_directory, name), label)
        for name, label in RUNTIME_ARTIFACTS
    ]
    artifact_exists = any(artifact_states)
    if config_snapshot is None:
        if artifact_exists:
            raise ValueError(
                "Elydora runtime identity cannot be verified without config.json: "
                f"{agent_directory}"
            )
        return
    validate_kiroide_runtime_config(
        parse_json_object(config_snapshot.contents, f"Elydora runtime config at {config_path}"),
        agent_id,
        config_path,
        workspace_root,
        allow_missing_workspace_root,
        allow_legacy_ownerless_config,
    )


def _runtime_contract_exists(
    contract: KiroIdeRuntimeContract, workspace_root: str
) -> bool:
    root = runtime_root()
    agent_directory = os.path.dirname(contract.guard_path)
    if (
        not same_path(os.path.dirname(agent_directory), root)
        or not same_path(
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
    config_snapshot = read_physical_file(
        config_path, "Elydora runtime config", MAX_CONFIG_BYTES
    )
    config = (
        None
        if config_snapshot is None
        else parse_json_object(
            config_snapshot.contents,
            f"Elydora runtime config at {config_path}",
        )
    )
    key = read_physical_file(
        os.path.join(agent_directory, "private.key"),
        "Elydora private key",
        MAX_SECRET_BYTES,
    )
    guard = read_physical_file(contract.guard_path, "Elydora guard runtime")
    audit = read_physical_file(contract.audit_path, "Elydora audit runtime")
    if config is None or key is None or guard is None or audit is None:
        return False
    validate_kiroide_runtime_config(
        config,
        contract.agent_id,
        config_path,
        workspace_root,
    )
    if os.name != "nt" and key.mode & 0o077:
        raise ValueError(
            f"Elydora private key must be accessible only by its owner: "
            f"{os.path.join(agent_directory, 'private.key')}"
        )
    if (
        os.name != "nt"
        and "token" in config
        and config_snapshot is not None
        and config_snapshot.mode & 0o077
    ):
        raise ValueError(
            "Token-bearing Elydora runtime config must be accessible only by "
            f"its owner: {config_path}"
        )
    validate_private_key(key.contents, "Elydora private key")
    expected_guard, expected_audit = expected_runtime_scripts(AGENT_KEY, contract.agent_id, config)
    return guard.contents == expected_guard and audit.contents == expected_audit


def kiroide_runtime_files_exist(
    contracts: List[KiroIdeRuntimeContract],
    workspace_root: str,
) -> bool:
    return any(
        _runtime_contract_exists(contract, workspace_root) for contract in contracts
    )


def require_kiroide_workspace_owner(
    agent_id: str,
    workspace_root: str,
    allow_missing_workspace_root: bool = False,
    allow_legacy_ownerless_config: bool = False,
) -> None:
    root = runtime_root()
    agent_directory = resolve_agent_directory(root, agent_id)
    validate_runtime_tree(
        agent_directory,
        agent_id,
        workspace_root,
        allow_missing_workspace_root,
        allow_legacy_ownerless_config,
    )


def legacy_kiroide_contract_matches_agent(
    legacy: LegacyKiroIdeDocument, agent_id: str
) -> bool:
    contract = legacy.contract
    if contract is None or not same_agent_id(
        contract.agent_id, agent_id
    ):
        return False
    agent_directory = resolve_agent_directory(runtime_root(), agent_id)
    return same_path(
        contract.guard_path,
        os.path.join(agent_directory, "guard.py"),
    ) and same_path(
        contract.audit_path,
        os.path.join(agent_directory, "hook.py"),
    )
