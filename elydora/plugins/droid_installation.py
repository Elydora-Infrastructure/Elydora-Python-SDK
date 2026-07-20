"""Transactional Factory Droid hook installation."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import sys
from typing import Optional, Sequence, Tuple

from elydora._runtime_paths import resolve_agent_directory

from ._managed_files import MAX_CONFIG_BYTES, MAX_SECRET_BYTES, MAX_SOURCE_BYTES
from ._transaction import (
    FileChange,
    FilePrecondition,
    file_change,
    source_change,
    write_changes,
)
from .base import InstallConfig
from .droid_config import (
    DroidDocument,
    DroidSources,
    RenderedDocument,
    installation_documents,
    source_documents,
)
from .droid_contract import (
    AGENT_KEY,
    AUDIT_SCRIPT,
    GUARD_SCRIPT,
    elydora_dir,
    same_path,
    validate_javascript_regexes,
)
from .droid_io import (
    require_hooks_enabled,
    validate_api_origin,
    validate_private_key,
    validate_runtime_tree,
)
from .guard_template import generate_guard_script
from .hook_template import generate_hook_script


@dataclass(frozen=True)
class DroidRuntimePaths:
    agent_id: str
    agent_directory: str
    guard_path: str
    audit_path: str


@dataclass(frozen=True)
class PreparedDroidInstallation:
    changes: Tuple[FileChange, ...]
    preconditions: Tuple[FilePrecondition, ...]


@dataclass(frozen=True)
class PreparedDroidUninstall:
    changes: Tuple[FileChange, ...]
    preconditions: Tuple[FilePrecondition, ...]


def _source_label(document: DroidDocument) -> str:
    if document.kind == "settings":
        return "Factory Droid user settings"
    if document.kind == "local-settings":
        return "Factory Droid local settings"
    if document.kind == "legacy":
        return "Factory Droid legacy hooks"
    return "Factory Droid user hooks"


def _runtime_config(config: InstallConfig, agent_id: str) -> dict:
    value = {
        "org_id": config.get("org_id", ""),
        "agent_id": agent_id,
        "kid": config.get("kid", ""),
        "base_url": config.get("base_url", "https://api.elydora.com"),
        "agent_name": AGENT_KEY,
    }
    token = config.get("token")
    if token:
        value["token"] = token
    return value


def _json_source(value: dict) -> str:
    return json.dumps(value, indent=2) + "\n"


def _agent_paths(config: InstallConfig) -> DroidRuntimePaths:
    agent_id = config.get("agent_id", "")
    if not agent_id:
        raise ValueError("agent_id is required")
    agent_directory = resolve_agent_directory(elydora_dir(), agent_id)
    guard_path = os.path.join(agent_directory, GUARD_SCRIPT)
    audit_path = os.path.join(agent_directory, AUDIT_SCRIPT)
    if not same_path(config.get("guard_script_path", ""), guard_path):
        raise ValueError(
            "Elydora guard runtime must use the managed agent directory: "
            f"{guard_path}"
        )
    return DroidRuntimePaths(
        agent_id,
        agent_directory,
        guard_path,
        audit_path,
    )


def _validate_install_config(config: InstallConfig) -> None:
    for field in ("org_id", "agent_id", "kid", "private_key", "base_url"):
        value = config.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{field} is required")
    if config.get("agent_name") != AGENT_KEY:
        raise ValueError(
            f"Factory Droid installation requires agent_name {AGENT_KEY}"
        )
    if not os.path.isabs(sys.executable):
        raise RuntimeError(
            "Factory Droid requires an absolute Python executable path"
        )
    validate_private_key(config["private_key"])
    validate_api_origin(config["base_url"])
    if "token" in config:
        token = config["token"]
        if not isinstance(token, str) or not token:
            raise ValueError("token must be a non-empty string when provided")
    _agent_paths(config)


def preflight_droid_installation(
    config: InstallConfig,
    sources: DroidSources,
) -> DroidRuntimePaths:
    require_hooks_enabled(sources)
    validate_javascript_regexes([
        document.hooks for document in source_documents(sources)
    ])
    _validate_install_config(config)
    paths = _agent_paths(config)
    validate_runtime_tree(paths.agent_directory, paths.agent_id)
    return paths


def _runtime_change(
    file_path: str,
    label: str,
    next_source: str,
    mode: int,
    maximum_bytes: int = MAX_SOURCE_BYTES,
) -> Optional[FileChange]:
    return file_change(file_path, label, next_source, mode, maximum_bytes)


def _document_change(rendered: RenderedDocument) -> Optional[FileChange]:
    if not rendered.changed:
        return None
    document = rendered.document
    return source_change(
        document.file_path,
        _source_label(document),
        document.raw if document.exists else None,
        rendered.next_source,
        0o600,
        MAX_SOURCE_BYTES,
        document.snapshot,
    )


def _present(
    changes: Sequence[Optional[FileChange]],
) -> Tuple[FileChange, ...]:
    return tuple(change for change in changes if change is not None)


def _validate_rendered_documents(
    sources: DroidSources,
    rendered: Sequence[RenderedDocument],
) -> None:
    expected = installation_documents(sources)
    if len(rendered) != len(expected):
        raise ValueError("Factory Droid rendered source set is incomplete")
    for document in expected:
        matches = [
            item
            for item in rendered
            if same_path(item.document.file_path, document.file_path)
        ]
        if len(matches) != 1:
            raise ValueError(
                "Factory Droid rendered source set contains unexpected paths"
            )


def _source_preconditions(
    sources: DroidSources,
    changed_paths: Sequence[str],
) -> Tuple[FilePrecondition, ...]:
    return tuple(
        FilePrecondition(
            document.file_path,
            _source_label(document),
            document.snapshot,
            MAX_SOURCE_BYTES,
        )
        for document in source_documents(sources)
        if not any(
            same_path(document.file_path, changed)
            for changed in changed_paths
        )
    )


def prepare_droid_installation(
    config: InstallConfig,
    sources: DroidSources,
    rendered: Sequence[RenderedDocument],
) -> PreparedDroidInstallation:
    paths = preflight_droid_installation(config, sources)
    _validate_rendered_documents(sources, rendered)
    guard_script = generate_guard_script(AGENT_KEY, paths.agent_id)
    audit_script = generate_hook_script(
        org_id=config.get("org_id", ""),
        agent_id=paths.agent_id,
        kid=config.get("kid", ""),
        base_url=config.get("base_url", "https://api.elydora.com"),
        native_payload=True,
        agent_name=AGENT_KEY,
    )
    document_changes = _present(tuple(
        _document_change(item) for item in rendered
    ))
    changes = _present((
        _runtime_change(
            paths.guard_path,
            "Elydora guard runtime",
            guard_script,
            0o700,
        ),
        _runtime_change(
            os.path.join(paths.agent_directory, "config.json"),
            "Elydora runtime config",
            _json_source(_runtime_config(config, paths.agent_id)),
            0o600,
            MAX_CONFIG_BYTES,
        ),
        _runtime_change(
            os.path.join(paths.agent_directory, "private.key"),
            "Elydora private key",
            config.get("private_key", ""),
            0o600,
            MAX_SECRET_BYTES,
        ),
        _runtime_change(
            paths.audit_path,
            "Elydora audit runtime",
            audit_script,
            0o700,
        ),
        *document_changes,
    ))
    changed_paths = [change.file_path for change in document_changes]
    preconditions = (
        *_source_preconditions(sources, changed_paths),
        *sources.policy.preconditions,
    )
    return PreparedDroidInstallation(changes, tuple(preconditions))


def commit_droid_installation(
    prepared: PreparedDroidInstallation,
) -> None:
    write_changes(
        prepared.changes,
        "Install Factory Droid hooks",
        prepared.preconditions,
    )


def prepare_droid_uninstall(
    rendered: Sequence[RenderedDocument],
) -> PreparedDroidUninstall:
    changes = _present(tuple(_document_change(item) for item in rendered))
    changed_paths = [change.file_path for change in changes]
    preconditions = tuple(
        FilePrecondition(
            item.document.file_path,
            _source_label(item.document),
            item.document.snapshot,
            MAX_SOURCE_BYTES,
        )
        for item in rendered
        if not any(
            same_path(item.document.file_path, changed)
            for changed in changed_paths
        )
    )
    return PreparedDroidUninstall(changes, preconditions)


def commit_droid_uninstall(prepared: PreparedDroidUninstall) -> None:
    write_changes(
        prepared.changes,
        "Uninstall Factory Droid hooks",
        prepared.preconditions,
    )
