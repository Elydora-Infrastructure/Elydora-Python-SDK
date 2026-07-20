"""Transactional Qwen Code hook and runtime installation."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from typing import List, Optional, Sequence

from elydora._runtime_paths import resolve_agent_directory

from ._managed_files import MAX_CONFIG_BYTES, MAX_SECRET_BYTES, MAX_SOURCE_BYTES
from ._transaction import FileChange, FilePrecondition, file_change, source_change, write_changes
from .base import InstallConfig
from .guard_template import generate_guard_script
from .hook_template import generate_hook_script
from .qwen_command import same_qwen_path
from .qwen_config import RenderedQwenDocument, qwen_document_label
from .qwen_contract import AGENT_KEY, AUDIT_SCRIPT, GUARD_SCRIPT, elydora_dir
from .qwen_io import validate_api_origin, validate_private_key, validate_runtime_tree
from .qwen_sources import QwenSources, require_qwen_hooks_enabled


@dataclass(frozen=True)
class QwenRuntimePaths:
    agent_id: str
    agent_directory: str
    guard_path: str
    audit_path: str


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


def _agent_paths(config: InstallConfig) -> QwenRuntimePaths:
    agent_id = config.get("agent_id", "")
    if not agent_id:
        raise ValueError("agent_id is required")
    agent_directory = resolve_agent_directory(elydora_dir(), agent_id)
    guard_path = os.path.join(agent_directory, GUARD_SCRIPT)
    audit_path = os.path.join(agent_directory, AUDIT_SCRIPT)
    if not same_qwen_path(config.get("guard_script_path", ""), guard_path):
        raise ValueError(
            "Elydora guard runtime must use the managed agent directory: "
            f"{guard_path}"
        )
    return QwenRuntimePaths(agent_id, agent_directory, guard_path, audit_path)


def _validate_install_config(config: InstallConfig) -> None:
    for field in ("org_id", "agent_id", "kid", "private_key", "base_url"):
        value = config.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{field} is required")
    if config.get("agent_name") != AGENT_KEY:
        raise ValueError(
            f"Qwen Code installation requires agent_name {AGENT_KEY}"
        )
    validate_private_key(config["private_key"])
    validate_api_origin(config["base_url"])
    if "token" in config:
        token = config["token"]
        if not isinstance(token, str) or not token:
            raise ValueError("token must be a non-empty string when provided")
    _agent_paths(config)


def preflight_qwen_installation(
    config: InstallConfig, sources: QwenSources
) -> QwenRuntimePaths:
    require_qwen_hooks_enabled(sources)
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


def _rendered_change(
    rendered: RenderedQwenDocument,
) -> Optional[FileChange]:
    if not rendered.changed:
        return None
    return source_change(
        rendered.document.file_path,
        qwen_document_label(rendered.document),
        rendered.document.raw if rendered.document.exists else None,
        rendered.next_source,
        0o600,
        MAX_SOURCE_BYTES,
        expected_snapshot=rendered.document.snapshot,
    )


def _present(changes: Sequence[Optional[FileChange]]) -> List[FileChange]:
    return [change for change in changes if change is not None]


def prepare_qwen_installation(
    config: InstallConfig,
    paths: QwenRuntimePaths,
    rendered: RenderedQwenDocument,
) -> List[FileChange]:
    guard_script = generate_guard_script(AGENT_KEY, paths.agent_id)
    audit_script = generate_hook_script(
        org_id=config.get("org_id", ""),
        agent_id=paths.agent_id,
        kid=config.get("kid", ""),
        base_url=config.get("base_url", "https://api.elydora.com"),
        native_payload=True,
        agent_name=AGENT_KEY,
    )
    return _present([
        _runtime_change(
            paths.guard_path, "Elydora guard runtime", guard_script, 0o700
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
            paths.audit_path, "Elydora audit runtime", audit_script, 0o700
        ),
        _rendered_change(rendered),
    ])


def _read_only_preconditions(
    sources: QwenSources, changed_path: Optional[str]
) -> List[FilePrecondition]:
    return [
        condition
        for condition in sources.preconditions
        if changed_path is None
        or not same_qwen_path(condition.file_path, changed_path)
    ]


def commit_qwen_installation(
    changes: List[FileChange], sources: QwenSources
) -> None:
    write_changes(
        changes,
        "Install Qwen Code hooks",
        _read_only_preconditions(sources, sources.user.file_path),
    )


def prepare_qwen_uninstall(
    rendered: RenderedQwenDocument,
) -> Optional[FileChange]:
    return _rendered_change(rendered)


def commit_qwen_uninstall(
    change: Optional[FileChange], sources: QwenSources
) -> None:
    if change is None:
        return
    write_changes(
        [change],
        "Uninstall Qwen Code hooks",
        _read_only_preconditions(sources, sources.user.file_path),
    )
