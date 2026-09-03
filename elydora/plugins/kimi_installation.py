"""Transactional Kimi hook and runtime installation."""

from __future__ import annotations

from typing import List, Optional

from ._managed_files import MAX_SOURCE_BYTES
from ._runtime import (
    DEFAULT_BASE_URL,
    RuntimePaths,
    present,
    resolve_runtime_paths,
    runtime_file_changes,
    validate_install_config,
    validate_runtime_tree,
)
from ._transaction import FileChange, source_change, write_changes
from .base import InstallConfig
from .guard_template import generate_guard_script
from .hook_template import generate_hook_script
from .kimi_contract import AGENT_KEY, KimiDocument, RenderedKimiDocument

PRODUCT = "Kimi"


def preflight_kimi_installation(
    config: InstallConfig, documents: List[KimiDocument]
) -> RuntimePaths:
    if not documents:
        raise ValueError("Kimi installation requires at least one hook contract")
    validate_install_config(config, AGENT_KEY, PRODUCT)
    paths = resolve_runtime_paths(config)
    validate_runtime_tree(paths.agent_directory, paths.agent_id, AGENT_KEY, PRODUCT)
    return paths


def rendered_change(rendered: RenderedKimiDocument) -> Optional[FileChange]:
    if not rendered.changed:
        return None
    source = rendered.document
    return source_change(
        source.contract.config_path,
        source.contract.label,
        source.raw,
        rendered.next_source,
        0o600,
        MAX_SOURCE_BYTES,
    )


def prepare_kimi_installation(
    config: InstallConfig,
    paths: RuntimePaths,
    rendered: List[RenderedKimiDocument],
) -> List[FileChange]:
    guard_script = generate_guard_script(AGENT_KEY, paths.agent_id)
    audit_script = generate_hook_script(
        org_id=config.get("org_id", ""),
        agent_id=paths.agent_id,
        kid=config.get("kid", ""),
        base_url=config.get("base_url", DEFAULT_BASE_URL),
        native_payload=True,
        agent_name=AGENT_KEY,
    )
    return [
        *runtime_file_changes(config, paths, AGENT_KEY, guard_script, audit_script),
        *present([rendered_change(item) for item in rendered]),
    ]


def commit_kimi_installation(changes: List[FileChange]) -> None:
    write_changes(changes, "Install Kimi hooks")


def prepare_kimi_uninstall(rendered: List[RenderedKimiDocument]) -> List[FileChange]:
    return present([rendered_change(item) for item in rendered])


def commit_kimi_uninstall(changes: List[FileChange]) -> None:
    write_changes(changes, "Uninstall Kimi hooks")
