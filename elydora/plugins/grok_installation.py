"""Transactional Grok hook and runtime installation."""

from __future__ import annotations

from typing import List

from ._runtime import (
    DEFAULT_BASE_URL,
    RuntimePaths,
    present,
    resolve_runtime_paths,
    runtime_file_changes,
    validate_install_config,
    validate_runtime_tree,
)
from ._transaction import FileChange, write_changes
from .base import InstallConfig
from .grok_contract import AGENT_KEY, GrokDocument, RenderedGrokDocument
from .grok_io import rendered_change
from .guard_template import generate_guard_script
from .hook_template import generate_hook_script

PRODUCT = "Grok"


def preflight_grok_installation(
    config: InstallConfig, document: GrokDocument
) -> RuntimePaths:
    if not document.config_path:
        raise ValueError("Grok installation requires a hook configuration path")
    validate_install_config(config, AGENT_KEY, PRODUCT)
    paths = resolve_runtime_paths(config)
    validate_runtime_tree(paths.agent_directory, paths.agent_id, AGENT_KEY, PRODUCT)
    return paths


def prepare_grok_installation(
    config: InstallConfig,
    paths: RuntimePaths,
    rendered: RenderedGrokDocument,
) -> List[FileChange]:
    guard_script = generate_guard_script(AGENT_KEY, paths.agent_id, deny_protocol="grok")
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
        *present([rendered_change(rendered)]),
    ]


def commit_grok_installation(changes: List[FileChange]) -> None:
    write_changes(changes, "Install Grok hooks")


def prepare_grok_uninstall(rendered: RenderedGrokDocument) -> List[FileChange]:
    return present([rendered_change(rendered)])


def commit_grok_uninstall(changes: List[FileChange]) -> None:
    write_changes(changes, "Uninstall Grok hooks")
