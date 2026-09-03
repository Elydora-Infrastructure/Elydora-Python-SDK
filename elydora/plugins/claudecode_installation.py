"""Transactional Claude Code hook and runtime installation."""

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
from .claudecode_contract import AGENT_KEY, ClaudeDocument, RenderedClaudeDocument
from .claudecode_io import rendered_change
from .guard_template import generate_guard_script
from .hook_template import generate_hook_script

PRODUCT = "Claude Code"


def preflight_claude_installation(
    config: InstallConfig, document: ClaudeDocument
) -> RuntimePaths:
    if not document.file_path:
        raise ValueError("Claude Code installation requires a settings path")
    validate_install_config(config, AGENT_KEY, PRODUCT)
    paths = resolve_runtime_paths(config)
    validate_runtime_tree(paths.agent_directory, paths.agent_id, AGENT_KEY, PRODUCT)
    return paths


def prepare_claude_installation(
    config: InstallConfig,
    paths: RuntimePaths,
    rendered: RenderedClaudeDocument,
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
        *present([rendered_change(rendered)]),
    ]


def commit_claude_installation(changes: List[FileChange]) -> None:
    write_changes(changes, "Install Claude Code hooks")


def prepare_claude_uninstall(rendered: RenderedClaudeDocument) -> List[FileChange]:
    return present([rendered_change(rendered)])


def commit_claude_uninstall(changes: List[FileChange]) -> None:
    write_changes(changes, "Uninstall Claude Code hooks")
