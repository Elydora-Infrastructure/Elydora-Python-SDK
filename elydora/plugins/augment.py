"""Augment Code CLI native user-hook integration."""

from __future__ import annotations

import shutil
import subprocess  # nosec B404

from .augment_contract import (
    AGENT_KEY,
    AugmentHooks,
    build_handler,
    remove_managed_hooks,
    render_augment_document,
    runtime_contracts,
)
from .augment_installation import (
    AugmentRuntimePaths,
    commit_augment_installation,
    commit_augment_uninstall,
    preflight_augment_installation,
    prepare_augment_installation,
    prepare_augment_uninstall,
)
from .augment_io import augment_runtime_files_exist, read_augment_document
from .base import AgentPlugin, InstallConfig, PluginStatus


_REGEX_VALIDATION_TIMEOUT_SECONDS = 10
_REGEX_VALIDATOR = """import fs from "node:fs";
const pattern = fs.readFileSync(0, "utf8");
try {
  new RegExp(pattern);
} catch (error) {
  process.stderr.write(error instanceof Error ? error.message : String(error));
  process.exit(1);
}
"""


def _resolve_node_runtime() -> str:
    node_path = shutil.which("node")
    if node_path is None:
        raise FileNotFoundError(
            "Node.js runtime is required to validate Auggie matcher expressions"
        )
    return node_path


def _validate_matcher(node_path: str, label: str, matcher: str) -> None:
    try:
        result = subprocess.run(  # nosec B603
            [
                node_path,
                "--input-type=module",
                "--eval",
                _REGEX_VALIDATOR,
            ],
            input=matcher,
            text=True,
            capture_output=True,
            check=False,
            timeout=_REGEX_VALIDATION_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise TimeoutError(
            f"{label} matcher validation timed out after "
            f"{_REGEX_VALIDATION_TIMEOUT_SECONDS} seconds"
        ) from error
    except OSError as error:
        raise OSError(f"Run Node.js matcher validator: {error}") from error
    if result.returncode == 0:
        return
    message = (
        result.stderr.strip()
        or result.stdout.strip()
        or f"Node.js exited with code {result.returncode}"
    )
    raise ValueError(
        f"{label} matcher must be a valid JavaScript regular expression: {message}"
    )


def _validate_matchers(hooks: AugmentHooks) -> None:
    matchers = [
        (event, group_index, group["matcher"])
        for event in sorted(hooks)
        for group_index, group in enumerate(hooks[event])
        if "matcher" in group
    ]
    if not matchers:
        return
    node_path = _resolve_node_runtime()
    for event, group_index, matcher in matchers:
        label = f"Auggie settings group hooks.{event}[{group_index}]"
        _validate_matcher(node_path, label, matcher)


def _installed_hooks(hooks: AugmentHooks, paths: AugmentRuntimePaths) -> AugmentHooks:
    cleaned, _ = remove_managed_hooks(hooks)
    return {
        **cleaned,
        "PreToolUse": [
            *cleaned.get("PreToolUse", []),
            {
                "matcher": ".*",
                "hooks": [build_handler(paths.guard_wrapper_path)],
            },
        ],
        "PostToolUse": [
            *cleaned.get("PostToolUse", []),
            {
                "matcher": ".*",
                "hooks": [build_handler(paths.audit_wrapper_path)],
            },
        ],
    }


class AugmentPlugin(AgentPlugin):
    """Install Elydora into Auggie's global user settings."""

    manages_guard_runtime = True

    def preflight_install(self, config: InstallConfig) -> None:
        document = read_augment_document()
        _validate_matchers(document.hooks)
        preflight_augment_installation(config, document)

    def install(self, config: InstallConfig) -> None:
        document = read_augment_document()
        _validate_matchers(document.hooks)
        paths = preflight_augment_installation(config, document)
        rendered = render_augment_document(
            document, _installed_hooks(document.hooks, paths)
        )
        changes = prepare_augment_installation(config, paths, rendered)
        commit_augment_installation(changes)
        print("Auggie: user-level PreToolUse and PostToolUse hooks installed.")

    def uninstall(self, agent_id: str = "") -> None:
        document = read_augment_document()
        if not document.exists:
            return
        hooks, changed = remove_managed_hooks(document.hooks, agent_id)
        if not changed:
            return
        rendered = render_augment_document(document, hooks)
        commit_augment_uninstall(prepare_augment_uninstall(rendered))

    def status(self) -> PluginStatus:
        document = read_augment_document()
        contracts = runtime_contracts(document.hooks)
        configured = bool(contracts)
        installed = configured and augment_runtime_files_exist(contracts)
        details = (
            f"Config: {document.config_path}"
            if installed
            else f"Configured at {document.config_path}; managed contract incomplete"
        )
        return PluginStatus(
            installed=installed,
            agent=AGENT_KEY,
            details=details if configured else "Not installed",
        )
