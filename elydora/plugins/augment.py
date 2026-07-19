"""Augment Code CLI native user-hook integration."""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404
from typing import List

from ._file_io import (
    read_json as _read_json,
    regular_file_exists as _regular_file_exists,
    remove_file as _remove_file,
    require_runtime as _require_runtime,
    write_json_atomic as _write_json_atomic,
    write_text_atomic as _write_text_atomic,
)
from .augment_contract import (
    AGENT_KEY,
    AUDIT_SCRIPT,
    AugmentDocument,
    AugmentHooks,
    JsonObject,
    RuntimeContract,
    build_handler,
    build_wrapper,
    elydora_dir,
    read_hooks,
    remove_managed_hooks,
    resolve_config_path,
    runtime_contracts,
    wrapper_paths,
)
from .base import AgentPlugin, InstallConfig, PluginStatus
from .hook_template import generate_hook_script


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


def _read_config() -> AugmentDocument:
    config_path = resolve_config_path()
    root = _read_json(config_path, "Auggie settings")
    if root is None:
        return AugmentDocument(False, config_path, {}, {})
    return AugmentDocument(True, config_path, root, read_hooks(root))


def _same_agent_id(left: str, right: str) -> bool:
    return os.path.normcase(left) == os.path.normcase(right)


def _runtime_files_exist(contracts: List[RuntimeContract]) -> bool:
    root = elydora_dir()
    try:
        with os.scandir(root) as iterator:
            entries = sorted(iterator, key=lambda entry: entry.name)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise OSError(f"Read Elydora runtime directory at {root}: {error}") from error

    for contract in contracts:
        entry = next(
            (
                candidate
                for candidate in entries
                if _same_agent_id(candidate.name, contract.agent_id)
            ),
            None,
        )
        if entry is None:
            continue
        try:
            if not entry.is_dir(follow_symlinks=False):
                continue
        except OSError as error:
            raise OSError(
                f"Read Elydora runtime entry at {entry.path}: {error}"
            ) from error
        runtime_config_path = os.path.join(entry.path, "config.json")
        runtime_config = _read_json(runtime_config_path, "Elydora runtime config")
        if runtime_config is None:
            continue
        agent_name = runtime_config.get("agent_name")
        if not isinstance(agent_name, str):
            raise ValueError(
                f"Elydora runtime config at {runtime_config_path} field "
                '"agent_name" must be a string'
            )
        if agent_name != AGENT_KEY:
            continue
        files = (
            (contract.guard_path, "Elydora guard runtime"),
            (contract.audit_path, "Elydora audit runtime"),
            (contract.guard_wrapper_path, "Auggie guard wrapper"),
            (contract.audit_wrapper_path, "Auggie audit wrapper"),
        )
        return all(_regular_file_exists(file_path, label) for file_path, label in files)
    return False


class AugmentPlugin(AgentPlugin):
    """Install Elydora into Auggie's global user settings."""

    def install(self, config: InstallConfig) -> None:
        agent_id = config.get("agent_id", "")
        if not agent_id:
            raise ValueError("agent_id is required")
        source = _read_config()
        _validate_matchers(source.hooks)
        guard_path = config.get("guard_script_path", "")
        _require_runtime(guard_path, "Elydora guard runtime")

        agent_directory = os.path.join(elydora_dir(), agent_id)
        audit_path = os.path.join(agent_directory, AUDIT_SCRIPT)
        wrappers = wrapper_paths(agent_id)
        cleaned, _ = remove_managed_hooks(source.hooks)
        hooks = {
            **cleaned,
            "PreToolUse": [
                *cleaned.get("PreToolUse", []),
                {
                    "matcher": ".*",
                    "hooks": [build_handler(wrappers.guard_path)],
                },
            ],
            "PostToolUse": [
                *cleaned.get("PostToolUse", []),
                {
                    "matcher": ".*",
                    "hooks": [build_handler(wrappers.audit_path)],
                },
            ],
        }
        runtime_config: JsonObject = {
            "org_id": config.get("org_id", ""),
            "agent_id": agent_id,
            "kid": config.get("kid", ""),
            "base_url": config.get("base_url", "https://api.elydora.com"),
            "token": config.get("token", ""),
            "agent_name": AGENT_KEY,
        }
        audit_script = generate_hook_script(
            org_id=config.get("org_id", ""),
            agent_id=agent_id,
            kid=config.get("kid", ""),
            base_url=config.get("base_url", "https://api.elydora.com"),
        )

        _write_json_atomic(
            os.path.join(agent_directory, "config.json"),
            runtime_config,
            0o600,
            "Elydora runtime config",
        )
        _write_text_atomic(
            os.path.join(agent_directory, "private.key"),
            config.get("private_key", ""),
            0o600,
            "Elydora private key",
        )
        _write_text_atomic(
            audit_path,
            audit_script,
            0o700,
            "Elydora audit runtime",
        )
        _write_text_atomic(
            wrappers.guard_path,
            build_wrapper(guard_path),
            0o700,
            "Auggie guard wrapper",
        )
        _write_text_atomic(
            wrappers.audit_path,
            build_wrapper(audit_path),
            0o700,
            "Auggie audit wrapper",
        )
        _write_json_atomic(
            source.config_path,
            {**source.root, "hooks": hooks},
            0o600,
            "Auggie settings",
        )
        print("Auggie: user-level PreToolUse and PostToolUse hooks installed.")

    def uninstall(self, agent_id: str = "") -> None:
        source = _read_config()
        if not source.exists:
            return
        hooks, changed = remove_managed_hooks(source.hooks, agent_id)
        if not changed:
            return
        root = dict(source.root)
        if hooks:
            root["hooks"] = hooks
        else:
            root.pop("hooks", None)
        if root:
            _write_json_atomic(
                source.config_path,
                root,
                0o600,
                "Auggie settings",
            )
        else:
            _remove_file(source.config_path, "Auggie settings")

    def status(self) -> PluginStatus:
        source = _read_config()
        contracts = runtime_contracts(source.hooks)
        if not contracts:
            return PluginStatus(
                installed=False,
                agent=AGENT_KEY,
                details="Not installed",
            )
        installed = _runtime_files_exist(contracts)
        details = (
            f"Config: {source.config_path}"
            if installed
            else (
                f"Configured at {source.config_path}; "
                "runtime scripts or wrappers missing"
            )
        )
        return PluginStatus(
            installed=installed,
            agent=AGENT_KEY,
            details=details,
        )
