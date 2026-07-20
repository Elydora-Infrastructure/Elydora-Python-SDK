"""Elydora CLI — install, uninstall, and manage agent audit hooks.

Entry point: ``elydora`` console script (see pyproject.toml).
Uses only stdlib argparse — zero external dependencies for the CLI itself.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from typing import Dict, NamedTuple, NoReturn, Optional, Type

from ._cli_secrets import resolve_install_secrets
from ._version import __version__
from ._runtime_paths import (
    ensure_private_directory,
    require_physical_directory,
    require_physical_file,
    resolve_agent_directory,
)
from .crypto import get_public_key_base64url
from .plugins.base import AgentPlugin, InstallConfig
from .plugins.registry import SUPPORTED_AGENTS, get_agent_names
from .plugins.hook_template import generate_guard_script
from .plugins.augment import AugmentPlugin
from .plugins.claudecode import ClaudeCodePlugin
from .plugins.codex import CodexPlugin
from .plugins.cline import ClinePlugin
from .plugins.copilot import CopilotPlugin
from .plugins.cursor import CursorPlugin
from .plugins.droid import DroidPlugin
from .plugins.gemini import GeminiPlugin
from .plugins.grok import GrokPlugin
from .plugins.kirocli import KiroCliPlugin
from .plugins.kiroide import KiroIdePlugin
from .plugins.kimi import KimiPlugin
from .plugins.letta import LettaPlugin
from .plugins.opencode import OpenCodePlugin
from .plugins.qwen import QwenPlugin
from .plugins._file_io import write_text_atomic


PLUGIN_MAP: Dict[str, Type[AgentPlugin]] = {
    "augment": AugmentPlugin,
    "claudecode": ClaudeCodePlugin,
    "codex": CodexPlugin,
    "cline": ClinePlugin,
    "copilot": CopilotPlugin,
    "cursor": CursorPlugin,
    "droid": DroidPlugin,
    "gemini": GeminiPlugin,
    "grok": GrokPlugin,
    "kirocli": KiroCliPlugin,
    "kiroide": KiroIdePlugin,
    "kimi": KimiPlugin,
    "letta": LettaPlugin,
    "opencode": OpenCodePlugin,
    "qwen": QwenPlugin,
}

LEGACY_SECRET_OPTIONS = {
    "--private_key": "--private_key_file",
    "--token": "--token_file",
}


def _runtime_root() -> str:
    return os.path.join(os.path.expanduser("~"), ".elydora")


def _exit_with_error(message: str) -> NoReturn:
    print(f"Error: {message}", file=sys.stderr)
    raise SystemExit(1)


def _reject_legacy_secret_arguments(arguments: list[str]) -> None:
    for argument in arguments:
        option = argument.split("=", 1)[0]
        replacement = LEGACY_SECRET_OPTIONS.get(option)
        if replacement:
            _exit_with_error(
                f"{option} exposes credentials in process arguments; "
                f"use {replacement} or hidden terminal input"
            )


def _resolve_agent_directory_or_exit(agent_id: str) -> str:
    try:
        return resolve_agent_directory(_runtime_root(), agent_id)
    except ValueError as error:
        _exit_with_error(str(error))


class _InstalledAgent(NamedTuple):
    agent_id: str
    agent_name: str
    config_path: str


def _require_physical_directory_or_exit(path: str) -> bool:
    try:
        return require_physical_directory(path)
    except OSError as error:
        _exit_with_error(str(error))


def _require_physical_file_or_exit(path: str) -> bool:
    try:
        return require_physical_file(path)
    except OSError as error:
        _exit_with_error(str(error))


def _read_runtime_config_or_exit(config_path: str) -> Dict[str, object]:
    try:
        with open(config_path, "r", encoding="utf-8") as file:
            config = json.load(file)
    except (OSError, json.JSONDecodeError) as error:
        _exit_with_error(f"Read agent config at {config_path}: {error}")
    if not isinstance(config, dict):
        _exit_with_error(f"Agent config at {config_path} must contain a JSON object")
    return config


def _read_installed_agent_or_exit(agent_id: str) -> Optional[_InstalledAgent]:
    agent_directory = _resolve_agent_directory_or_exit(agent_id)
    if not _require_physical_directory_or_exit(agent_directory):
        return None

    config_path = os.path.join(agent_directory, "config.json")
    if not _require_physical_file_or_exit(config_path):
        return None
    config = _read_runtime_config_or_exit(config_path)
    stored_agent_id = config.get("agent_id")
    stored_agent_name = config.get("agent_name")
    if not isinstance(stored_agent_id, str) or not isinstance(
        stored_agent_name, str
    ):
        _exit_with_error(f"Agent config at {config_path} has an invalid identity")
    if stored_agent_id != agent_id:
        _exit_with_error(
            f"Agent config at {config_path} crosses its runtime directory"
        )
    _resolve_agent_directory_or_exit(stored_agent_id)
    return _InstalledAgent(agent_id, stored_agent_name, config_path)


def _discover_installed_agents_or_exit() -> list[_InstalledAgent]:
    runtime_root = _runtime_root()
    if not _require_physical_directory_or_exit(runtime_root):
        return []

    installed_agents: list[_InstalledAgent] = []
    try:
        with os.scandir(runtime_root) as entries:
            for entry in entries:
                if entry.is_symlink():
                    _exit_with_error(
                        f"Agent runtime path is not a physical directory: {entry.path}"
                    )
                if not entry.is_dir(follow_symlinks=False):
                    continue
                installed_agent = _read_installed_agent_or_exit(entry.name)
                if installed_agent is not None:
                    installed_agents.append(installed_agent)
    except OSError as error:
        _exit_with_error(f"Scan agent runtime root at {runtime_root}: {error}")
    return installed_agents


def _get_plugin(agent_name: str) -> AgentPlugin:
    """Instantiate the plugin for the given agent name."""
    cls = PLUGIN_MAP.get(agent_name)
    if cls is None:
        print(f"Error: Unknown agent '{agent_name}'.", file=sys.stderr)
        print(f"Supported agents: {', '.join(get_agent_names())}", file=sys.stderr)
        sys.exit(1)
    return cls()


def cmd_install(args: argparse.Namespace) -> None:
    """Handle the 'install' subcommand."""
    agent_name: str = args.agent
    agent_dir = _resolve_agent_directory_or_exit(args.agent_id)
    plugin = _get_plugin(agent_name)

    try:
        secrets = resolve_install_secrets(
            private_key_file=args.private_key_file,
            token_file=args.token_file,
        )
    except (OSError, RuntimeError, ValueError) as error:
        _exit_with_error(str(error))

    # Derive public key to verify the private key is valid
    try:
        pub = get_public_key_base64url(secrets.private_key)
    except Exception as exc:
        print(f"Error: Invalid private key — {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Verified key pair (public key: {pub[:16]}...)")

    guard_script_path = os.path.join(agent_dir, "guard.py")
    config: InstallConfig = {
        "org_id": args.org_id,
        "agent_id": args.agent_id,
        "agent_name": agent_name,
        "private_key": secrets.private_key,
        "kid": args.kid,
        "base_url": args.base_url,
        "guard_script_path": guard_script_path,
    }
    if secrets.token:
        config["token"] = secrets.token
    plugin.preflight_install(config)

    # Create per-agent directory under ~/.elydora/{agent_id}/
    ensure_private_directory(_runtime_root())
    ensure_private_directory(agent_dir)

    # Generate and write the guard script for adapters that use the shared runtime.
    if not plugin.manages_guard_runtime:
        guard_script = generate_guard_script(agent_name, args.agent_id)
        write_text_atomic(
            guard_script_path,
            guard_script,
            0o700,
            "Elydora guard runtime",
        )

    plugin.install(config)
    print(f"  Guard script: {guard_script_path}")


def cmd_uninstall(args: argparse.Namespace) -> None:
    """Handle the 'uninstall' subcommand."""
    explicit_agent_id = getattr(args, "agent_id", None)
    elydora_dir = _runtime_root()
    agent_id = explicit_agent_id
    if agent_id:
        agent_dir = _resolve_agent_directory_or_exit(agent_id)
        runtime_root_exists = _require_physical_directory_or_exit(elydora_dir)
        agent_directory_exists = (
            _require_physical_directory_or_exit(agent_dir)
            if runtime_root_exists
            else False
        )
        if agent_directory_exists:
            installed_agent = _read_installed_agent_or_exit(agent_id)
            if installed_agent and installed_agent.agent_name != args.agent:
                _exit_with_error(
                    f"Agent runtime {agent_id} belongs to "
                    f"{installed_agent.agent_name}, not {args.agent}"
                )
    else:
        matches = [
            installed_agent
            for installed_agent in _discover_installed_agents_or_exit()
            if installed_agent.agent_name == args.agent
        ]
        if not matches:
            _exit_with_error(
                f"No installed agent found for {args.agent!r}; pass --agent_id explicitly"
            )
        if len(matches) > 1:
            _exit_with_error(
                f"Multiple installed agents found for {args.agent!r}; "
                "pass --agent_id explicitly"
            )
        agent_id = matches[0].agent_id
        agent_dir = _resolve_agent_directory_or_exit(agent_id)
        agent_directory_exists = True

    plugin = _get_plugin(args.agent)
    plugin.uninstall(agent_id=agent_id)

    if agent_directory_exists:
        shutil.rmtree(agent_dir)
        print(f"  Removed agent directory: {agent_dir}")


def cmd_status(args: argparse.Namespace) -> None:
    """Handle the 'status' subcommand."""
    print("Elydora Agent Hook Status")
    print("=" * 40)
    for name in get_agent_names():
        plugin = PLUGIN_MAP[name]()
        st = plugin.status()
        marker = "[installed]" if st["installed"] else "[not installed]"
        display = SUPPORTED_AGENTS[name]["name"]
        print(f"  {display:20s} {marker:16s} {st['details']}")


def cmd_agents(args: argparse.Namespace) -> None:
    """Handle the 'agents' subcommand."""
    print("Supported agents:")
    for name in get_agent_names():
        info = SUPPORTED_AGENTS[name]
        print(f"  {name:15s} {info['name']:20s} (hook: {info['hook_event']})")


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse parser."""
    parser = argparse.ArgumentParser(
        prog="elydora",
        description="Elydora — tamper-evident audit trail for AI agents",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # install
    install_parser = subparsers.add_parser("install", help="Install audit hook for an agent")
    install_parser.add_argument("--agent", required=True, help="Agent name (e.g. claudecode, cursor)")
    install_parser.add_argument("--org_id", required=True, help="Organization ID")
    install_parser.add_argument("--agent_id", required=True, help="Agent ID")
    install_parser.add_argument(
        "--private_key_file",
        default=None,
        help="Owner-only file containing the Ed25519 private key seed",
    )
    install_parser.add_argument("--kid", required=True, help="Key ID")
    install_parser.add_argument(
        "--token_file",
        default=None,
        help="Owner-only file containing the optional API token",
    )
    install_parser.add_argument("--base_url", default="https://api.elydora.com", help="API base URL")

    # uninstall
    uninstall_parser = subparsers.add_parser("uninstall", help="Uninstall audit hook for an agent")
    uninstall_parser.add_argument("--agent", required=True, help="Agent name")
    uninstall_parser.add_argument("--agent_id", default=None, help="Agent ID (if omitted, scans config files for matching agent name)")

    # status
    subparsers.add_parser("status", help="Show installation status of all agents")

    # agents
    subparsers.add_parser("agents", help="List supported agents")

    return parser


def main() -> None:
    """CLI entry point."""
    _reject_legacy_secret_arguments(sys.argv[1:])
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    handlers = {
        "install": cmd_install,
        "uninstall": cmd_uninstall,
        "status": cmd_status,
        "agents": cmd_agents,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    handler(args)


if __name__ == "__main__":
    main()
