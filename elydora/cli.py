"""Elydora CLI — install, uninstall, and manage agent audit hooks.

Entry point: ``elydora`` console script (see pyproject.toml).
Uses only stdlib argparse — zero external dependencies for the CLI itself.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Dict, Type

from .crypto import get_public_key_base64url
from .plugins.base import AgentPlugin, InstallConfig
from .plugins.registry import SUPPORTED_AGENTS, get_agent_names
from .plugins.hook_template import generate_guard_script
from .plugins.claudecode import ClaudeCodePlugin
from .plugins.cursor import CursorPlugin
from .plugins.gemini import GeminiPlugin
from .plugins.augment import AugmentPlugin
from .plugins.kiro import KiroPlugin
from .plugins.opencode import OpenCodePlugin


PLUGIN_MAP: Dict[str, Type[AgentPlugin]] = {
    "claudecode": ClaudeCodePlugin,
    "cursor": CursorPlugin,
    "gemini": GeminiPlugin,
    "augment": AugmentPlugin,
    "kiro": KiroPlugin,
    "opencode": OpenCodePlugin,
}


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

    # Derive public key to verify the private key is valid
    try:
        pub = get_public_key_base64url(args.private_key)
    except Exception as exc:
        print(f"Error: Invalid private key — {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Verified key pair (public key: {pub[:16]}...)")

    # Generate and write the guard script
    guard_dir = os.path.join(os.path.expanduser("~"), ".elydora", "hooks")
    os.makedirs(guard_dir, exist_ok=True)
    guard_script_path = os.path.join(guard_dir, f"{agent_name}-guard.py")
    guard_script = generate_guard_script(agent_name)
    with open(guard_script_path, "w", encoding="utf-8") as f:
        f.write(guard_script)
    try:
        import stat
        os.chmod(guard_script_path, os.stat(guard_script_path).st_mode | stat.S_IEXEC)
    except Exception:
        pass  # chmod may fail on Windows
    print(f"  Guard script: {guard_script_path}")

    config: InstallConfig = {
        "org_id": args.org_id,
        "agent_id": args.agent_id,
        "private_key": args.private_key,
        "kid": args.kid,
        "base_url": args.base_url,
        "guard_script_path": guard_script_path,
    }
    if args.token:
        config["token"] = args.token

    plugin = _get_plugin(agent_name)
    plugin.install(config)


def cmd_uninstall(args: argparse.Namespace) -> None:
    """Handle the 'uninstall' subcommand."""
    plugin = _get_plugin(args.agent)
    plugin.uninstall()

    # Remove the guard script
    guard_script_path = os.path.join(
        os.path.expanduser("~"), ".elydora", "hooks", f"{args.agent}-guard.py"
    )
    if os.path.exists(guard_script_path):
        os.remove(guard_script_path)
        print(f"  Removed guard script: {guard_script_path}")


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
        "--version", action="version", version="%(prog)s 1.0.0"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # install
    install_parser = subparsers.add_parser("install", help="Install audit hook for an agent")
    install_parser.add_argument("--agent", required=True, help="Agent name (e.g. claudecode, cursor)")
    install_parser.add_argument("--org_id", required=True, help="Organization ID")
    install_parser.add_argument("--agent_id", required=True, help="Agent ID")
    install_parser.add_argument("--private_key", required=True, help="Base64url-encoded Ed25519 private key seed")
    install_parser.add_argument("--kid", required=True, help="Key ID")
    install_parser.add_argument("--token", default="", help="JWT bearer token (optional)")
    install_parser.add_argument("--base_url", default="https://api.elydora.com", help="API base URL")

    # uninstall
    uninstall_parser = subparsers.add_parser("uninstall", help="Uninstall audit hook for an agent")
    uninstall_parser.add_argument("--agent", required=True, help="Agent name")

    # status
    subparsers.add_parser("status", help="Show installation status of all agents")

    # agents
    subparsers.add_parser("agents", help="List supported agents")

    return parser


def main() -> None:
    """CLI entry point."""
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
