"""Cursor plugin — writes/merges postToolUse hook into ~/.cursor/hooks.json."""

from __future__ import annotations

import json
import os
import sys

from ._file_io import write_json_atomic, write_text_atomic
from .base import AgentPlugin, InstallConfig, PluginStatus
from .hook_template import generate_hook_script


SETTINGS_PATH = os.path.join(os.path.expanduser("~"), ".cursor", "hooks.json")
ELYDORA_DIR = os.path.join(os.path.expanduser("~"), ".elydora")


class CursorPlugin(AgentPlugin):
    """Install/uninstall Elydora audit hook for Cursor."""

    @staticmethod
    def _hook_path_for(agent_id: str) -> str:
        return os.path.join(ELYDORA_DIR, agent_id, "hook.py")

    def install(self, config: InstallConfig) -> None:
        agent_id = config.get("agent_id", "")
        agent_name = config.get("agent_name", "")

        # Create per-agent directory
        agent_dir = os.path.join(ELYDORA_DIR, agent_id)
        os.makedirs(agent_dir, exist_ok=True)

        # Write config.json
        config_data = {
            "org_id": config.get("org_id", ""),
            "agent_id": agent_id,
            "kid": config.get("kid", ""),
            "base_url": config.get("base_url", "https://api.elydora.com"),
            "token": config.get("token", ""),
            "agent_name": agent_name,
        }
        config_path = os.path.join(agent_dir, "config.json")
        write_json_atomic(
            config_path,
            config_data,
            0o600,
            "Elydora runtime config",
        )

        # Write private key
        private_key_path = os.path.join(agent_dir, "private.key")
        write_text_atomic(
            private_key_path,
            config.get("private_key", ""),
            0o600,
            "Elydora private key",
        )

        script = generate_hook_script(
            org_id=config.get("org_id", ""),
            agent_id=agent_id,
            kid=config.get("kid", ""),
            base_url=config.get("base_url", "https://api.elydora.com"),
        )
        hook_path = self._hook_path_for(agent_id)
        write_text_atomic(
            hook_path,
            script,
            0o700,
            "Elydora audit runtime",
        )

        guard_script_path = config.get("guard_script_path", "")
        python_exe = sys.executable

        settings = _load_json(SETTINGS_PATH)
        hooks = settings.setdefault("hooks", {})

        # --- preToolUse (guard — freeze enforcement, camelCase) ---
        pre_tool_use = hooks.setdefault("preToolUse", [])
        pre_tool_use[:] = [h for h in pre_tool_use if not _is_elydora_hook(h)]
        if guard_script_path:
            pre_tool_use.append({
                "command": f'"{python_exe}" {guard_script_path}',
            })

        # --- postToolUse (audit logging, camelCase) ---
        post_tool_use = hooks.setdefault("postToolUse", [])

        post_tool_use[:] = [h for h in post_tool_use if not _is_elydora_hook(h)]

        post_tool_use.append({
            "command": hook_path,
        })

        _save_json(SETTINGS_PATH, settings)
        print("Elydora hook installed for Cursor.")
        print(f"  Hook script: {hook_path}")
        print(f"  Settings: {SETTINGS_PATH}")

    def uninstall(self, agent_id: str = "") -> None:
        if os.path.exists(SETTINGS_PATH):
            settings = _load_json(SETTINGS_PATH)
            hooks = settings.get("hooks", {})
            changed = False

            # Remove preToolUse entries
            pre_tool_use = hooks.get("preToolUse", [])
            pre_filtered = [h for h in pre_tool_use if not _is_elydora_hook(h, agent_id)]
            if len(pre_filtered) != len(pre_tool_use):
                hooks["preToolUse"] = pre_filtered
                if not pre_filtered:
                    del hooks["preToolUse"]
                changed = True

            # Remove postToolUse entries
            post_tool_use = hooks.get("postToolUse", [])
            post_filtered = [h for h in post_tool_use if not _is_elydora_hook(h, agent_id)]
            if len(post_filtered) != len(post_tool_use):
                hooks["postToolUse"] = post_filtered
                if not post_filtered:
                    del hooks["postToolUse"]
                changed = True

            if changed:
                if not hooks:
                    del settings["hooks"]
                _save_json(SETTINGS_PATH, settings)

        # Hook script removal is handled by cli.py cmd_uninstall (rmtree of agent dir)
        print("Elydora hook uninstalled from Cursor.")

    def status(self) -> PluginStatus:
        # Scan ~/.elydora/*/hook.py for any installed hook
        import glob as _glob
        hook_pattern = os.path.join(ELYDORA_DIR, "*", "hook.py")
        hook_files = _glob.glob(hook_pattern)
        hook_exists = len(hook_files) > 0

        settings_configured = False
        if os.path.exists(SETTINGS_PATH):
            settings = _load_json(SETTINGS_PATH)
            hooks = settings.get("hooks", {})
            pre_tool_use = hooks.get("preToolUse", [])
            post_tool_use = hooks.get("postToolUse", [])
            pre_configured = any(_is_elydora_hook(h) for h in pre_tool_use)
            post_configured = any(_is_elydora_hook(h) for h in post_tool_use)
            settings_configured = pre_configured and post_configured

        installed = hook_exists and settings_configured
        if installed:
            details = f"Found {len(hook_files)} agent(s): {', '.join(hook_files)}"
        elif hook_exists:
            details = "Hook script exists but not configured in hooks.json"
        elif settings_configured:
            details = "Configured in hooks.json but hook script missing"
        else:
            details = "Not installed"

        return PluginStatus(installed=installed, agent="cursor", details=details)


def _is_elydora_hook(hook: dict, agent_id: str = "") -> bool:
    cmd = hook.get("command", "")
    if "elydora" not in cmd.lower():
        return False
    # If agent_id is specified, only match hooks for that specific agent
    if agent_id:
        return agent_id in cmd
    return True


def _load_json(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_json(path: str, data: dict) -> None:
    write_json_atomic(path, data, 0o600, "Cursor hooks config")
