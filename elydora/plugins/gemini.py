"""Gemini CLI plugin — merges AfterTool hook into ~/.gemini/settings.json."""

from __future__ import annotations

import json
import os
import sys

from ._file_io import write_json_atomic, write_text_atomic
from .base import AgentPlugin, InstallConfig, PluginStatus
from .hook_template import generate_hook_script


SETTINGS_PATH = os.path.join(os.path.expanduser("~"), ".gemini", "settings.json")
ELYDORA_DIR = os.path.join(os.path.expanduser("~"), ".elydora")


class GeminiPlugin(AgentPlugin):
    """Install/uninstall Elydora audit hook for Gemini CLI."""

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

        # --- BeforeTool (guard — freeze enforcement) ---
        before_tool = hooks.setdefault("BeforeTool", [])
        before_tool[:] = [h for h in before_tool if not _is_elydora_hook(h)]
        if guard_script_path:
            before_tool.append({
                "hooks": [
                    {
                        "type": "command",
                        "command": f'"{python_exe}" {guard_script_path}',
                    }
                ],
            })

        # --- AfterTool (audit logging) ---
        after_tool = hooks.setdefault("AfterTool", [])

        after_tool[:] = [h for h in after_tool if not _is_elydora_hook(h)]

        after_tool.append({
            "hooks": [
                {
                    "type": "command",
                    "command": hook_path,
                }
            ],
        })

        _save_json(SETTINGS_PATH, settings)
        print("Elydora hook installed for Gemini CLI.")
        print(f"  Hook script: {hook_path}")
        print(f"  Settings: {SETTINGS_PATH}")

    def uninstall(self, agent_id: str = "") -> None:
        if os.path.exists(SETTINGS_PATH):
            settings = _load_json(SETTINGS_PATH)
            hooks = settings.get("hooks", {})
            changed = False

            # Remove BeforeTool entries
            before_tool = hooks.get("BeforeTool", [])
            before_filtered = [h for h in before_tool if not _is_elydora_hook(h, agent_id)]
            if len(before_filtered) != len(before_tool):
                hooks["BeforeTool"] = before_filtered
                if not before_filtered:
                    del hooks["BeforeTool"]
                changed = True

            # Remove AfterTool entries
            after_tool = hooks.get("AfterTool", [])
            after_filtered = [h for h in after_tool if not _is_elydora_hook(h, agent_id)]
            if len(after_filtered) != len(after_tool):
                hooks["AfterTool"] = after_filtered
                if not after_filtered:
                    del hooks["AfterTool"]
                changed = True

            if changed:
                if not hooks:
                    del settings["hooks"]
                _save_json(SETTINGS_PATH, settings)

        # Hook script removal is handled by cli.py cmd_uninstall (rmtree of agent dir)
        print("Elydora hook uninstalled from Gemini CLI.")

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
            before_tool = hooks.get("BeforeTool", [])
            after_tool = hooks.get("AfterTool", [])
            before_configured = any(_is_elydora_hook(h) for h in before_tool)
            after_configured = any(_is_elydora_hook(h) for h in after_tool)
            settings_configured = before_configured and after_configured

        installed = hook_exists and settings_configured
        if installed:
            details = f"Found {len(hook_files)} agent(s): {', '.join(hook_files)}"
        elif hook_exists:
            details = "Hook script exists but not configured in settings"
        elif settings_configured:
            details = "Configured in settings but hook script missing"
        else:
            details = "Not installed"

        return PluginStatus(installed=installed, agent="gemini", details=details)


def _is_elydora_hook(entry: dict, agent_id: str = "") -> bool:
    # Collect all command strings from the entry
    commands: list[str] = []
    inner_hooks = entry.get("hooks")
    if isinstance(inner_hooks, list):
        for hook in inner_hooks:
            if isinstance(hook, dict) and isinstance(hook.get("command"), str):
                commands.append(hook["command"])
    else:
        command = entry.get("command")
        if isinstance(command, str):
            commands.append(command)

    for cmd in commands:
        cmd_lower = cmd.lower()
        if "elydora" not in cmd_lower:
            continue
        # If agent_id is specified, only match hooks for that specific agent
        if agent_id and agent_id in cmd:
            return True
        if not agent_id:
            return True
    return False


def _load_json(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_json(path: str, data: dict) -> None:
    write_json_atomic(path, data, 0o600, "Gemini settings")
