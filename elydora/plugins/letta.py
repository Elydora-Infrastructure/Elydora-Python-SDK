"""Letta Code plugin — merges PreToolUse/PostToolUse hooks into ~/.letta/settings.json."""

from __future__ import annotations

import json
import os
import stat
import sys

from .base import AgentPlugin, InstallConfig, PluginStatus
from .hook_template import generate_hook_script


SETTINGS_PATH = os.path.join(os.path.expanduser("~"), ".letta", "settings.json")
ELYDORA_DIR = os.path.join(os.path.expanduser("~"), ".elydora")


class LettaPlugin(AgentPlugin):
    """Install/uninstall Elydora audit hook for Letta Code."""

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
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2)
            f.write("\n")

        # Write private key
        private_key_path = os.path.join(agent_dir, "private.key")
        with open(private_key_path, "w", encoding="utf-8") as f:
            f.write(config.get("private_key", ""))
        try:
            os.chmod(private_key_path, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass  # chmod may fail on Windows

        script = generate_hook_script(
            org_id=config.get("org_id", ""),
            agent_id=agent_id,
            private_key=config.get("private_key", ""),
            kid=config.get("kid", ""),
            base_url=config.get("base_url", "https://api.elydora.com"),
        )
        hook_path = self._hook_path_for(agent_id)
        with open(hook_path, "w", encoding="utf-8") as f:
            f.write(script)
        try:
            os.chmod(hook_path, stat.S_IRWXU)
        except Exception:
            pass  # chmod may fail on Windows

        guard_script_path = config.get("guard_script_path", "")
        python_exe = sys.executable

        settings = _load_json(SETTINGS_PATH)
        hooks = settings.setdefault("hooks", {})

        # --- PreToolUse (guard — freeze enforcement, PascalCase with matcher, no timeout_ms) ---
        pre_tool_use = hooks.setdefault("PreToolUse", [])
        pre_tool_use[:] = [h for h in pre_tool_use if not _is_elydora_hook(h)]
        if guard_script_path:
            pre_tool_use.append({
                "matcher": "*",
                "hooks": [
                    {
                        "type": "command",
                        "command": f'"{python_exe}" {guard_script_path}',
                    }
                ],
            })

        # --- PostToolUse (audit logging, PascalCase with matcher, no timeout_ms) ---
        post_tool_use = hooks.setdefault("PostToolUse", [])

        post_tool_use[:] = [h for h in post_tool_use if not _is_elydora_hook(h)]

        post_tool_use.append({
            "matcher": "*",
            "hooks": [
                {
                    "type": "command",
                    "command": hook_path,
                }
            ],
        })

        _save_json(SETTINGS_PATH, settings)
        print(f"Elydora hook installed for Letta Code.")
        print(f"  Hook script: {hook_path}")
        print(f"  Settings: {SETTINGS_PATH}")

    def uninstall(self, agent_id: str = "") -> None:
        if os.path.exists(SETTINGS_PATH):
            settings = _load_json(SETTINGS_PATH)
            hooks = settings.get("hooks", {})
            changed = False

            # Remove PreToolUse entries
            pre_tool_use = hooks.get("PreToolUse", [])
            pre_filtered = [h for h in pre_tool_use if not _is_elydora_hook(h, agent_id)]
            if len(pre_filtered) != len(pre_tool_use):
                hooks["PreToolUse"] = pre_filtered
                if not pre_filtered:
                    del hooks["PreToolUse"]
                changed = True

            # Remove PostToolUse entries
            post_tool_use = hooks.get("PostToolUse", [])
            post_filtered = [h for h in post_tool_use if not _is_elydora_hook(h, agent_id)]
            if len(post_filtered) != len(post_tool_use):
                hooks["PostToolUse"] = post_filtered
                if not post_filtered:
                    del hooks["PostToolUse"]
                changed = True

            if changed:
                if not hooks:
                    del settings["hooks"]
                _save_json(SETTINGS_PATH, settings)

        # Hook script removal is handled by cli.py cmd_uninstall (rmtree of agent dir)
        print("Elydora hook uninstalled from Letta Code.")

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
            pre_tool_use = hooks.get("PreToolUse", [])
            post_tool_use = hooks.get("PostToolUse", [])
            pre_configured = any(_is_elydora_hook(h) for h in pre_tool_use)
            post_configured = any(_is_elydora_hook(h) for h in post_tool_use)
            settings_configured = pre_configured and post_configured

        installed = hook_exists and settings_configured
        if installed:
            details = f"Found {len(hook_files)} agent(s): {', '.join(hook_files)}"
        elif hook_exists:
            details = "Hook script exists but not configured in settings"
        elif settings_configured:
            details = "Configured in settings but hook script missing"
        else:
            details = "Not installed"

        return PluginStatus(installed=installed, agent="letta", details=details)


def _is_elydora_hook(entry: dict, agent_id: str = "") -> bool:
    # Collect all command strings from the entry
    commands = []
    inner_hooks = entry.get("hooks")
    if isinstance(inner_hooks, list):
        commands.extend(
            h.get("command", "")
            for h in inner_hooks
            if isinstance(h, dict)
        )
    else:
        commands.append(entry.get("command", ""))

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
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
