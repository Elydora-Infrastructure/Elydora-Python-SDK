"""Cursor plugin — writes/merges postToolUse hook into ~/.cursor/hooks.json."""

from __future__ import annotations

import json
import os
import stat

from .base import AgentPlugin, InstallConfig, PluginStatus
from .hook_template import generate_hook_script


SETTINGS_PATH = os.path.join(os.path.expanduser("~"), ".cursor", "hooks.json")
HOOK_DIR = os.path.join(os.path.expanduser("~"), ".elydora", "hooks")
HOOK_FILENAME = "elydora-audit-hook-cursor.py"


class CursorPlugin(AgentPlugin):
    """Install/uninstall Elydora audit hook for Cursor."""

    def _hook_path(self) -> str:
        return os.path.join(HOOK_DIR, HOOK_FILENAME)

    def install(self, config: InstallConfig) -> None:
        script = generate_hook_script(
            org_id=config.get("org_id", ""),
            agent_id=config.get("agent_id", ""),
            private_key=config.get("private_key", ""),
            kid=config.get("kid", ""),
            base_url=config.get("base_url", "https://api.elydora.com"),
        )
        os.makedirs(HOOK_DIR, exist_ok=True)
        hook_path = self._hook_path()
        with open(hook_path, "w", encoding="utf-8") as f:
            f.write(script)
        os.chmod(hook_path, os.stat(hook_path).st_mode | stat.S_IEXEC)

        guard_script_path = config.get("guard_script_path", "")

        settings = _load_json(SETTINGS_PATH)
        hooks = settings.setdefault("hooks", {})

        # --- preToolUse (guard — freeze enforcement, camelCase) ---
        pre_tool_use = hooks.setdefault("preToolUse", [])
        pre_tool_use[:] = [h for h in pre_tool_use if not _is_elydora_hook(h)]
        if guard_script_path:
            pre_tool_use.append({
                "command": f"python3 {guard_script_path}",
            })

        # --- postToolUse (audit logging, camelCase) ---
        post_tool_use = hooks.setdefault("postToolUse", [])

        post_tool_use[:] = [h for h in post_tool_use if not _is_elydora_hook(h)]

        post_tool_use.append({
            "command": hook_path,
        })

        _save_json(SETTINGS_PATH, settings)
        print(f"Elydora hook installed for Cursor.")
        print(f"  Hook script: {hook_path}")
        print(f"  Settings: {SETTINGS_PATH}")

    def uninstall(self) -> None:
        if os.path.exists(SETTINGS_PATH):
            settings = _load_json(SETTINGS_PATH)
            hooks = settings.get("hooks", {})
            changed = False

            # Remove preToolUse entries
            pre_tool_use = hooks.get("preToolUse", [])
            pre_filtered = [h for h in pre_tool_use if not _is_elydora_hook(h)]
            if len(pre_filtered) != len(pre_tool_use):
                hooks["preToolUse"] = pre_filtered
                if not pre_filtered:
                    del hooks["preToolUse"]
                changed = True

            # Remove postToolUse entries
            post_tool_use = hooks.get("postToolUse", [])
            post_filtered = [h for h in post_tool_use if not _is_elydora_hook(h)]
            if len(post_filtered) != len(post_tool_use):
                hooks["postToolUse"] = post_filtered
                if not post_filtered:
                    del hooks["postToolUse"]
                changed = True

            if changed:
                if not hooks:
                    del settings["hooks"]
                _save_json(SETTINGS_PATH, settings)

        hook_path = self._hook_path()
        if os.path.exists(hook_path):
            os.remove(hook_path)

        print("Elydora hook uninstalled from Cursor.")

    def status(self) -> PluginStatus:
        hook_path = self._hook_path()
        hook_exists = os.path.exists(hook_path)

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
            details = f"Hook: {hook_path}"
        elif hook_exists:
            details = "Hook script exists but not configured in hooks.json"
        elif settings_configured:
            details = "Configured in hooks.json but hook script missing"
        else:
            details = "Not installed"

        return PluginStatus(installed=installed, agent="cursor", details=details)


def _is_elydora_hook(hook: dict) -> bool:
    cmd = hook.get("command", "")
    return "elydora" in cmd.lower()


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
