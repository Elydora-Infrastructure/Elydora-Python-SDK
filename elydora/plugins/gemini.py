"""Gemini CLI plugin — merges AfterTool hook into ~/.gemini/settings.json."""

from __future__ import annotations

import json
import os
import stat

from .base import AgentPlugin, InstallConfig, PluginStatus
from .hook_template import generate_hook_script


SETTINGS_PATH = os.path.join(os.path.expanduser("~"), ".gemini", "settings.json")
HOOK_DIR = os.path.join(os.path.expanduser("~"), ".elydora", "hooks")
HOOK_FILENAME = "elydora-audit-hook-gemini.py"


class GeminiPlugin(AgentPlugin):
    """Install/uninstall Elydora audit hook for Gemini CLI."""

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

        # --- BeforeTool (guard — freeze enforcement) ---
        before_tool = hooks.setdefault("BeforeTool", [])
        before_tool[:] = [h for h in before_tool if not _is_elydora_hook(h)]
        if guard_script_path:
            before_tool.append({
                "hooks": [
                    {
                        "type": "command",
                        "command": f"python3 {guard_script_path}",
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
        print(f"Elydora hook installed for Gemini CLI.")
        print(f"  Hook script: {hook_path}")
        print(f"  Settings: {SETTINGS_PATH}")

    def uninstall(self) -> None:
        if os.path.exists(SETTINGS_PATH):
            settings = _load_json(SETTINGS_PATH)
            hooks = settings.get("hooks", {})
            changed = False

            # Remove BeforeTool entries
            before_tool = hooks.get("BeforeTool", [])
            before_filtered = [h for h in before_tool if not _is_elydora_hook(h)]
            if len(before_filtered) != len(before_tool):
                hooks["BeforeTool"] = before_filtered
                if not before_filtered:
                    del hooks["BeforeTool"]
                changed = True

            # Remove AfterTool entries
            after_tool = hooks.get("AfterTool", [])
            after_filtered = [h for h in after_tool if not _is_elydora_hook(h)]
            if len(after_filtered) != len(after_tool):
                hooks["AfterTool"] = after_filtered
                if not after_filtered:
                    del hooks["AfterTool"]
                changed = True

            if changed:
                if not hooks:
                    del settings["hooks"]
                _save_json(SETTINGS_PATH, settings)

        hook_path = self._hook_path()
        if os.path.exists(hook_path):
            os.remove(hook_path)

        print("Elydora hook uninstalled from Gemini CLI.")

    def status(self) -> PluginStatus:
        hook_path = self._hook_path()
        hook_exists = os.path.exists(hook_path)

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
            details = f"Hook: {hook_path}"
        elif hook_exists:
            details = "Hook script exists but not configured in settings"
        elif settings_configured:
            details = "Configured in settings but hook script missing"
        else:
            details = "Not installed"

        return PluginStatus(installed=installed, agent="gemini", details=details)


def _is_elydora_hook(entry: dict) -> bool:
    inner_hooks = entry.get("hooks")
    if isinstance(inner_hooks, list):
        return any(
            "elydora" in h.get("command", "").lower()
            for h in inner_hooks
            if isinstance(h, dict)
        )
    cmd = entry.get("command", "")
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
