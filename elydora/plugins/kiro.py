"""Kiro plugin — writes .kiro/hooks/elydora-audit.kiro.hook file."""

from __future__ import annotations

import os
import stat

from .base import AgentPlugin, InstallConfig, PluginStatus
from .hook_template import generate_hook_script


HOOK_DIR = os.path.join(os.path.expanduser("~"), ".kiro", "hooks")
HOOK_FILENAME = "elydora-audit.kiro.hook"
SCRIPT_DIR = os.path.join(os.path.expanduser("~"), ".elydora", "hooks")
SCRIPT_FILENAME = "elydora-audit-hook-kiro.py"


class KiroPlugin(AgentPlugin):
    """Install/uninstall Elydora audit hook for Kiro."""

    def _hook_path(self) -> str:
        return os.path.join(HOOK_DIR, HOOK_FILENAME)

    def _script_path(self) -> str:
        return os.path.join(SCRIPT_DIR, SCRIPT_FILENAME)

    def install(self, config: InstallConfig) -> None:
        # Write the Python hook script
        script = generate_hook_script(
            org_id=config.get("org_id", ""),
            agent_id=config.get("agent_id", ""),
            private_key=config.get("private_key", ""),
            kid=config.get("kid", ""),
            base_url=config.get("base_url", "https://api.elydora.com"),
        )
        os.makedirs(SCRIPT_DIR, exist_ok=True)
        script_path = self._script_path()
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script)
        os.chmod(script_path, os.stat(script_path).st_mode | stat.S_IEXEC)

        guard_script_path = config.get("guard_script_path", "")

        # Write the Kiro hook definition file (JSON format matching Node SDK)
        import json

        hook_config = {
            "name": "Elydora Audit",
            "description": "Sends tool-use events to the Elydora tamper-evident audit platform",
            "version": "1.0.0",
            "hooks": {
                "pre_tool_use": {
                    "command": f"python3 {guard_script_path}" if guard_script_path else "",
                    "timeout_ms": 5000,
                },
                "post_tool_use": {
                    "command": script_path,
                    "timeout_ms": 5000,
                },
            },
        }

        os.makedirs(HOOK_DIR, exist_ok=True)
        hook_path = self._hook_path()
        with open(hook_path, "w", encoding="utf-8") as f:
            json.dump(hook_config, f, indent=2)
            f.write("\n")

        print(f"Elydora hook installed for Kiro.")
        print(f"  Hook script: {script_path}")
        print(f"  Hook definition: {hook_path}")

    def uninstall(self) -> None:
        hook_path = self._hook_path()
        if os.path.exists(hook_path):
            os.remove(hook_path)

        script_path = self._script_path()
        if os.path.exists(script_path):
            os.remove(script_path)

        print("Elydora hook uninstalled from Kiro.")

    def status(self) -> PluginStatus:
        hook_path = self._hook_path()
        script_path = self._script_path()
        hook_exists = os.path.exists(hook_path)
        script_exists = os.path.exists(script_path)

        hook_configured = False
        if hook_exists:
            try:
                import json
                with open(hook_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                hooks = cfg.get("hooks", {})
                hook_configured = bool(
                    hooks.get("pre_tool_use") and hooks.get("post_tool_use")
                )
            except Exception:
                hook_configured = hook_exists  # Fallback

        installed = hook_exists and script_exists and hook_configured
        if installed:
            details = f"Hook: {hook_path}"
        elif hook_exists:
            details = "Hook definition exists but script missing"
        elif script_exists:
            details = "Script exists but hook definition missing"
        else:
            details = "Not installed"

        return PluginStatus(installed=installed, agent="kiro", details=details)
