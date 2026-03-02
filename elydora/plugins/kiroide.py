"""Kiro IDE plugin — writes .kiro/hooks/elydora-audit.kiro.hook file."""

from __future__ import annotations

import json
import os
import stat
import sys

from .base import AgentPlugin, InstallConfig, PluginStatus
from .hook_template import generate_hook_script


KIRO_HOOK_DIR = os.path.join(os.path.expanduser("~"), ".kiro", "hooks")
KIRO_HOOK_FILENAME = "elydora-audit.kiro.hook"
ELYDORA_DIR = os.path.join(os.path.expanduser("~"), ".elydora")


class KiroIdePlugin(AgentPlugin):
    """Install/uninstall Elydora audit hook for Kiro IDE."""

    def _kiro_hook_path(self) -> str:
        return os.path.join(KIRO_HOOK_DIR, KIRO_HOOK_FILENAME)

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

        # Write the Python hook script
        script = generate_hook_script(
            org_id=config.get("org_id", ""),
            agent_id=agent_id,
            private_key=config.get("private_key", ""),
            kid=config.get("kid", ""),
            base_url=config.get("base_url", "https://api.elydora.com"),
        )
        script_path = self._hook_path_for(agent_id)
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script)
        try:
            os.chmod(script_path, stat.S_IRWXU)
        except Exception:
            pass  # chmod may fail on Windows

        guard_script_path = config.get("guard_script_path", "")
        python_exe = sys.executable

        # Write the Kiro hook definition file (JSON format matching Node SDK)
        hook_config = {
            "name": "Elydora Audit",
            "description": "Sends tool-use events to the Elydora tamper-evident audit platform",
            "version": "1.0.0",
            "hooks": {
                "pre_tool_use": {
                    "command": f'"{python_exe}" {guard_script_path}' if guard_script_path else "",
                    "timeout_ms": 5000,
                },
                "post_tool_use": {
                    "command": script_path,
                    "timeout_ms": 5000,
                },
            },
        }

        os.makedirs(KIRO_HOOK_DIR, exist_ok=True)
        hook_path = self._kiro_hook_path()
        with open(hook_path, "w", encoding="utf-8") as f:
            json.dump(hook_config, f, indent=2)
            f.write("\n")

        print(f"Elydora hook installed for Kiro IDE.")
        print(f"  Hook script: {script_path}")
        print(f"  Hook definition: {hook_path}")

    def uninstall(self, agent_id: str = "") -> None:
        hook_path = self._kiro_hook_path()
        if os.path.exists(hook_path):
            os.remove(hook_path)

        # Hook script removal is handled by cli.py cmd_uninstall (rmtree of agent dir)
        print("Elydora hook uninstalled from Kiro IDE.")

    def status(self) -> PluginStatus:
        hook_path = self._kiro_hook_path()
        hook_exists = os.path.exists(hook_path)

        # Scan ~/.elydora/*/hook.py for any installed hook script
        import glob as _glob
        hook_pattern = os.path.join(ELYDORA_DIR, "*", "hook.py")
        hook_files = _glob.glob(hook_pattern)
        script_exists = len(hook_files) > 0

        hook_configured = False
        if hook_exists:
            try:
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
            details = f"Found {len(hook_files)} agent(s): {', '.join(hook_files)}"
        elif hook_exists:
            details = "Hook definition exists but script missing"
        elif script_exists:
            details = "Script exists but hook definition missing"
        else:
            details = "Not installed"

        return PluginStatus(installed=installed, agent="kiroide", details=details)
