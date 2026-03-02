"""Copilot CLI plugin — merges preToolUse/postToolUse hooks into .github/hooks/hooks.json (project-relative)."""

from __future__ import annotations

import json
import os
import stat
import sys

from .base import AgentPlugin, InstallConfig, PluginStatus
from .hook_template import generate_hook_script


ELYDORA_DIR = os.path.join(os.path.expanduser("~"), ".elydora")


def _settings_path() -> str:
    return os.path.join(os.getcwd(), ".github", "hooks", "hooks.json")


class CopilotPlugin(AgentPlugin):
    """Install/uninstall Elydora audit hook for Copilot CLI."""

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

        settings_path = _settings_path()
        settings = _load_json(settings_path)
        settings["version"] = 1
        hooks = settings.setdefault("hooks", {})

        # --- preToolUse (guard — freeze enforcement, camelCase) ---
        pre_tool_use = hooks.setdefault("preToolUse", [])
        pre_tool_use[:] = [h for h in pre_tool_use if not _is_elydora_hook(h)]
        if guard_script_path:
            pre_tool_use.append({
                "type": "command",
                "bash": f'"{python_exe}" {guard_script_path}',
                "powershell": f'"{python_exe}" {guard_script_path}',
                "timeoutSec": 5,
            })

        # --- postToolUse (audit logging, camelCase) ---
        post_tool_use = hooks.setdefault("postToolUse", [])

        post_tool_use[:] = [h for h in post_tool_use if not _is_elydora_hook(h)]

        post_tool_use.append({
            "type": "command",
            "bash": hook_path,
            "powershell": hook_path,
            "timeoutSec": 5,
        })

        _save_json(settings_path, settings)
        print(f"Elydora hook installed for Copilot CLI.")
        print(f"  Hook script: {hook_path}")
        print(f"  Settings: {settings_path}")

    def uninstall(self, agent_id: str = "") -> None:
        settings_path = _settings_path()
        if os.path.exists(settings_path):
            settings = _load_json(settings_path)
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
                _save_json(settings_path, settings)

        # Hook script removal is handled by cli.py cmd_uninstall (rmtree of agent dir)
        print("Elydora hook uninstalled from Copilot CLI.")

    def status(self) -> PluginStatus:
        # Scan ~/.elydora/*/hook.py for any installed hook
        import glob as _glob
        hook_pattern = os.path.join(ELYDORA_DIR, "*", "hook.py")
        hook_files = _glob.glob(hook_pattern)
        hook_exists = len(hook_files) > 0

        settings_configured = False
        settings_path = _settings_path()
        if os.path.exists(settings_path):
            settings = _load_json(settings_path)
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

        return PluginStatus(installed=installed, agent="copilot", details=details)


def _is_elydora_hook(hook: dict, agent_id: str = "") -> bool:
    # Check both bash and powershell fields for Copilot's hook format
    for field in ("bash", "powershell", "command"):
        cmd = hook.get(field, "")
        if not isinstance(cmd, str):
            continue
        if "elydora" not in cmd.lower():
            continue
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
