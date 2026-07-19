from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import subprocess  # nosec B404
import sys
from typing import Any, Dict, Optional

import pytest

from elydora.plugins import qwen
from elydora.plugins._jsonc import parse_jsonc
from elydora.plugins.base import InstallConfig


AGENT_ID = "agent-1"
MISSING = object()
JsonObject = Dict[str, Any]


def generated_command(script_path: Path) -> str:
    if os.name == "nt":
        executable = "'" + sys.executable.replace("'", "''") + "'"
        script = "'" + str(script_path).replace("'", "''") + "'"
        return f"& {executable} {script}; exit $LASTEXITCODE"
    executable = "'" + sys.executable.replace("'", "'\"'\"'") + "'"
    script = "'" + str(script_path).replace("'", "'\"'\"'") + "'"
    return f"{executable} {script}"


def parse_settings(path: Path) -> JsonObject:
    value = parse_jsonc(
        path.read_text(encoding="utf-8"),
        str(path),
        allow_trailing_commas=False,
    )
    assert isinstance(value, dict)
    return value


def managed_handler(
    settings: JsonObject,
    event: str,
    script_path: Path,
) -> Optional[JsonObject]:
    command = generated_command(script_path)
    for group in settings.get("hooks", {}).get(event, []):
        for handler in group["hooks"]:
            if handler.get("command") == command:
                return handler
    return None


def run_handler(
    handler: JsonObject,
    payload: str,
) -> subprocess.CompletedProcess[str]:
    if handler["shell"] == "powershell":
        command = [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            handler["command"],
        ]
    else:
        command = ["bash", "-c", handler["command"]]
    return subprocess.run(  # nosec B603
        command,
        input=payload,
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )


class QwenFixture:
    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        *,
        existing_settings: Any = MISSING,
        create_guard: bool = True,
    ) -> None:
        self.home_dir = tmp_path / "home with spaces and 'quote"
        self.workspace_dir = self.home_dir / "workspace"
        self.qwen_dir = self.home_dir / ".qwen"
        self.config_path = self.qwen_dir / "settings.json"
        self.agent_dir = self.home_dir / ".elydora" / AGENT_ID
        self.guard_path = self.agent_dir / "guard.py"
        self.audit_path = self.agent_dir / "hook.py"
        self.runtime_config = self.agent_dir / "config.json"
        self.private_key_path = self.agent_dir / "private.key"
        self.workspace_dir.mkdir(parents=True)
        self.agent_dir.mkdir(parents=True)
        if create_guard:
            self.guard_path.write_text(
                "import sys\n"
                "sys.stdin.buffer.read()\n"
                "sys.stderr.write('Agent is frozen by Elydora.\\n')\n"
                "raise SystemExit(2)\n",
                encoding="utf-8",
            )
        if existing_settings is not MISSING:
            self._write(self.config_path, existing_settings)
        monkeypatch.setenv("HOME", str(self.home_dir))
        monkeypatch.setenv("USERPROFILE", str(self.home_dir))
        monkeypatch.delenv("QWEN_HOME", raising=False)
        monkeypatch.chdir(self.workspace_dir)
        private_key = base64.urlsafe_b64encode(bytes([1]) * 32).rstrip(b"=").decode()
        self.config: InstallConfig = {
            "agent_id": AGENT_ID,
            "agent_name": "qwen",
            "org_id": "org-1",
            "private_key": private_key,
            "kid": "kid-1",
            "base_url": "https://api.elydora.test",
            "guard_script_path": str(self.guard_path),
        }
        self.plugin = qwen.QwenPlugin()

    @staticmethod
    def _write(path: Path, value: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = value if isinstance(value, str) else json.dumps(value, indent=2) + "\n"
        with open(path, "w", encoding="utf-8", newline="") as file:
            file.write(raw)

    def install(self) -> None:
        self.plugin.install(self.config)
