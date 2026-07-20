from __future__ import annotations

import base64
from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest

from elydora.plugins import copilot
from elydora.plugins.base import InstallConfig


AGENT_ID = "agent-1"
VALID_PRIVATE_KEY = base64.urlsafe_b64encode(bytes([11]) * 32).rstrip(
    b"="
).decode("ascii")
MISSING = object()


@dataclass(frozen=True)
class CopilotFixture:
    plugin: copilot.CopilotPlugin
    config: InstallConfig
    home_dir: Path
    copilot_home: Path
    project_dir: Path
    agent_dir: Path
    config_path: Path
    legacy_path: Path
    guard_path: Path
    hook_path: Path
    runtime_config_path: Path
    private_key_path: Path
    user_settings_path: Path
    legacy_user_config_path: Path
    claude_settings_path: Path
    claude_local_settings_path: Path
    repository_settings_path: Path
    local_settings_path: Path


def write_json_or_text(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    source = (
        value
        if isinstance(value, str)
        else json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    )
    path.write_text(source, encoding="utf-8")


def prepare_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    user_config: object = MISSING,
    legacy_config: object = MISSING,
    user_settings: object = MISSING,
    legacy_user_config: object = MISSING,
    claude_settings: object = MISSING,
    claude_local_settings: object = MISSING,
    repository_settings: object = MISSING,
    local_settings: object = MISSING,
) -> CopilotFixture:
    home_dir = tmp_path / "home with spaces and 'quote %COPILOT%"
    project_dir = tmp_path / "project with spaces"
    copilot_home = home_dir / "custom Copilot 'home"
    agent_dir = home_dir / ".elydora" / AGENT_ID
    config_path = copilot_home / "hooks" / "elydora-audit.json"
    legacy_path = project_dir / ".github" / "hooks" / "hooks.json"
    user_settings_path = copilot_home / "settings.json"
    legacy_user_config_path = copilot_home / "config.json"
    claude_settings_path = project_dir / ".claude" / "settings.json"
    claude_local_settings_path = (
        project_dir / ".claude" / "settings.local.json"
    )
    repository_settings_path = (
        project_dir / ".github" / "copilot" / "settings.json"
    )
    local_settings_path = (
        project_dir / ".github" / "copilot" / "settings.local.json"
    )
    project_dir.mkdir(parents=True)
    optional = (
        (config_path, user_config),
        (legacy_path, legacy_config),
        (user_settings_path, user_settings),
        (legacy_user_config_path, legacy_user_config),
        (claude_settings_path, claude_settings),
        (claude_local_settings_path, claude_local_settings),
        (repository_settings_path, repository_settings),
        (local_settings_path, local_settings),
    )
    for path, value in optional:
        if value is not MISSING:
            write_json_or_text(path, value)

    monkeypatch.chdir(project_dir)
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("USERPROFILE", str(home_dir))
    monkeypatch.setenv("COPILOT_HOME", str(copilot_home))
    config: InstallConfig = {
        "agent_id": AGENT_ID,
        "agent_name": "copilot",
        "org_id": "org-1",
        "private_key": VALID_PRIVATE_KEY,
        "kid": "kid-1",
        "token": "token-1",
        "base_url": "http://127.0.0.1:9",
        "guard_script_path": str(agent_dir / "guard.py"),
    }
    return CopilotFixture(
        plugin=copilot.CopilotPlugin(),
        config=config,
        home_dir=home_dir,
        copilot_home=copilot_home,
        project_dir=project_dir,
        agent_dir=agent_dir,
        config_path=config_path,
        legacy_path=legacy_path,
        guard_path=agent_dir / "guard.py",
        hook_path=agent_dir / "hook.py",
        runtime_config_path=agent_dir / "config.json",
        private_key_path=agent_dir / "private.key",
        user_settings_path=user_settings_path,
        legacy_user_config_path=legacy_user_config_path,
        claude_settings_path=claude_settings_path,
        claude_local_settings_path=claude_local_settings_path,
        repository_settings_path=repository_settings_path,
        local_settings_path=local_settings_path,
    )


def managed_handler(
    settings: dict[str, Any], event: str, script_name: str
) -> dict[str, Any]:
    for handler in settings.get("hooks", {}).get(event, []):
        if script_name in str(handler.get("bash")):
            return handler
    raise AssertionError(f"managed {event} handler not found")


def assert_native_handler(handler: dict[str, Any]) -> None:
    assert set(handler) == {"type", "bash", "powershell", "timeoutSec"}
    assert handler["type"] == "command"
    assert handler["timeoutSec"] == 10
    assert handler["bash"].startswith("'")
    assert Path(sys.executable).name in handler["bash"]
    assert handler["powershell"].startswith("& '")
    assert handler["powershell"].endswith("; exit $LASTEXITCODE")


def legacy_managed_config(
    fixture: CopilotFixture,
    extra_hooks: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "version": 1,
        "hooks": {
            "preToolUse": [{
                "type": "command",
                "bash": f'"{sys.executable}" {fixture.guard_path}',
                "powershell": f'"{sys.executable}" {fixture.guard_path}',
                "timeoutSec": 5,
            }],
            "postToolUse": [{
                "type": "command",
                "bash": str(fixture.hook_path),
                "powershell": str(fixture.hook_path),
                "timeoutSec": 5,
            }],
            **(extra_hooks or {}),
        },
    }


def run_hook(
    handler: dict[str, Any],
    fixture: CopilotFixture,
    payload: str,
) -> subprocess.CompletedProcess[str]:
    if os.name == "nt":
        command = [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            handler["powershell"],
        ]
    else:
        command = ["/bin/sh", "-c", handler["bash"]]
    return subprocess.run(
        command,
        capture_output=True,
        check=False,
        cwd=fixture.project_dir,
        env={
            **os.environ,
            "HOME": str(fixture.home_dir),
            "USERPROFILE": str(fixture.home_dir),
        },
        input=payload,
        text=True,
    )


def assert_runtime_absent(fixture: CopilotFixture) -> None:
    assert fixture.guard_path.exists() is False
    assert fixture.hook_path.exists() is False
    assert fixture.runtime_config_path.exists() is False
    assert fixture.private_key_path.exists() is False
