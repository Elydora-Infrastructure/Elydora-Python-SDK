from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
from typing import Any

import pytest

from elydora.plugins import codex
from elydora.plugins.base import InstallConfig
from elydora.plugins.registry import SUPPORTED_AGENTS


AGENT_ID = "agent-1"
MISSING = object()
GUARD_STATUS = "Checking Elydora agent state"
AUDIT_STATUS = "Recording Elydora tool use"


@dataclass(frozen=True)
class CodexFixture:
    plugin: codex.CodexPlugin
    config: InstallConfig
    home_dir: Path
    agent_dir: Path
    config_path: Path
    guard_path: Path
    hook_path: Path
    runtime_config_path: Path
    private_key_path: Path


def write_json_or_text(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = value if isinstance(value, str) else json.dumps(value, indent=2)
    path.write_text(content, encoding="utf-8")


def prepare_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    existing_settings: Any = MISSING,
    create_guard: bool = True,
) -> CodexFixture:
    home_dir = tmp_path / "home with spaces"
    elydora_dir = home_dir / ".elydora"
    agent_dir = elydora_dir / AGENT_ID
    config_path = home_dir / ".codex" / "hooks.json"
    agent_dir.mkdir(parents=True)

    guard_path = agent_dir / "guard.py"
    if create_guard:
        guard_path.write_text(
            "import sys\nsys.stderr.write('Agent is frozen by Elydora.')\n"
            "raise SystemExit(2)\n",
            encoding="utf-8",
        )
    if existing_settings is not MISSING:
        write_json_or_text(config_path, existing_settings)

    monkeypatch.setattr(codex, "ELYDORA_DIR", str(elydora_dir))
    monkeypatch.setattr(codex, "CONFIG_PATH", str(config_path))
    config: InstallConfig = {
        "agent_id": AGENT_ID,
        "agent_name": "codex",
        "org_id": "org-1",
        "private_key": "test-key",
        "kid": "kid-1",
        "base_url": "https://api.elydora.test",
        "guard_script_path": str(guard_path),
    }
    return CodexFixture(
        plugin=codex.CodexPlugin(),
        config=config,
        home_dir=home_dir,
        agent_dir=agent_dir,
        config_path=config_path,
        guard_path=guard_path,
        hook_path=agent_dir / "hook.py",
        runtime_config_path=agent_dir / "config.json",
        private_key_path=agent_dir / "private.key",
    )


def find_handler(
    settings: dict[str, Any],
    event: str,
    status_message: str,
) -> dict[str, Any]:
    for group in settings["hooks"][event]:
        for handler in group["hooks"]:
            if handler.get("statusMessage") == status_message:
                return handler
    raise AssertionError(f"handler {status_message!r} not found")


def run_command(
    command: str,
    home_dir: Path,
    payload: dict[str, Any],
) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "HOME": str(home_dir),
        "USERPROFILE": str(home_dir),
    }
    return subprocess.run(
        command,
        shell=True,
        capture_output=True,
        check=False,
        env=env,
        input=json.dumps(payload),
        text=True,
    )


def test_codex_registry_points_at_global_hooks_contract() -> None:
    assert SUPPORTED_AGENTS["codex"] == {
        "name": "OpenAI Codex",
        "hook_event": "PreToolUse/PostToolUse",
        "config_path": "~/.codex/hooks.json",
    }


def test_install_preserves_existing_hooks_and_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        existing_settings={
            "description": "Workspace hooks",
            "hooks": {
                "SessionStart": [{
                    "hooks": [{"type": "command", "command": "existing-command"}],
                }],
            },
        },
    )

    fixture.plugin.install(fixture.config)
    fixture.plugin.install(fixture.config)

    assert "run /hooks to review and trust" in capsys.readouterr().out
    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    assert settings["description"] == "Workspace hooks"
    assert settings["hooks"]["SessionStart"][0]["hooks"][0]["command"] == "existing-command"
    assert len(settings["hooks"]["PreToolUse"]) == 1
    assert len(settings["hooks"]["PostToolUse"]) == 1
    assert settings["hooks"]["PreToolUse"][0]["matcher"] == "*"
    guard = find_handler(settings, "PreToolUse", GUARD_STATUS)
    assert guard["type"] == "command"
    assert guard["timeout"] == 10
    assert isinstance(guard["command"], str)
    assert isinstance(guard["commandWindows"], str)


def test_commands_block_frozen_agents_and_forward_official_payload(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    capture_path = tmp_path / "captured-event.json"
    fixture.hook_path.write_text(
        "import pathlib, sys\n"
        f"pathlib.Path({str(capture_path)!r}).write_text(sys.stdin.read(), encoding='utf-8')\n",
        encoding="utf-8",
    )
    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    command_key = "commandWindows" if os.name == "nt" else "command"
    payload = {
        "hook_event_name": "PreToolUse",
        "session_id": "session-1",
        "turn_id": "turn-1",
        "transcript_path": None,
        "cwd": str(fixture.home_dir),
        "model": "gpt-5",
        "permission_mode": "default",
        "tool_name": "Bash",
        "tool_use_id": "call-1",
        "tool_input": {"command": "echo test"},
    }

    guard = find_handler(settings, "PreToolUse", GUARD_STATUS)
    guard_result = run_command(guard[command_key], fixture.home_dir, payload)
    assert guard_result.returncode == 2
    assert "Agent is frozen by Elydora" in guard_result.stderr

    payload["hook_event_name"] = "PostToolUse"
    payload["tool_response"] = {"output": "test"}
    audit = find_handler(settings, "PostToolUse", AUDIT_STATUS)
    audit_result = run_command(audit[command_key], fixture.home_dir, payload)
    assert audit_result.returncode == 0
    assert json.loads(capture_path.read_text(encoding="utf-8")) == payload


def test_status_requires_both_runtimes_and_uninstall_preserves_other_hooks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    existing_handler = {"type": "command", "command": "existing-command"}
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        existing_settings={
            "hooks": {"PreToolUse": [{"hooks": [existing_handler]}]},
        },
    )
    fixture.plugin.install(fixture.config)
    assert fixture.plugin.status() == {
        "installed": True,
        "agent": "codex",
        "details": f"Config: {fixture.config_path}",
    }

    fixture.guard_path.unlink()
    assert fixture.plugin.status() == {
        "installed": False,
        "agent": "codex",
        "details": f"Configured at {fixture.config_path}; runtime scripts missing",
    }

    fixture.plugin.uninstall(AGENT_ID)
    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    assert settings["hooks"]["PreToolUse"] == [{"hooks": [existing_handler]}]
    assert settings["hooks"]["PostToolUse"] == []


def test_install_preserves_user_handlers_with_matching_status_text(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    user_guard = {
        "type": "command",
        "command": "user-guard",
        "statusMessage": GUARD_STATUS,
    }
    user_audit = {
        "type": "command",
        "command": "user-audit",
        "statusMessage": AUDIT_STATUS,
    }
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        existing_settings={
            "hooks": {
                "PreToolUse": [{"matcher": "Bash", "hooks": [user_guard]}],
                "PostToolUse": [{"matcher": "Bash", "hooks": [user_audit]}],
            },
        },
    )

    fixture.plugin.install(fixture.config)

    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    assert settings["hooks"]["PreToolUse"][0]["hooks"][0] == user_guard
    assert settings["hooks"]["PostToolUse"][0]["hooks"][0] == user_audit
    assert len(settings["hooks"]["PreToolUse"]) == 2
    assert len(settings["hooks"]["PostToolUse"]) == 2


def test_install_rejects_missing_guard_before_runtime_or_config_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, create_guard=False)

    with pytest.raises(FileNotFoundError, match="guard runtime is missing"):
        fixture.plugin.install(fixture.config)

    assert fixture.config_path.exists() is False
    assert fixture.hook_path.exists() is False
    assert fixture.runtime_config_path.exists() is False
    assert fixture.private_key_path.exists() is False


def test_status_surfaces_malformed_referenced_runtime_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    fixture.runtime_config_path.write_text("{ malformed", encoding="utf-8")

    with pytest.raises(ValueError, match="parse Elydora runtime config"):
        fixture.plugin.status()


def test_status_surfaces_malformed_matcher_groups(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    settings["hooks"]["PreToolUse"][0]["hooks"] = None
    fixture.config_path.write_text(json.dumps(settings), encoding="utf-8")

    with pytest.raises(ValueError, match="matcher group must contain a hooks array"):
        fixture.plugin.status()


def test_uninstall_removes_config_owned_entirely_by_elydora(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)

    fixture.plugin.uninstall(AGENT_ID)

    assert fixture.config_path.exists() is False


def test_uninstall_matches_the_exact_agent_runtime_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    other_agent_dir = fixture.agent_dir.parent / "agent-10"

    for event, status in (
        ("PreToolUse", GUARD_STATUS),
        ("PostToolUse", AUDIT_STATUS),
    ):
        handler = find_handler(settings, event, status)
        other_handler = {
            **handler,
            "command": handler["command"].replace(
                str(fixture.agent_dir), str(other_agent_dir)
            ),
            "commandWindows": handler["commandWindows"].replace(
                str(fixture.agent_dir), str(other_agent_dir)
            ),
        }
        settings["hooks"][event].append(
            {"matcher": "*", "hooks": [other_handler]}
        )
    fixture.config_path.write_text(json.dumps(settings), encoding="utf-8")

    fixture.plugin.uninstall(AGENT_ID)

    remaining = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    assert len(remaining["hooks"]["PreToolUse"]) == 1
    assert len(remaining["hooks"]["PostToolUse"]) == 1
    assert str(other_agent_dir) in find_handler(
        remaining, "PreToolUse", GUARD_STATUS
    )["command"]


@pytest.mark.parametrize(
    ("existing_settings", "error_pattern"),
    [
        ({"hooks": None}, 'field "hooks" must be an object'),
        ({"hooks": {"PreToolUse": None}}, 'field "hooks.PreToolUse" must be an array'),
        (
            {"hooks": {"PreToolUse": [{"hooks": None}]}},
            "matcher group must contain a hooks array",
        ),
    ],
)
def test_install_preserves_invalid_shapes_before_runtime_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    existing_settings: dict[str, Any],
    error_pattern: str,
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        existing_settings=existing_settings,
    )
    original = fixture.config_path.read_text(encoding="utf-8")

    with pytest.raises(ValueError, match=error_pattern):
        fixture.plugin.install(fixture.config)

    assert fixture.config_path.read_text(encoding="utf-8") == original
    assert fixture.hook_path.exists() is False
    assert fixture.runtime_config_path.exists() is False
    assert fixture.private_key_path.exists() is False


def test_install_preserves_malformed_config_before_runtime_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        existing_settings="{ malformed",
    )

    with pytest.raises(ValueError, match="parse Codex hooks config"):
        fixture.plugin.install(fixture.config)

    assert fixture.config_path.read_text(encoding="utf-8") == "{ malformed"
    assert fixture.hook_path.exists() is False
    assert fixture.runtime_config_path.exists() is False
    assert fixture.private_key_path.exists() is False
