from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
from typing import Any

import pytest

from elydora import cli
from elydora.plugins import grok
from elydora.plugins.base import InstallConfig
from elydora.plugins.registry import SUPPORTED_AGENTS


AGENT_ID = "agent-1"
MISSING = object()


@dataclass(frozen=True)
class GrokFixture:
    plugin: grok.GrokPlugin
    config: InstallConfig
    home_dir: Path
    grok_home: Path
    agent_dir: Path
    config_path: Path
    guard_path: Path
    hook_path: Path
    runtime_config_path: Path
    private_key_path: Path


def prepare_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    existing_config: object = MISSING,
    explicit_grok_home: bool = True,
    create_guard: bool = True,
) -> GrokFixture:
    home_dir = tmp_path / "home with spaces"
    agent_dir = home_dir / ".elydora" / AGENT_ID
    grok_home = (
        home_dir / "custom grok"
        if explicit_grok_home
        else home_dir / ".grok"
    )
    config_path = grok_home / "hooks" / "elydora-audit.json"
    guard_path = agent_dir / "guard.py"
    hook_path = agent_dir / "hook.py"
    agent_dir.mkdir(parents=True)
    if create_guard:
        guard_path.write_text(
            "import sys\nsys.stdin.read()\n"
            "sys.stderr.write('Agent is frozen by Elydora.')\n"
            "raise SystemExit(2)\n",
            encoding="utf-8",
        )
    if existing_config is not MISSING:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        raw = (
            str(existing_config)
            if isinstance(existing_config, str)
            else json.dumps(existing_config, indent=2)
        )
        config_path.write_text(raw, encoding="utf-8")

    monkeypatch.setattr(grok, "ELYDORA_DIR", str(agent_dir.parent))
    monkeypatch.setattr(grok, "_home_dir", lambda: str(home_dir))
    if explicit_grok_home:
        monkeypatch.setenv("GROK_HOME", str(grok_home))
    else:
        monkeypatch.delenv("GROK_HOME", raising=False)

    config: InstallConfig = {
        "agent_id": AGENT_ID,
        "agent_name": "grok",
        "org_id": "org-1",
        "private_key": "test-key",
        "kid": "kid-1",
        "base_url": "https://api.elydora.test",
        "guard_script_path": str(guard_path),
    }
    return GrokFixture(
        plugin=grok.GrokPlugin(),
        config=config,
        home_dir=home_dir,
        grok_home=grok_home,
        agent_dir=agent_dir,
        config_path=config_path,
        guard_path=guard_path,
        hook_path=hook_path,
        runtime_config_path=agent_dir / "config.json",
        private_key_path=agent_dir / "private.key",
    )


def managed_handler(
    settings: dict[str, Any], event: str, script_name: str
) -> dict[str, Any]:
    for group in settings["hooks"][event]:
        if "matcher" in group:
            continue
        for handler in group["hooks"]:
            if script_name in str(handler.get("command")):
                return handler
    raise AssertionError(f"managed {event} handler not found")


def run_command(
    command: str,
    home_dir: Path,
    payload: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        shell=True,
        capture_output=True,
        check=False,
        env={**os.environ, "HOME": str(home_dir), "USERPROFILE": str(home_dir)},
        input=payload,
        text=True,
    )


def test_grok_is_registered_in_sdk_and_cli() -> None:
    assert SUPPORTED_AGENTS["grok"] == {
        "name": "Grok Build",
        "hook_event": "PreToolUse/PostToolUse",
        "config_path": "~/.grok/hooks/elydora-audit.json",
    }
    assert cli.PLUGIN_MAP["grok"] is grok.GrokPlugin


def test_install_preserves_native_config_and_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    existing = {
        "schemaVersion": 1,
        "hooks": {
            "SessionStart": [{
                "matcher": "startup",
                "hooks": [{
                    "type": "http",
                    "url": "https://example.test/hook",
                    "timeout": 5,
                    "headers": {"x": "keep"},
                }],
                "label": "keep group metadata",
            }],
            "PreToolUse": [{
                "matcher": "Bash",
                "hooks": [{
                    "type": "command",
                    "command": "existing-command",
                    "timeout": 5,
                }],
            }],
        },
    }
    fixture = prepare_fixture(
        monkeypatch, tmp_path, existing_config=existing
    )

    fixture.plugin.install(fixture.config)
    fixture.plugin.install(fixture.config)

    assert "global PreToolUse and PostToolUse hooks installed" in capsys.readouterr().out
    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    assert settings["schemaVersion"] == 1
    assert settings["hooks"]["SessionStart"] == existing["hooks"]["SessionStart"]
    assert settings["hooks"]["PreToolUse"][0] == existing["hooks"]["PreToolUse"][0]
    assert len(settings["hooks"]["PreToolUse"]) == 2
    assert len(settings["hooks"]["PostToolUse"]) == 1
    assert set(settings["hooks"]["PreToolUse"][1]) == {"hooks"}
    for event, script_name in (
        ("PreToolUse", "guard.py"),
        ("PostToolUse", "hook.py"),
    ):
        handler = managed_handler(settings, event, script_name)
        assert set(handler) == {"type", "command", "timeout"}
        assert handler["type"] == "command"
        assert handler["timeout"] == 10
    assert json.loads(fixture.runtime_config_path.read_text())["agent_name"] == "grok"
    assert fixture.private_key_path.read_text(encoding="utf-8") == "test-key"
    assert (fixture.home_dir / ".claude" / "settings.json").exists() is False
    assert (fixture.home_dir / ".cursor" / "hooks.json").exists() is False
    assert (
        fixture.home_dir / ".grok" / "hooks" / "elydora-audit.json"
    ).exists() is False


def test_empty_home_override_uses_official_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(
        monkeypatch, tmp_path, explicit_grok_home=False
    )
    fixture.plugin.install(fixture.config)
    monkeypatch.setenv("GROK_HOME", "")

    assert fixture.plugin.status()["installed"] is True


def test_commands_block_and_forward_official_payload_byte_for_byte(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    capture_path = tmp_path / "captured-event.json"
    fixture.hook_path.write_text(
        "from pathlib import Path\nimport sys\n"
        f"Path({str(capture_path)!r}).write_text(sys.stdin.read(), encoding='utf-8')\n",
        encoding="utf-8",
    )
    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    pre_payload = json.dumps({
        "hookEventName": "PreToolUse",
        "sessionId": "session-1",
        "cwd": str(fixture.home_dir),
        "workspaceRoot": str(fixture.home_dir),
        "toolName": "Bash",
        "toolInput": {"command": "echo test"},
    }, separators=(",", ":"))
    guard = managed_handler(settings, "PreToolUse", "guard.py")
    guard_result = run_command(guard["command"], fixture.home_dir, pre_payload)
    assert guard_result.returncode == 2
    assert "Agent is frozen by Elydora" in guard_result.stderr

    post_payload = json.dumps({
        "hookEventName": "PostToolUse",
        "sessionId": "session-1",
        "cwd": str(fixture.home_dir),
        "workspaceRoot": str(fixture.home_dir),
        "toolName": "Bash",
        "toolInput": {"command": "echo test"},
        "toolResult": {"output": "test"},
    }, separators=(",", ":"))
    audit = managed_handler(settings, "PostToolUse", "hook.py")
    audit_result = run_command(audit["command"], fixture.home_dir, post_payload)
    assert audit_result.returncode == 0
    assert capture_path.read_text(encoding="utf-8") == post_payload


def test_status_requires_complete_pair_and_both_runtime_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    assert fixture.plugin.status()["installed"] is True

    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    del settings["hooks"]["PostToolUse"]
    fixture.config_path.write_text(json.dumps(settings), encoding="utf-8")
    assert fixture.plugin.status()["installed"] is False

    fixture.plugin.install(fixture.config)
    fixture.guard_path.unlink()
    status = fixture.plugin.status()
    assert status["installed"] is False
    assert "runtime scripts missing" in status["details"]


def test_uninstall_removes_exact_ownership_and_preserves_mixed_handlers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        existing_config={"owner": "user", "hooks": {"Notification": []}},
    )
    fixture.plugin.install(fixture.config)
    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    settings["hooks"]["PreToolUse"][-1]["hooks"].append({
        "type": "command",
        "command": "user-command",
        "timeout": 10,
    })
    settings["hooks"]["PreToolUse"].append({"hooks": [{
        "type": "command",
        "command": grok._build_command(str(fixture.agent_dir / "guard.py.backup")),
        "timeout": 10,
    }]})
    settings["hooks"]["PreToolUse"].append({"hooks": [{
        "type": "command",
        "command": grok._build_command(str(
            fixture.agent_dir.parent / "agent-10" / "guard.py"
        )),
        "timeout": 10,
    }]})
    fixture.config_path.write_text(json.dumps(settings), encoding="utf-8")

    uninstall_id = "AGENT-1" if os.name == "nt" else AGENT_ID
    fixture.plugin.uninstall(uninstall_id)

    remaining = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    assert remaining["owner"] == "user"
    assert remaining["hooks"]["Notification"] == []
    assert len(remaining["hooks"]["PreToolUse"]) == 3
    assert remaining["hooks"]["PreToolUse"][0]["hooks"] == [{
        "type": "command",
        "command": "user-command",
        "timeout": 10,
    }]
    raw = fixture.config_path.read_text(encoding="utf-8")
    assert "guard.py.backup" in raw
    assert "agent-10" in raw
    assert "PostToolUse" not in remaining["hooks"]


def test_install_replaces_stale_handlers_for_every_agent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    for event, script_name in (
        ("PreToolUse", "guard.py"),
        ("PostToolUse", "hook.py"),
    ):
        settings["hooks"][event].append({"hooks": [{
            "type": "command",
            "command": grok._build_command(str(
                fixture.agent_dir.parent / "agent-old" / script_name
            )),
            "timeout": 10,
        }]})
    fixture.config_path.write_text(json.dumps(settings), encoding="utf-8")

    fixture.plugin.install(fixture.config)

    raw = fixture.config_path.read_text(encoding="utf-8")
    current = json.loads(raw)
    assert "agent-old" not in raw
    assert len(current["hooks"]["PreToolUse"]) == 1
    assert len(current["hooks"]["PostToolUse"]) == 1


def test_uninstall_preserves_untouched_empty_native_event(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(
        monkeypatch, tmp_path, existing_config={"owner": "user"}
    )
    fixture.plugin.install(fixture.config)
    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    settings["hooks"]["PreToolUse"] = []
    fixture.config_path.write_text(json.dumps(settings), encoding="utf-8")

    fixture.plugin.uninstall(AGENT_ID)

    remaining = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    assert remaining["hooks"]["PreToolUse"] == []
    assert "PostToolUse" not in remaining["hooks"]


def test_uninstall_removes_config_owned_entirely_by_elydora(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)

    fixture.plugin.uninstall(AGENT_ID)

    assert fixture.config_path.exists() is False


def test_install_preserves_malformed_json_for_recovery(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(
        monkeypatch, tmp_path, existing_config="{ malformed"
    )

    with pytest.raises(ValueError, match="parse Grok hooks config"):
        fixture.plugin.install(fixture.config)

    assert fixture.config_path.read_text(encoding="utf-8") == "{ malformed"
    assert fixture.hook_path.exists() is False
    assert fixture.runtime_config_path.exists() is False


@pytest.mark.parametrize(
    "existing",
    [
        {"hooks": None},
        {"hooks": {"PreToolUse": None}},
        {"hooks": {"PreToolUse": [None]}},
        {"hooks": {"PreToolUse": [{"matcher": None, "hooks": []}]}},
        {"hooks": {"PreToolUse": [{"matcher": 1, "hooks": []}]}},
        {"hooks": {"PreToolUse": [{"hooks": None}]}},
        {"hooks": {"PreToolUse": [{"hooks": [
            {"type": "command", "command": ""}
        ]}]}},
        {"hooks": {"PreToolUse": [{"hooks": [
            {"type": "file", "command": "x"}
        ]}]}},
        {"hooks": {"PreToolUse": [{"hooks": [
            {"type": {"future": True}, "command": "x"}
        ]}]}},
        {"hooks": {"PreToolUse": [{"hooks": [
            {"type": "http", "url": ""}
        ]}]}},
        {"hooks": {"PreToolUse": [{"hooks": [
            {"type": "command", "command": "x", "timeout": 0}
        ]}]}},
        {"hooks": {"PreToolUse": [{"hooks": [
            {"type": "command", "command": "x", "timeout": float("inf")}
        ]}]}},
    ],
)
def test_install_rejects_invalid_native_shapes_before_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    existing: dict[str, Any],
) -> None:
    fixture = prepare_fixture(
        monkeypatch, tmp_path, existing_config=existing
    )
    original = fixture.config_path.read_text(encoding="utf-8")

    with pytest.raises(ValueError):
        fixture.plugin.install(fixture.config)

    assert fixture.config_path.read_text(encoding="utf-8") == original
    assert fixture.hook_path.exists() is False
    assert fixture.runtime_config_path.exists() is False


def test_install_rejects_missing_guard_before_creating_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, create_guard=False)

    with pytest.raises(FileNotFoundError, match="guard runtime is missing"):
        fixture.plugin.install(fixture.config)

    assert fixture.config_path.exists() is False
    assert fixture.hook_path.exists() is False
    assert fixture.runtime_config_path.exists() is False
    assert fixture.private_key_path.exists() is False


def test_status_surfaces_malformed_referenced_runtime_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    fixture.runtime_config_path.write_text("{ malformed", encoding="utf-8")

    with pytest.raises(ValueError, match="parse Elydora runtime config"):
        fixture.plugin.status()


def test_atomic_writes_leave_no_temporary_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)

    for directory in (fixture.agent_dir, fixture.config_path.parent):
        assert all(path.suffix != ".tmp" for path in directory.iterdir())
