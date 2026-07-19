from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from elydora import cli
from elydora.plugins import _transaction, qwen
from elydora.plugins.registry import SUPPORTED_AGENTS
from qwen_support import (
    AGENT_ID,
    QwenFixture,
    generated_command,
    managed_handler,
    parse_settings,
    run_handler,
)


EXPECTED_SHELL = "powershell" if os.name == "nt" else "bash"


def test_qwen_is_registered_in_the_sdk_and_cli() -> None:
    assert SUPPORTED_AGENTS["qwen"] == {
        "name": "Qwen Code",
        "hook_event": "PreToolUse/PostToolUse",
        "config_path": "~/.qwen/settings.json",
    }
    assert cli.PLUGIN_MAP["qwen"] is qwen.QwenPlugin


def test_install_preserves_jsonc_and_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = (
        "{\r\n"
        "  // Keep this user preference.\r\n"
        '  "theme": "GitHub",\r\n'
        '  "hooks": {\r\n'
        '    "SessionStart": [{ "hooks": [{ "type": "command", "command": "session-hook" }] }],\r\n'
        '    "PreToolUse": [{ "matcher": "read_file", "hooks": [{ "type": "command", "command": "user-hook" }] }]\r\n'
        "  }\r\n"
        "}\r\n"
    )
    fixture = QwenFixture(monkeypatch, tmp_path, existing_settings=source)
    workspace_settings = fixture.workspace_dir / ".qwen" / "settings.json"
    workspace_settings.parent.mkdir(parents=True)
    workspace_settings.write_text('{ "owner": "workspace" }\n', encoding="utf-8")
    fixture.install()
    fixture.install()
    output = capsys.readouterr().out
    with open(fixture.config_path, "r", encoding="utf-8", newline="") as file:
        raw = file.read()
    settings = parse_settings(fixture.config_path)
    assert "Keep this user preference" in raw
    assert "\r\n" in raw
    assert settings["theme"] == "GitHub"
    assert settings["hooks"]["SessionStart"][0]["hooks"][0]["command"] == "session-hook"
    assert len(settings["hooks"]["PreToolUse"]) == 2
    assert len(settings["hooks"]["PostToolUse"]) == 1
    for event, script_path in (
        ("PreToolUse", fixture.guard_path),
        ("PostToolUse", fixture.audit_path),
    ):
        handler = managed_handler(settings, event, script_path)
        assert handler is not None
        assert sorted(handler) == ["command", "shell", "timeout", "type"]
        assert handler["shell"] == EXPECTED_SHELL
        assert handler["timeout"] == 10_000
    assert parse_settings(workspace_settings) == {"owner": "workspace"}
    assert (
        json.loads(fixture.runtime_config.read_text(encoding="utf-8"))["agent_name"]
        == "qwen"
    )
    assert fixture.private_key_path.is_file()
    assert fixture.audit_path.is_file()
    assert "run /hooks" in output


def test_qwen_home_uses_official_user_env_precedence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = QwenFixture(monkeypatch, tmp_path)
    first_home = tmp_path / "first # qwen home"
    second_home = tmp_path / "second qwen home"
    fixture.qwen_dir.mkdir(parents=True)
    (fixture.qwen_dir / ".env").write_text(
        f'export QWEN_HOME = "{first_home}" # selected by Qwen\n',
        encoding="utf-8",
    )
    (fixture.home_dir / ".env").write_text(
        f"QWEN_HOME={second_home}\n", encoding="utf-8"
    )
    fixture.install()
    selected = first_home / "settings.json"
    assert managed_handler(parse_settings(selected), "PreToolUse", fixture.guard_path)
    assert not (second_home / "settings.json").exists()
    assert not fixture.config_path.exists()
    assert str(selected) in fixture.plugin.status()["details"]


@pytest.mark.parametrize(
    ("value", "relative"),
    [
        ("relative-qwen", "relative-qwen"),
        ("~/custom-qwen", "custom-qwen"),
        ("", ".qwen"),
    ],
)
def test_explicit_qwen_home_supports_relative_tilde_and_empty_values(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    value: str,
    relative: str,
) -> None:
    fixture = QwenFixture(monkeypatch, tmp_path / (relative.replace(".", "default")))
    fixture.qwen_dir.mkdir(parents=True)
    ignored = tmp_path / "ignored-qwen-home"
    (fixture.qwen_dir / ".env").write_text(f"QWEN_HOME={ignored}\n", encoding="utf-8")
    monkeypatch.setenv("QWEN_HOME", value)
    fixture.install()
    if value.startswith("relative"):
        selected = fixture.workspace_dir / relative / "settings.json"
    else:
        selected = fixture.home_dir / relative / "settings.json"
    assert "hooks" in parse_settings(selected)
    assert not (ignored / "settings.json").exists()


def test_commands_block_and_forward_official_input_byte_for_byte(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = QwenFixture(monkeypatch, tmp_path)
    fixture.install()
    capture_path = tmp_path / "captured-event.json"
    fixture.audit_path.write_text(
        "import pathlib, sys\n"
        f"pathlib.Path({str(capture_path)!r}).write_bytes(sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    settings = parse_settings(fixture.config_path)
    guard = managed_handler(settings, "PreToolUse", fixture.guard_path)
    audit = managed_handler(settings, "PostToolUse", fixture.audit_path)
    assert guard is not None and audit is not None
    payload = json.dumps(
        {
            "session_id": "session-1",
            "transcript_path": "transcript.jsonl",
            "cwd": str(fixture.workspace_dir),
            "hook_event_name": "PreToolUse",
            "timestamp": "2026-07-19T00:00:00.000Z",
            "tool_name": "run_shell_command",
            "tool_input": {"command": "echo test"},
        }
    )
    guard_result = run_handler(guard, payload)
    assert guard_result.returncode == 2
    assert "Agent is frozen by Elydora" in guard_result.stderr
    post_payload = payload.replace("PreToolUse", "PostToolUse")
    audit_result = run_handler(audit, post_payload)
    assert audit_result.returncode == 0, audit_result.stderr
    assert capture_path.read_text(encoding="utf-8") == post_payload


def test_status_requires_enabled_pair_and_complete_runtime(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = QwenFixture(monkeypatch, tmp_path)
    fixture.install()
    assert fixture.plugin.status()["installed"] is True
    settings = parse_settings(fixture.config_path)
    settings["disableAllHooks"] = True
    fixture.config_path.write_text(json.dumps(settings), encoding="utf-8")
    status = fixture.plugin.status()
    assert status["installed"] is False
    assert "disabled" in status["details"].lower()
    settings["disableAllHooks"] = False
    fixture.config_path.write_text(json.dumps(settings), encoding="utf-8")
    fixture.guard_path.unlink()
    status = fixture.plugin.status()
    assert status["installed"] is False
    assert "runtime" in status["details"].lower()


def test_uninstall_preserves_external_mutations_and_exact_ownership(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = QwenFixture(
        monkeypatch,
        tmp_path,
        existing_settings='{"$version":4,"owner":"user"}',
    )
    fixture.install()
    settings = parse_settings(fixture.config_path)
    managed_group = settings["hooks"]["PreToolUse"][-1]
    managed_group["hooks"].append({"type": "command", "command": "user-command"})
    lookalike = fixture.home_dir / ".elydora" / "agent-10" / "guard.py"
    settings["hooks"]["PreToolUse"].append(
        {
            "matcher": "*",
            "hooks": [
                {
                    "type": "command",
                    "command": generated_command(lookalike),
                    "shell": EXPECTED_SHELL,
                    "timeout": 10_000,
                }
            ],
        }
    )
    fixture.config_path.write_text(
        json.dumps(settings, indent=2) + "\n", encoding="utf-8"
    )
    before = fixture.config_path.read_text(encoding="utf-8")
    fixture.plugin.uninstall("other-agent")
    assert fixture.config_path.read_text(encoding="utf-8") == before
    uninstall_id = "AGENT-1" if os.name == "nt" else AGENT_ID
    fixture.plugin.uninstall(uninstall_id)
    remaining = parse_settings(fixture.config_path)
    assert remaining["$version"] == 4
    assert remaining["owner"] == "user"
    assert remaining["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "user-command"
    assert "agent-10" in json.dumps(remaining)
    assert "PostToolUse" not in remaining.get("hooks", {})


def test_uninstall_deletes_an_empty_elydora_owned_settings_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = QwenFixture(monkeypatch, tmp_path)
    fixture.install()
    assert fixture.config_path.read_text(encoding="utf-8").startswith(
        "// Managed by Elydora"
    )
    fixture.plugin.uninstall(AGENT_ID)
    assert not fixture.config_path.exists()


@pytest.mark.parametrize(
    "source",
    [
        "{ malformed",
        "[]",
        '{ "owner": true, }',
        '{ "hooks": {}, "hooks": {} }',
        '{ "disableAllHooks": "yes" }',
        '{ "hooks": [] }',
        '{ "hooks": { "UnknownEvent": [] } }',
        '{ "hooks": { "PreToolUse": null } }',
        '{ "hooks": { "PreToolUse": [null] } }',
        '{ "hooks": { "PreToolUse": [{ "matcher": "[", "hooks": [] }] } }',
        '{ "hooks": { "PreToolUse": [{ "sequential": "yes", "hooks": [] }] } }',
        '{ "hooks": { "PreToolUse": [{ "hooks": null }] } }',
        '{ "hooks": { "PreToolUse": [{ "hooks": [{ "type": "command" }] }] } }',
        '{ "hooks": { "PreToolUse": [{ "hooks": [{ "type": "http" }] }] }',
        '{ "hooks": { "PreToolUse": [{ "hooks": [{ "type": "function", "command": "x" }] }] } }',
        '{ "hooks": { "PreToolUse": [{ "hooks": [{ "type": "command", "command": "x", "timeout": "ten" }] }] } }',
    ],
)
def test_install_rejects_malformed_settings_before_every_write(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    source: str,
) -> None:
    fixture = QwenFixture(monkeypatch, tmp_path, existing_settings=source)
    with pytest.raises((ValueError, RuntimeError), match="Qwen"):
        fixture.install()
    assert fixture.config_path.read_text(encoding="utf-8") == source
    assert not fixture.audit_path.exists()
    assert not fixture.runtime_config.exists()
    assert not fixture.private_key_path.exists()


def test_install_fails_on_unreadable_env_and_missing_guard(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    env_fixture = QwenFixture(monkeypatch, tmp_path / "env")
    (env_fixture.qwen_dir / ".env").mkdir(parents=True)
    with pytest.raises(OSError, match="Qwen home environment"):
        env_fixture.install()
    assert not env_fixture.config_path.exists()
    assert not env_fixture.runtime_config.exists()

    runtime_fixture = QwenFixture(
        monkeypatch,
        tmp_path / "runtime",
        create_guard=False,
    )
    with pytest.raises(FileNotFoundError, match="guard runtime is missing"):
        runtime_fixture.install()
    assert not runtime_fixture.config_path.exists()
    assert not runtime_fixture.runtime_config.exists()


def test_status_surfaces_malformed_runtime_metadata_and_cleans_staging(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = QwenFixture(monkeypatch, tmp_path)
    fixture.install()
    assert [
        path
        for path in fixture.home_dir.rglob("*")
        if path.suffix in {".tmp", ".rollback"}
    ] == []
    fixture.runtime_config.write_text("{ malformed", encoding="utf-8")
    with pytest.raises(ValueError, match="parse Elydora runtime config"):
        fixture.plugin.status()


def test_transaction_rolls_back_runtime_and_settings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = QwenFixture(
        monkeypatch,
        tmp_path,
        existing_settings={"owner": "user"},
    )
    original = fixture.config_path.read_text(encoding="utf-8")
    real_replace = _transaction.os.replace
    failed = False

    def fail_settings_commit(source: Any, destination: Any) -> None:
        nonlocal failed
        if not failed and Path(destination) == fixture.config_path:
            failed = True
            raise OSError("simulated settings commit failure")
        real_replace(source, destination)

    monkeypatch.setattr(_transaction.os, "replace", fail_settings_commit)
    with pytest.raises(OSError, match="Write Qwen Code installation"):
        fixture.install()
    assert failed is True
    assert fixture.config_path.read_text(encoding="utf-8") == original
    assert not fixture.audit_path.exists()
    assert not fixture.runtime_config.exists()
    assert not fixture.private_key_path.exists()
    assert [
        path
        for path in fixture.home_dir.rglob("*")
        if path.suffix in {".tmp", ".rollback"}
    ] == []


def test_install_rejects_invalid_agent_id_before_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = QwenFixture(monkeypatch, tmp_path)
    fixture.config["agent_id"] = "../escape"
    with pytest.raises(ValueError, match="single non-empty path segment"):
        fixture.install()
    assert not fixture.config_path.exists()
