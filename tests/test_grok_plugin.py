from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from elydora import cli
from elydora.plugins import grok
from elydora.plugins.registry import SUPPORTED_AGENTS
from grok_support import (
    AGENT_ID,
    assert_managed_triple,
    assert_no_transaction_files,
    legacy_command,
    prepare_fixture,
)


def test_grok_is_registered_in_sdk_and_cli() -> None:
    assert SUPPORTED_AGENTS["grok"] == {
        "name": "Grok Build",
        "hook_event": "PreToolUse/PostToolUse/PostToolUseFailure",
        "config_path": "~/.grok/hooks/elydora-audit.json",
    }
    assert cli.PLUGIN_MAP["grok"] is grok.GrokPlugin


def test_install_writes_exact_triple_and_preserves_valid_user_hooks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    existing = {
        "schemaVersion": 1,
        "hooks": {
            "SessionStart": [{
                "hooks": [{
                    "type": "http",
                    "url": "https://example.test/hook",
                    "timeout": 0,
                }],
                "label": "keep group metadata",
            }],
            "PreToolUse": [{
                "matcher": "Bash|run_terminal_command",
                "hooks": [{
                    "type": "command",
                    "command": "existing-command",
                    "timeout": 5,
                }],
            }],
        },
    }
    fixture = prepare_fixture(monkeypatch, tmp_path, existing_config=existing)

    fixture.install()
    first_source = fixture.config_path.read_text(encoding="utf-8")
    fixture.install()

    assert "PostToolUseFailure hooks installed" in capsys.readouterr().out
    settings = fixture.settings()
    assert fixture.config_path.read_text(encoding="utf-8") == first_source
    assert settings["schemaVersion"] == 1
    assert settings["hooks"]["SessionStart"] == existing["hooks"]["SessionStart"]
    assert settings["hooks"]["PreToolUse"][0] == existing["hooks"]["PreToolUse"][0]
    assert len(settings["hooks"]["PreToolUse"]) == 2
    assert_managed_triple(settings)
    assert not (fixture.home_dir / ".claude" / "settings.json").exists()
    assert not (fixture.home_dir / ".cursor" / "hooks.json").exists()
    assert not (
        fixture.home_dir / ".grok" / "hooks" / "elydora-audit.json"
    ).exists()


def test_empty_home_override_uses_official_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(
        monkeypatch, tmp_path, explicit_grok_home=False
    )
    fixture.install()
    monkeypatch.setenv("GROK_HOME", "")

    assert fixture.plugin.status()["installed"] is True
    assert_managed_triple(fixture.settings())


def test_install_parses_hook_file_before_creating_runtime_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(
        monkeypatch, tmp_path, existing_config="{ malformed"
    )

    with pytest.raises(ValueError, match="parse Grok user hooks"):
        fixture.install()

    assert fixture.config_path.read_text(encoding="utf-8") == "{ malformed"
    assert not fixture.agent_dir.exists()


@pytest.mark.parametrize(
    ("existing", "pattern"),
    [
        ('{"hooks":{},"hooks":{}}', 'duplicate field "hooks"'),
        ({"hooks": None}, 'field "hooks" must be an object'),
        ({"hooks": {"PreToolUse": None}}, "must be an array"),
        ({"hooks": {"PreToolUse": [None]}}, "group.*must be an object"),
        (
            {"hooks": {"PreToolUse": [{"matcher": 1, "hooks": []}]}},
            "matcher must be a string",
        ),
        (
            {"hooks": {"SessionStart": [{"matcher": "x", "hooks": []}]}},
            "cannot declare a matcher",
        ),
        (
            {"hooks": {"PreToolUse": [{"hooks": [None]}]}},
            "handler.*must be an object",
        ),
        (
            {"hooks": {"PreToolUse": [{"hooks": [{"type": "file"}]}]}},
            "unsupported type",
        ),
        (
            {"hooks": {"PreToolUse": [{"hooks": [{
                "type": "command", "command": ""
            }]}]}},
            "non-empty command",
        ),
        (
            {"hooks": {"PostToolUse": [{"hooks": [{
                "type": "http", "url": ""
            }]}]}},
            "non-empty url",
        ),
        (
            {"hooks": {"PreToolUse": [{"hooks": [{
                "type": "command", "command": "x", "timeout": -1
            }]}]}},
            "non-negative integer",
        ),
        (
            {"hooks": {"PreToolUse": [{"hooks": [{
                "type": "command", "command": "x", "timeout": 1.5
            }]}]}},
            "non-negative integer",
        ),
        (
            '{"hooks":{"PreToolUse":[{"hooks":[{"type":"command",'
            '"command":"x","timeout":NaN}]}]}}',
            "invalid numeric constant",
        ),
        (
            {"hooks": {"PreToolUse": [{"hooks": [{
                "type": "command", "command": "x", "env": {"A": 1}
            }]}]}},
            "env must map names to strings",
        ),
    ],
)
def test_install_rejects_invalid_native_shapes_before_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    existing: object,
    pattern: str,
) -> None:
    fixture = prepare_fixture(
        monkeypatch, tmp_path, existing_config=existing
    )
    original = fixture.config_path.read_text(encoding="utf-8")

    with pytest.raises(ValueError, match=pattern):
        fixture.install()

    assert fixture.config_path.read_text(encoding="utf-8") == original
    assert not fixture.agent_dir.exists()


def test_install_migrates_exact_legacy_commands_and_preserves_lookalikes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    lookalike = f"{legacy_command(fixture.guard_path)} --inspect"
    legacy = {
        "hooks": {
            "PreToolUse": [
                {"hooks": [{
                    "type": "command",
                    "command": legacy_command(fixture.guard_path),
                    "timeout": 10,
                }]},
                {"hooks": [{
                    "type": "command",
                    "command": lookalike,
                    "timeout": 10,
                }]},
            ],
            "PostToolUse": [{"hooks": [{
                "type": "command",
                "command": legacy_command(fixture.hook_path),
                "timeout": 10,
            }]}],
        }
    }
    fixture.config_path.parent.mkdir(parents=True)
    fixture.config_path.write_text(json.dumps(legacy), encoding="utf-8")

    fixture.install()
    settings = fixture.settings()
    assert_managed_triple(settings)
    assert any(
        handler.get("command") == lookalike
        for group in settings["hooks"]["PreToolUse"]
        for handler in group["hooks"]
    )
    managed = settings["hooks"]["PreToolUse"][-1]
    managed["hooks"].append({
        "type": "command", "command": "user-command", "timeout": 10
    })
    fixture.config_path.write_text(json.dumps(settings), encoding="utf-8")

    fixture.plugin.uninstall(AGENT_ID)
    remaining = fixture.settings()
    assert remaining["hooks"]["PreToolUse"] == [
        {"hooks": [{"type": "command", "command": lookalike, "timeout": 10}]},
        {"hooks": [{"type": "command", "command": "user-command", "timeout": 10}]},
    ]
    assert "PostToolUse" not in remaining["hooks"]
    assert "PostToolUseFailure" not in remaining["hooks"]


def test_uninstall_preserves_user_config_and_removes_fully_managed_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    user = prepare_fixture(
        monkeypatch,
        tmp_path / "user",
        existing_config={"owner": "user", "hooks": {"Notification": []}},
    )
    user.install()
    user.plugin.uninstall(AGENT_ID)
    assert user.settings() == {
        "owner": "user",
        "hooks": {"Notification": []},
    }

    managed = prepare_fixture(monkeypatch, tmp_path / "managed")
    managed.install()
    managed.plugin.uninstall(AGENT_ID)
    assert not managed.config_path.exists()


def test_status_requires_one_complete_triple_identity_and_private_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    assert fixture.plugin.status()["installed"] is True

    settings = fixture.settings()
    del settings["hooks"]["PostToolUseFailure"]
    fixture.config_path.write_text(json.dumps(settings), encoding="utf-8")
    assert fixture.plugin.status()["installed"] is False

    fixture.install()
    settings = fixture.settings()
    settings["hooks"]["PostToolUseFailure"].append(
        settings["hooks"]["PostToolUseFailure"][-1]
    )
    fixture.config_path.write_text(json.dumps(settings), encoding="utf-8")
    assert fixture.plugin.status()["installed"] is False

    fixture.install()
    fixture.private_key_path.write_text("invalid", encoding="utf-8")
    with pytest.raises(ValueError, match="private key.*canonical 32-byte"):
        fixture.plugin.status()


@pytest.mark.parametrize(
    "runtime_name", ["guard.py", "hook.py", "config.json", "private.key"]
)
def test_status_requires_every_runtime_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, runtime_name: str
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    (fixture.agent_dir / runtime_name).unlink()

    assert fixture.plugin.status()["installed"] is False


def test_installation_leaves_no_transaction_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()

    assert_no_transaction_files(fixture.home_dir)
    if os.name != "nt":
        for path in (
            fixture.config_path,
            fixture.runtime_config_path,
            fixture.private_key_path,
        ):
            assert path.stat().st_mode & 0o777 == 0o600
