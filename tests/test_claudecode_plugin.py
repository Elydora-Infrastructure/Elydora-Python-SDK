from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess  # nosec B404
import sys

import pytest

from claudecode_support import (
    AGENT_ID,
    MISSING,
    VALID_PRIVATE_KEY,
    assert_native_handler,
    legacy_handler,
    managed_handler,
    prepare_fixture,
    write_json,
    write_text,
)
from elydora.plugins.claudecode_contract import AUDIT_STATUS, GUARD_STATUS
from elydora.plugins.registry import SUPPORTED_AGENTS


def assert_managed_triple(settings: dict, fixture: object) -> None:
    assert_native_handler(
        managed_handler(settings, "PreToolUse"),
        fixture.guard_path,
        GUARD_STATUS,
    )
    assert_native_handler(
        managed_handler(settings, "PostToolUse"),
        fixture.hook_path,
        AUDIT_STATUS,
    )
    assert_native_handler(
        managed_handler(settings, "PostToolUseFailure"),
        fixture.hook_path,
        AUDIT_STATUS,
    )


def test_claude_code_is_registered_with_the_official_contract() -> None:
    assert SUPPORTED_AGENTS["claudecode"] == {
        "name": "Claude Code",
        "hook_event": "PreToolUse/PostToolUse/PostToolUseFailure",
        "config_path": "$CLAUDE_CONFIG_DIR/settings.json",
    }


def test_install_preserves_settings_and_writes_one_exact_triple(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    existing = {
        "$schema": "https://json.schemastore.org/claude-code-settings.json",
        "model": "sonnet",
        "disableAllHooks": False,
        "hooks": {
            "Notification": [{
                "matcher": "permission_prompt",
                "hooks": [{
                    "type": "http",
                    "url": "https://example.test/hook",
                    "timeout": 1,
                }],
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
        monkeypatch, tmp_path, existing_settings=existing
    )

    fixture.install()
    output = capsys.readouterr().out
    assert "run /hooks and claude doctor" in output
    installed = fixture.settings()
    assert installed["model"] == "sonnet"
    assert installed["hooks"]["Notification"] == existing["hooks"]["Notification"]
    assert installed["hooks"]["PreToolUse"][0] == existing["hooks"]["PreToolUse"][0]
    assert_managed_triple(installed, fixture)
    first_source = fixture.config_path.read_text(encoding="utf-8")

    fixture.install()

    assert fixture.config_path.read_text(encoding="utf-8") == first_source


@pytest.mark.parametrize(
    ("config_override", "expected_kind"),
    [
        (None, "custom"),
        (MISSING, "default"),
        ("relative claude", "relative"),
        ("", "cwd"),
        ("~", "literal_tilde"),
    ],
)
def test_claude_config_dir_matches_native_path_resolution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    config_override: object,
    expected_kind: str,
) -> None:
    fixture = prepare_fixture(
        monkeypatch, tmp_path, config_override=config_override
    )

    fixture.install()

    expected = {
        "custom": fixture.home_dir / "custom claude" / "settings.json",
        "default": fixture.home_dir / ".claude" / "settings.json",
        "relative": fixture.project_dir / "relative claude" / "settings.json",
        "cwd": fixture.project_dir / "settings.json",
        "literal_tilde": fixture.project_dir / "~" / "settings.json",
    }[expected_kind]
    assert fixture.config_path == expected
    assert expected.is_file()


def test_malformed_settings_fail_before_runtime_creation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(
        monkeypatch, tmp_path, existing_settings="{ malformed"
    )

    with pytest.raises(ValueError, match="parse Claude Code user settings"):
        fixture.install()

    assert fixture.config_path.read_text(encoding="utf-8") == "{ malformed"
    assert not fixture.agent_dir.exists()


def test_documented_handler_types_and_fields_are_preserved(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    user_hooks = {
        "SessionStart": [{"hooks": [{
            "type": "prompt",
            "prompt": "Review context",
            "model": "haiku",
            "continueOnBlock": True,
            "if": "always",
            "once": False,
            "statusMessage": "Reviewing",
            "timeout": 0.5,
        }]}],
        "PreToolUse": [{"matcher": "Bash", "hooks": [{
            "type": "command",
            "command": "user-command",
            "args": ["--safe"],
            "async": False,
            "asyncRewake": True,
            "shell": "powershell",
        }]}],
        "Stop": [{"hooks": [{
            "type": "agent", "prompt": "Verify completion", "model": "sonnet",
        }]}],
        "Notification": [{"hooks": [{
            "type": "http",
            "url": "https://example.test/hook",
            "headers": {"Authorization": "Bearer ${TOKEN}"},
            "allowedEnvVars": ["TOKEN"],
        }]}],
        "PostToolUse": [{"hooks": [{
            "type": "mcp_tool",
            "server": "audit",
            "tool": "record",
            "input": {"source": "claude"},
        }]}],
    }
    fixture = prepare_fixture(
        monkeypatch, tmp_path, existing_settings={"hooks": user_hooks}
    )

    fixture.install()

    installed = fixture.settings()["hooks"]
    for event, groups in user_hooks.items():
        assert installed[event][0] == groups[0]


INVALID_SETTINGS = [
    ('{"hooks":{},"hooks":{}}', 'duplicate field "hooks"'),
    (json.dumps({"disableAllHooks": "yes"}), "must be a boolean"),
    (json.dumps({"hooks": None}), 'field "hooks" must be an object'),
    (json.dumps({"hooks": {"MadeUp": []}}), "unsupported hook event"),
    (json.dumps({"hooks": {"PreToolUse": None}}), "must be an array"),
    (json.dumps({"hooks": {"PreToolUse": [None]}}), "must be an object"),
    (
        json.dumps({"hooks": {"PreToolUse": [{"hooks": [], "label": "x"}]}}),
        'unsupported field "label"',
    ),
    (
        json.dumps({"hooks": {"PreToolUse": [{"matcher": 1, "hooks": []}]}}),
        "matcher must be a string",
    ),
    (json.dumps({"hooks": {"PreToolUse": [{}]}}), "hooks array"),
    (
        json.dumps({"hooks": {"PreToolUse": [{"hooks": [None]}]}}),
        "handler",
    ),
    (
        json.dumps({"hooks": {"PreToolUse": [{"hooks": [{"type": "file"}]}]}}),
        "unsupported type",
    ),
    (
        json.dumps({"hooks": {"PreToolUse": [{"hooks": [{
            "type": "command", "command": "x", "invented": True,
        }]}]}}),
        'unsupported field "invented"',
    ),
    (
        json.dumps({"hooks": {"PreToolUse": [{"hooks": [{
            "type": "command", "command": "",
        }]}]}}),
        "non-empty string",
    ),
    (
        json.dumps({"hooks": {"PreToolUse": [{"hooks": [{
            "type": "command", "command": "x", "args": [1],
        }]}]}}),
        "array of strings",
    ),
    (
        json.dumps({"hooks": {"PreToolUse": [{"hooks": [{
            "type": "command", "command": "x", "timeout": 0,
        }]}]}}),
        "positive finite number",
    ),
    (
        json.dumps({"hooks": {"PreToolUse": [{"hooks": [{
            "type": "http", "url": "https://example.test", "headers": {"A": 1},
        }]}]}}),
        "map names to strings",
    ),
    (
        json.dumps({"hooks": {"PreToolUse": [{"hooks": [{
            "type": "mcp_tool", "server": "s", "tool": "t", "input": [],
        }]}]}}),
        "must be an object",
    ),
]


@pytest.mark.parametrize(("source", "pattern"), INVALID_SETTINGS)
def test_invalid_official_hook_shapes_fail_before_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    source: str,
    pattern: str,
) -> None:
    fixture = prepare_fixture(
        monkeypatch, tmp_path, existing_settings=source
    )

    with pytest.raises(ValueError, match=pattern):
        fixture.install()

    assert fixture.config_path.read_text(encoding="utf-8") == source
    assert not fixture.agent_dir.exists()


def test_disabled_user_hooks_block_installation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(
        monkeypatch, tmp_path, existing_settings={"disableAllHooks": True}
    )

    with pytest.raises(ValueError, match="disabled by disableAllHooks"):
        fixture.install()

    assert not fixture.agent_dir.exists()
    assert fixture.settings() == {"disableAllHooks": True}


def test_exact_legacy_hooks_migrate_and_lookalikes_survive_uninstall(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    lookalike = legacy_handler(fixture.guard_path)
    lookalike["command"] += " --inspect"
    write_json(fixture.config_path, {
        "hooks": {
            "PreToolUse": [
                {"hooks": [legacy_handler(fixture.guard_path)]},
                {"hooks": [lookalike]},
            ],
            "PostToolUse": [{"hooks": [legacy_handler(fixture.hook_path)]}],
        }
    })

    fixture.install()
    settings = fixture.settings()
    assert_managed_triple(settings, fixture)
    assert any(
        group["hooks"][0].get("command") == lookalike["command"]
        for group in settings["hooks"]["PreToolUse"]
    )
    settings["hooks"]["PreToolUse"][-1]["hooks"].append({
        "type": "command", "command": "user-command", "timeout": 5,
    })
    write_json(fixture.config_path, settings)

    fixture.plugin.uninstall(AGENT_ID)

    remaining = fixture.settings()["hooks"]
    assert remaining["PreToolUse"] == [
        {"hooks": [lookalike]},
        {"hooks": [{"type": "command", "command": "user-command", "timeout": 5}]},
    ]
    assert "PostToolUse" not in remaining
    assert "PostToolUseFailure" not in remaining


def test_uninstall_preserves_user_settings_and_removes_managed_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    user = prepare_fixture(
        monkeypatch,
        tmp_path / "user",
        existing_settings={"model": "sonnet", "hooks": {"Notification": []}},
    )
    user.install()
    user.plugin.uninstall(AGENT_ID)
    assert user.settings() == {
        "model": "sonnet", "hooks": {"Notification": []},
    }

    managed = prepare_fixture(monkeypatch, tmp_path / "managed")
    managed.install()
    managed.plugin.uninstall(AGENT_ID)
    assert not managed.config_path.exists()


def test_status_requires_enabled_unique_triple_and_strict_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    assert fixture.plugin.status()["installed"] is True

    settings = fixture.settings()
    del settings["hooks"]["PostToolUseFailure"]
    write_json(fixture.config_path, settings)
    assert fixture.plugin.status()["installed"] is False

    fixture.install()
    settings = fixture.settings()
    settings["hooks"]["PostToolUseFailure"].append(
        settings["hooks"]["PostToolUseFailure"][-1]
    )
    write_json(fixture.config_path, settings)
    assert fixture.plugin.status()["installed"] is False

    fixture.install()
    settings = fixture.settings()
    settings["disableAllHooks"] = True
    write_json(fixture.config_path, settings)
    assert fixture.plugin.status()["installed"] is False

    settings["disableAllHooks"] = False
    write_json(fixture.config_path, settings)
    write_text(fixture.private_key_path, "invalid")
    with pytest.raises(ValueError, match="canonical 32-byte"):
        fixture.plugin.status()


def test_project_and_local_settings_remain_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    project_settings = fixture.project_dir / ".claude" / "settings.json"
    local_settings = fixture.project_dir / ".claude" / "settings.local.json"
    project_source = '{"hooks":{"PreToolUse":[]}}\n'
    local_source = '{"model":"haiku"}\n'
    write_text(project_settings, project_source)
    write_text(local_settings, local_source)

    fixture.install()

    assert project_settings.read_text(encoding="utf-8") == project_source
    assert local_settings.read_text(encoding="utf-8") == local_source


def test_cli_install_status_and_uninstall_end_to_end(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    key_path = tmp_path / "install-private.key"
    token_path = tmp_path / "install-token.txt"
    write_text(key_path, VALID_PRIVATE_KEY + "\n")
    write_text(token_path, "token-1\n")
    environment = {
        **os.environ,
        "HOME": str(fixture.home_dir),
        "USERPROFILE": str(fixture.home_dir),
        "CLAUDE_CONFIG_DIR": str(fixture.config_path.parent),
    }
    root = Path(__file__).parents[1]
    base = [sys.executable, "-m", "elydora.cli"]

    install = subprocess.run(
        [
            *base, "install", "--agent", "claudecode",
            "--org_id", "org-1", "--agent_id", AGENT_ID,
            "--private_key_file", str(key_path), "--token_file", str(token_path),
            "--kid", "key-1", "--base_url", "http://127.0.0.1:9",
        ],
        capture_output=True,
        check=False,
        cwd=root,
        env=environment,
        text=True,
    )
    assert install.returncode == 0, install.stderr
    assert "PostToolUseFailure hooks installed" in install.stdout
    assert_managed_triple(fixture.settings(), fixture)

    status = subprocess.run(
        [*base, "status"], capture_output=True, check=False,
        cwd=root, env=environment, text=True,
    )
    assert status.returncode == 0, status.stderr
    assert "Claude Code" in status.stdout
    assert "[installed]" in status.stdout

    uninstall = subprocess.run(
        [*base, "uninstall", "--agent", "claudecode", "--agent_id", AGENT_ID],
        capture_output=True,
        check=False,
        cwd=root,
        env=environment,
        text=True,
    )
    assert uninstall.returncode == 0, uninstall.stderr
    assert not fixture.config_path.exists()
    assert not fixture.agent_dir.exists()
