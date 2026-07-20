from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess  # nosec B404
import sys

import pytest

from gemini_support import (
    AGENT_ID,
    MISSING,
    VALID_PRIVATE_KEY,
    assert_managed_handler,
    legacy_handler,
    managed_handler,
    prepare_fixture,
    write_json,
    write_text,
)
from elydora.plugins.registry import SUPPORTED_AGENTS


GUARD_NAME = "elydora-guard"
AUDIT_NAME = "elydora-audit"


def assert_managed_pair(settings: dict, fixture: object) -> None:
    guard = managed_handler(settings, "BeforeTool", GUARD_NAME)
    audit = managed_handler(settings, "AfterTool", AUDIT_NAME)
    assert_managed_handler(guard, GUARD_NAME)
    assert_managed_handler(audit, AUDIT_NAME)
    assert str(fixture.guard_path) not in ("", guard["command"])
    assert str(fixture.hook_path) not in ("", audit["command"])


def test_gemini_is_registered_with_the_official_contract() -> None:
    assert SUPPORTED_AGENTS["gemini"] == {
        "name": "Gemini CLI",
        "hook_event": "BeforeTool/AfterTool",
        "config_path": "$GEMINI_CLI_HOME/.gemini/settings.json",
    }


def test_install_preserves_jsonc_and_writes_one_exact_pair(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    existing = "\r\n".join([
        "{",
        "  // Keep this user preference.",
        '  "theme": "GitHub",',
        '  "hooks": {',
        '    "FutureEvent": [null],',
        '    "BeforeTool": [{ "matcher": "read_file", "hooks": '
        '[{ "type": "command", "command": "user-hook" }] }]',
        "  }",
        "}",
        "",
    ])
    fixture = prepare_fixture(
        monkeypatch, tmp_path, existing_settings=existing
    )
    project_settings = fixture.project_dir / ".gemini" / "settings.json"
    system_settings = tmp_path / "system-settings.json"
    write_text(project_settings, '{ "owner": "project" }\n')
    write_text(system_settings, '{ "owner": "system" }\n')
    monkeypatch.setenv("GEMINI_CLI_SYSTEM_SETTINGS_PATH", str(system_settings))

    fixture.install()
    output = capsys.readouterr().out
    assert "run /hooks list" in output
    installed = fixture.settings()
    assert "Keep this user preference" in fixture.source()
    assert "\r\n" in fixture.source()
    assert installed["theme"] == "GitHub"
    assert installed["hooks"]["FutureEvent"] == [None]
    assert installed["hooks"]["BeforeTool"][0]["hooks"][0]["command"] == "user-hook"
    assert_managed_pair(installed, fixture)
    first_source = fixture.source()

    fixture.install()

    assert fixture.source() == first_source
    assert project_settings.read_text(encoding="utf-8") == '{ "owner": "project" }\n'
    assert system_settings.read_text(encoding="utf-8") == '{ "owner": "system" }\n'


@pytest.mark.parametrize(
    ("override", "kind"),
    [
        (MISSING, "default"),
        ("", "empty"),
        ("relative gemini", "relative"),
        ("~", "literal_tilde"),
    ],
)
def test_gemini_home_matches_official_path_resolution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    override: object,
    kind: str,
) -> None:
    fixture = prepare_fixture(
        monkeypatch, tmp_path, gemini_home_override=override
    )

    fixture.install()

    expected = {
        "default": fixture.home_dir / ".gemini" / "settings.json",
        "empty": fixture.home_dir / ".gemini" / "settings.json",
        "relative": fixture.project_dir / "relative gemini" / ".gemini" / "settings.json",
        "literal_tilde": fixture.project_dir / "~" / ".gemini" / "settings.json",
    }[kind]
    assert fixture.config_path == expected
    assert expected.is_file()


INVALID_SETTINGS = [
    ("{ malformed", "parse Gemini CLI user settings"),
    ("[]", "must contain a JSON object"),
    ('{ "theme": true, }', "trailing commas are not allowed"),
    ('{ "hooks": {}, "hooks": {} }', 'duplicate field "hooks"'),
    ('{ "hooks": null }', 'field "hooks" must be an object'),
    ('{ "hooks": { "BeforeTool": null } }', "must be an array"),
    ('{ "hooks": { "BeforeTool": [null] } }', "group.*must be an object"),
    (
        '{ "hooks": { "BeforeTool": [{ "matcher": 1, "hooks": [] }] } }',
        "matcher must be a string",
    ),
    (
        '{ "hooks": { "BeforeTool": [{ "sequential": 1, "hooks": [] }] } }',
        "sequential must be a boolean",
    ),
    ('{ "hooks": { "BeforeTool": [{}] } }', "hooks array"),
    ('{ "hooks": { "BeforeTool": [{ "hooks": [null] }] } }', "handler"),
    (
        '{ "hooks": { "BeforeTool": [{ "hooks": [{ "type": "http" }] }] } }',
        "unsupported type",
    ),
    (
        '{ "hooks": { "BeforeTool": [{ "hooks": [{ "type": "command", '
        '"command": "" }] }] } }',
        "non-empty command",
    ),
    (
        '{ "hooks": { "BeforeTool": [{ "hooks": [{ "type": "command", '
        '"command": "x", "timeout": -1 }] }] } }',
        "non-negative finite number",
    ),
    (
        '{ "hooks": { "BeforeTool": [{ "hooks": [{ "type": "command", '
        '"command": "x", "env": { "A": 1 } }] }] } }',
        "env must map names to strings",
    ),
    ('{ "hooksConfig": null }', "hooksConfig.*must be an object"),
    ('{ "hooksConfig": { "future": true } }', 'unsupported field "future"'),
    ('{ "hooksConfig": { "enabled": "yes" } }', "enabled.*must be a boolean"),
    ('{ "hooksConfig": { "disabled": [1] } }', "array of strings"),
    ('{ "hooksConfig": { "notifications": 1 } }', "notifications.*boolean"),
]


@pytest.mark.parametrize(("source", "pattern"), INVALID_SETTINGS)
def test_invalid_official_settings_fail_before_every_write(
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

    assert fixture.source() == source
    assert not fixture.agent_dir.exists()


@pytest.mark.parametrize(
    ("settings", "pattern"),
    [
        ({"hooksConfig": {"enabled": False}}, "hooksConfig.enabled"),
        ({"hooksConfig": {"disabled": [GUARD_NAME]}}, GUARD_NAME),
        ({"hooksConfig": {"disabled": [AUDIT_NAME]}}, AUDIT_NAME),
    ],
)
def test_canonical_hook_controls_block_installation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    settings: dict,
    pattern: str,
) -> None:
    fixture = prepare_fixture(
        monkeypatch, tmp_path, existing_settings=settings
    )
    with pytest.raises(ValueError, match=pattern):
        fixture.install()
    assert not fixture.agent_dir.exists()


def test_disabled_legacy_command_blocks_installation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    write_json(fixture.config_path, {
        "hooksConfig": {
            "disabled": [legacy_handler(fixture.guard_path)["command"]]
        }
    })

    with pytest.raises(ValueError, match="hooksConfig.disabled"):
        fixture.install()

    assert not fixture.agent_dir.exists()


def test_exact_legacy_hooks_migrate_and_lookalikes_survive_uninstall(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    lookalike = legacy_handler(fixture.guard_path)
    lookalike["command"] += " --inspect"
    write_json(fixture.config_path, {
        "hooks": {
            "BeforeTool": [
                {"hooks": [legacy_handler(fixture.guard_path)]},
                {"hooks": [lookalike]},
            ],
            "AfterTool": [{"hooks": [legacy_handler(fixture.hook_path)]}],
        }
    })

    fixture.install()
    settings = fixture.settings()
    assert_managed_pair(settings, fixture)
    assert any(
        group["hooks"][0].get("command") == lookalike["command"]
        for group in settings["hooks"]["BeforeTool"]
    )
    settings["hooks"]["BeforeTool"][-1]["hooks"].append({
        "type": "command", "command": "user-command"
    })
    write_json(fixture.config_path, settings)

    fixture.plugin.uninstall(AGENT_ID)

    remaining = fixture.settings()["hooks"]
    assert remaining["BeforeTool"] == [
        {"hooks": [lookalike]},
        {"hooks": [{"type": "command", "command": "user-command"}]},
    ]
    assert "AfterTool" not in remaining


def test_uninstall_preserves_user_settings_and_removes_owned_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    user = prepare_fixture(
        monkeypatch,
        tmp_path / "user",
        existing_settings={"theme": "GitHub", "hooks": {"Notification": []}},
    )
    user.install()
    user.plugin.uninstall(AGENT_ID)
    assert user.settings() == {
        "theme": "GitHub", "hooks": {"Notification": []}
    }

    owned = prepare_fixture(monkeypatch, tmp_path / "owned")
    owned.install()
    owned.plugin.uninstall(AGENT_ID)
    assert not owned.config_path.exists()


def test_status_requires_enabled_unique_pair_and_strict_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    assert fixture.plugin.status()["installed"] is True

    settings = fixture.settings()
    settings["hooks"]["AfterTool"].append(settings["hooks"]["AfterTool"][-1])
    write_json(fixture.config_path, settings)
    assert fixture.plugin.status()["installed"] is False

    fixture.install()
    settings = fixture.settings()
    settings["hooksConfig"] = {"disabled": [AUDIT_NAME]}
    write_json(fixture.config_path, settings)
    assert fixture.plugin.status()["installed"] is False

    settings["hooksConfig"] = {"disabled": []}
    write_json(fixture.config_path, settings)
    write_text(fixture.private_key_path, "invalid")
    with pytest.raises(ValueError, match="canonical 32-byte"):
        fixture.plugin.status()


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
        "GEMINI_CLI_HOME": str(fixture.home_dir),
    }
    root = Path(__file__).parents[1]
    base = [sys.executable, "-m", "elydora.cli"]

    install = subprocess.run(  # nosec B603
        [
            *base, "install", "--agent", "gemini",
            "--org_id", "org-1", "--agent_id", AGENT_ID,
            "--private_key_file", str(key_path),
            "--token_file", str(token_path),
            "--kid", "key-1", "--base_url", "http://127.0.0.1:9",
        ],
        capture_output=True,
        check=False,
        cwd=root,
        env=environment,
        text=True,
    )
    assert install.returncode == 0, install.stderr
    assert "run /hooks list" in install.stdout
    assert_managed_pair(fixture.settings(), fixture)

    status = subprocess.run(  # nosec B603
        [*base, "status"],
        capture_output=True,
        check=False,
        cwd=root,
        env=environment,
        text=True,
    )
    assert status.returncode == 0, status.stderr
    assert "Gemini CLI" in status.stdout
    assert "[installed]" in status.stdout

    uninstall = subprocess.run(  # nosec B603
        [*base, "uninstall", "--agent", "gemini", "--agent_id", AGENT_ID],
        capture_output=True,
        check=False,
        cwd=root,
        env=environment,
        text=True,
    )
    assert uninstall.returncode == 0, uninstall.stderr
    assert not fixture.config_path.exists()
    assert not fixture.agent_dir.exists()
