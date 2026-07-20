from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from elydora import cli
from elydora.plugins import letta
from elydora.plugins.registry import SUPPORTED_AGENTS
from letta_support import (
    AGENT_ID,
    VALID_PRIVATE_KEY,
    assert_managed_triple,
    legacy_group,
    prepare_fixture,
    run_cli,
    write_json,
    write_text,
)


def test_letta_is_registered_in_the_sdk_and_cli() -> None:
    assert SUPPORTED_AGENTS["letta"] == {
        "name": "Letta Code",
        "hook_event": "PreToolUse/PostToolUse/PostToolUseFailure",
        "config_path": "~/.letta/settings.json",
    }
    assert cli.PLUGIN_MAP["letta"] is letta.LettaPlugin


def test_install_preserves_every_source_and_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    global_source = (
        "{\r\n"
        '  "theme": "dark",\r\n'
        '  "hooks": {\r\n'
        '    "FutureEvent": [null],\r\n'
        '    "PreToolUse": [{ "matcher": "Bash", "hooks": '
        '[{ "type": "command", "command": "user-hook", "quiet": true }] }]\r\n'
        "  }\r\n"
        "}\r\n"
    )
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        global_settings=global_source,
        project_settings={"owner": "project"},
        local_settings={"owner": "local"},
    )
    project_before = fixture.source(fixture.project_path)
    local_before = fixture.source(fixture.local_path)

    fixture.install()
    first_source = fixture.source()
    settings = fixture.settings()
    assert "\r\n" in first_source
    assert settings["theme"] == "dark"
    assert settings["hooks"]["FutureEvent"] == [None]
    assert settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "user-hook"
    assert_managed_triple(settings)
    assert fixture.source(fixture.project_path) == project_before
    assert fixture.source(fixture.local_path) == local_before
    for file_path in (
        fixture.guard_path,
        fixture.audit_path,
        fixture.runtime_config_path,
        fixture.private_key_path,
    ):
        assert file_path.is_file()

    fixture.install()
    assert fixture.source() == first_source
    output = capsys.readouterr().out
    assert "run /hooks" in output
    assert "restart active sessions" in output


def test_letta_validates_known_schemas_and_preserves_future_events(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, global_settings={
        "hooks": {
            "FutureEvent": [None],
            "PreToolUse": [{
                "matcher": "[",
                "hooks": [{
                    "type": "command",
                    "command": "user-command",
                    "timeout": 0,
                    "quiet": False,
                    "futureField": True,
                }],
            }],
            "Stop": [{
                "hooks": [{
                    "type": "prompt",
                    "prompt": "Evaluate $ARGUMENTS",
                    "model": "fast",
                    "timeout": 30,
                }],
            }],
        },
    })
    fixture.install()
    settings = fixture.settings()
    assert settings["hooks"]["FutureEvent"] == [None]
    assert settings["hooks"]["PreToolUse"][0]["matcher"] == "["
    assert settings["hooks"]["PreToolUse"][0]["hooks"][0]["futureField"] is True
    assert settings["hooks"]["Stop"][0]["hooks"][0]["type"] == "prompt"


@pytest.mark.parametrize(
    "source",
    [
        "{ malformed",
        "[]",
        '{ "theme": true, }',
        '{ "theme": true // comment\n }',
        '{ "hooks": {}, "hooks": {} }',
        '{ "hooks": null }',
        '{ "hooks": [] }',
        '{ "hooks": { "disabled": "yes" } }',
        '{ "hooks": { "PreToolUse": null } }',
        '{ "hooks": { "PreToolUse": [null] } }',
        '{ "hooks": { "PreToolUse": [{ "hooks": [] }] } }',
        '{ "hooks": { "Stop": [{ "matcher": "*", "hooks": [] }] } }',
        '{ "hooks": { "PreToolUse": [{ "matcher": "*" }] } }',
        '{ "hooks": { "Stop": [{ "hooks": [null] }] } }',
        '{ "hooks": { "Stop": [{ "hooks": [{ "type": "http" }] }] } }',
        '{ "hooks": { "PreToolUse": [{ "matcher": "*", "hooks": [{ "type": "command" }] }] } }',
        '{ "hooks": { "Stop": [{ "hooks": [{ "type": "prompt" }] }] } }',
        '{ "hooks": { "Stop": [{ "hooks": [{ "type": "prompt", "prompt": "x", "model": 1 }] }] } }',
        '{ "hooks": { "Stop": [{ "hooks": [{ "type": "command", "command": "x", "quiet": 1 }] }] } }',
        '{ "hooks": { "Stop": [{ "hooks": [{ "type": "command", "command": "x", "timeout": -1 }] }] } }',
    ],
)
def test_install_rejects_malformed_global_settings_before_every_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, source: str
) -> None:
    fixture = prepare_fixture(
        monkeypatch, tmp_path, global_settings=source
    )
    with pytest.raises((OSError, ValueError), match="Letta Code"):
        fixture.install()
    assert fixture.source() == source
    assert not fixture.agent_dir.exists()


@pytest.mark.parametrize("kind", ["project", "local"])
def test_install_surfaces_malformed_read_only_sources(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, kind: str
) -> None:
    options = (
        {"project_settings": "{ malformed"}
        if kind == "project"
        else {"local_settings": "{ malformed"}
    )
    fixture = prepare_fixture(monkeypatch, tmp_path, **options)
    label = "project-local" if kind == "local" else kind
    with pytest.raises(ValueError, match=f"Letta Code {label}"):
        fixture.install()
    assert not fixture.global_path.exists()
    assert not fixture.agent_dir.exists()


@pytest.mark.parametrize(
    ("global_settings", "project_settings", "local_settings", "enabled"),
    [
        ({"hooks": {"disabled": True}}, {}, {}, False),
        ({}, {"hooks": {"disabled": True}}, {}, False),
        ({}, {}, {"hooks": {"disabled": True}}, False),
        (
            {"hooks": {"disabled": False}},
            {"hooks": {"disabled": True}},
            {"hooks": {"disabled": True}},
            True,
        ),
    ],
)
def test_hooks_disabled_uses_official_precedence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    global_settings: object,
    project_settings: object,
    local_settings: object,
    enabled: bool,
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        global_settings=global_settings,
        project_settings=project_settings,
        local_settings=local_settings,
    )
    if enabled:
        fixture.install()
        assert_managed_triple(fixture.settings())
    else:
        with pytest.raises(ValueError, match="hooks.disabled"):
            fixture.install()
        assert not fixture.agent_dir.exists()


def test_install_migrates_exact_legacy_and_preserves_lookalikes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    guard_legacy = legacy_group(fixture.guard_path, "PreToolUse")
    guard_lookalike = legacy_group(fixture.guard_path, "PreToolUse")
    guard_lookalike["hooks"][0]["quiet"] = True
    audit_legacy = legacy_group(fixture.audit_path, "PostToolUse")
    write_json(fixture.global_path, {
        "owner": "user",
        "hooks": {
            "PreToolUse": [guard_legacy, guard_lookalike],
            "PostToolUse": [audit_legacy],
        },
    })
    fixture.install()
    settings = fixture.settings()
    assert_managed_triple(settings)
    assert any(
        group["hooks"][0].get("quiet") is True
        for group in settings["hooks"]["PreToolUse"]
    )
    managed = next(
        group for group in settings["hooks"]["PreToolUse"]
        if group["hooks"][0].get("timeout") == 10_000
    )
    managed["userField"] = "preserve-group"
    managed["hooks"].append({"type": "command", "command": "user-command"})
    write_json(fixture.global_path, settings)

    fixture.plugin.uninstall(AGENT_ID)
    remaining = fixture.settings()
    assert remaining["owner"] == "user"
    assert any(
        group["hooks"][0].get("quiet") is True
        for group in remaining["hooks"]["PreToolUse"]
    )
    assert any(
        handler.get("command") == "user-command"
        for group in remaining["hooks"]["PreToolUse"]
        for handler in group["hooks"]
    )
    assert "PostToolUse" not in remaining["hooks"]
    assert "PostToolUseFailure" not in remaining["hooks"]


def test_uninstall_removes_owned_file_and_preserves_user_settings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    user = prepare_fixture(
        monkeypatch,
        tmp_path / "user",
        global_settings={"theme": "dark", "hooks": {"Notification": []}},
    )
    user.install()
    user.plugin.uninstall(AGENT_ID)
    assert user.settings() == {
        "theme": "dark",
        "hooks": {"Notification": []},
    }

    owned = prepare_fixture(monkeypatch, tmp_path / "owned")
    owned.install()
    owned.plugin.uninstall(AGENT_ID)
    assert not owned.global_path.exists()


def test_status_requires_effective_contract_and_strict_runtime_identity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, project_settings={})
    fixture.install()
    assert fixture.plugin.status()["installed"] is True
    write_json(fixture.project_path, {"hooks": {"disabled": True}})
    assert fixture.plugin.status()["installed"] is False
    write_json(fixture.project_path, {})
    settings = fixture.settings()
    settings["hooks"]["PostToolUseFailure"].append(
        settings["hooks"]["PostToolUseFailure"][-1]
    )
    write_json(fixture.global_path, settings)
    assert fixture.plugin.status()["installed"] is False

    fixture.install()
    write_text(fixture.private_key_path, "invalid")
    with pytest.raises(ValueError, match="private key"):
        fixture.plugin.status()
    fixture.install()
    write_text(fixture.audit_path, "tampered")
    assert fixture.plugin.status()["installed"] is False
    fixture.install()
    runtime = json.loads(fixture.runtime_config_path.read_text())
    runtime["agent_name"] = "other"
    write_json(fixture.runtime_config_path, runtime)
    with pytest.raises(ValueError, match="runtime identity"):
        fixture.plugin.status()


def test_preflight_rejects_unverifiable_runtime_and_invalid_agent_id(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    identity = prepare_fixture(monkeypatch, tmp_path / "identity")
    write_text(identity.audit_path, "unverified")
    with pytest.raises(ValueError, match="without config.json"):
        identity.install()
    assert not identity.global_path.exists()

    invalid = prepare_fixture(monkeypatch, tmp_path / "invalid")
    invalid.config["agent_id"] = "../escape"
    with pytest.raises(ValueError, match="Invalid agent ID"):
        invalid.install()
    assert not invalid.global_path.exists()


def test_letta_cli_install_status_and_uninstall_end_to_end(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(
        monkeypatch, tmp_path, global_settings={"theme": "dark"}
    )
    key_file = tmp_path / "install-private.key"
    token_file = tmp_path / "install-token.txt"
    write_text(key_file, VALID_PRIVATE_KEY + "\n")
    write_text(token_file, "token-1\n")
    install = run_cli(fixture, [
        "install",
        "--agent", "letta",
        "--org_id", "org-1",
        "--agent_id", AGENT_ID,
        "--kid", "kid-1",
        "--private_key_file", str(key_file),
        "--token_file", str(token_file),
        "--base_url", "http://127.0.0.1:9",
    ])
    assert install.returncode == 0, install.stderr
    assert_managed_triple(fixture.settings())
    status = run_cli(fixture, ["status"])
    assert status.returncode == 0, status.stderr
    assert "Letta Code" in status.stdout and "[installed]" in status.stdout
    uninstall = run_cli(fixture, [
        "uninstall", "--agent", "letta", "--agent_id", AGENT_ID
    ])
    assert uninstall.returncode == 0, uninstall.stderr
    assert fixture.settings() == {"theme": "dark"}
    assert not fixture.agent_dir.exists()


@pytest.mark.skipif(
    os.name != "nt", reason="Windows resolves HOME and USERPROFILE separately"
)
def test_windows_cli_separates_letta_home_from_runtime_home(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(
        monkeypatch, tmp_path, global_settings={"theme": "dark"}
    )
    runtime_home = tmp_path / "windows profile"
    runtime_agent_dir = runtime_home / ".elydora" / AGENT_ID
    monkeypatch.setenv("USERPROFILE", str(runtime_home))
    key_file = tmp_path / "install-private.key"
    write_text(key_file, VALID_PRIVATE_KEY + "\n")

    install = run_cli(fixture, [
        "install",
        "--agent", "letta",
        "--org_id", "org-1",
        "--agent_id", AGENT_ID,
        "--kid", "kid-1",
        "--private_key_file", str(key_file),
        "--base_url", "http://127.0.0.1:9",
    ])
    assert install.returncode == 0, install.stderr
    assert_managed_triple(fixture.settings())
    assert (runtime_agent_dir / "guard.py").is_file()
    assert (runtime_agent_dir / "hook.py").is_file()

    status = run_cli(fixture, ["status"])
    assert status.returncode == 0, status.stderr
    assert "Letta Code" in status.stdout and "[installed]" in status.stdout

    uninstall = run_cli(fixture, [
        "uninstall", "--agent", "letta", "--agent_id", AGENT_ID
    ])
    assert uninstall.returncode == 0, uninstall.stderr
    assert fixture.settings() == {"theme": "dark"}
    assert not runtime_agent_dir.exists()
