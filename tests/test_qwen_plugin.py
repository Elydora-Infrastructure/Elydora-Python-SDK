from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from elydora import cli
from elydora.plugins import _transaction, qwen
from elydora.plugins.qwen_config import render_qwen_document
from elydora.plugins.qwen_contract import (
    AUDIT_HOOK_NAME,
    GUARD_HOOK_NAME,
    build_qwen_group,
)
from elydora.plugins.qwen_installation import (
    commit_qwen_installation,
    preflight_qwen_installation,
    prepare_qwen_installation,
)
from elydora.plugins.qwen_sources import read_qwen_sources
from elydora.plugins.registry import SUPPORTED_AGENTS
from qwen_support import (
    AGENT_ID,
    VALID_PRIVATE_KEY,
    assert_managed_triple,
    legacy_group,
    prepare_fixture,
    run_cli,
    write_json,
    write_text,
)


def test_qwen_is_registered_in_the_sdk_and_cli() -> None:
    assert SUPPORTED_AGENTS["qwen"] == {
        "name": "Qwen Code",
        "hook_event": "PreToolUse/PostToolUse/PostToolUseFailure",
        "config_path": "~/.qwen/settings.json",
    }
    assert cli.PLUGIN_MAP["qwen"] is qwen.QwenPlugin


def test_install_preserves_all_sources_and_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = (
        "{\r\n"
        "  // Keep this user preference.\r\n"
        '  "theme": "GitHub",\r\n'
        '  "hooks": {\r\n'
        '    "FutureEvent": [null],\r\n'
        '    "PreToolUse": [{ "matcher": "read_file", "hooks": '
        '[{ "type": "command", "command": "user-hook" }] }]\r\n'
        "  }\r\n"
        "}\r\n"
    )
    fixture = prepare_fixture(
        monkeypatch, tmp_path, existing_settings=source
    )
    workspace_path = fixture.project_dir / ".qwen" / "settings.json"
    write_json(workspace_path, {"owner": "workspace"})
    write_json(fixture.system_defaults_path, {"owner": "defaults"})
    write_json(fixture.system_path, {"owner": "system"})

    fixture.install()
    first_source = fixture.source()
    first = fixture.settings()
    assert "Keep this user preference" in first_source
    assert "\r\n" in first_source
    assert first["theme"] == "GitHub"
    assert first["hooks"]["FutureEvent"] == [None]
    assert first["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "user-hook"
    assert_managed_triple(first)
    for file_path in (
        fixture.guard_path,
        fixture.audit_path,
        fixture.runtime_config_path,
        fixture.private_key_path,
    ):
        assert file_path.is_file()

    fixture.install()
    assert fixture.source() == first_source
    assert json.loads(workspace_path.read_text(encoding="utf-8")) == {
        "owner": "workspace"
    }
    assert json.loads(fixture.system_defaults_path.read_text()) == {
        "owner": "defaults"
    }
    assert json.loads(fixture.system_path.read_text()) == {"owner": "system"}
    assert "run /hooks" in capsys.readouterr().out


def test_qwen_home_uses_complete_official_bootstrap_precedence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    first_home = tmp_path / "first # qwen home"
    second_home = tmp_path / "second qwen home"
    write_text(
        fixture.home_dir / ".qwen" / ".env",
        f'export QWEN_HOME = "{first_home}" # selected by Qwen\n',
    )
    write_text(fixture.home_dir / ".env", f"QWEN_HOME={second_home}\n")
    write_text(first_home / ".env", "QWEN_RUNTIME_DIR=runtime\n")

    fixture.install()
    selected = first_home / "settings.json"
    assert_managed_triple(fixture.settings(selected))
    assert not (second_home / "settings.json").exists()
    assert not fixture.config_path.exists()
    assert str(selected) in fixture.plugin.status()["details"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("relative-qwen", "project"),
        ("~/custom-qwen", "home"),
        ("", "default"),
    ],
)
def test_explicit_qwen_home_preserves_process_ownership_semantics(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    value: str,
    expected: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    ignored = tmp_path / "ignored-home"
    write_text(
        fixture.home_dir / ".qwen" / ".env", f"QWEN_HOME={ignored}\n"
    )
    monkeypatch.setenv("QWEN_HOME", value)
    fixture.install()
    paths = {
        "project": fixture.project_dir / "relative-qwen" / "settings.json",
        "home": fixture.home_dir / "custom-qwen" / "settings.json",
        "default": fixture.config_path,
    }
    assert_managed_triple(fixture.settings(paths[expected]))
    assert not (ignored / "settings.json").exists()


def test_qwen_validates_current_schemas_and_preserves_future_events(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, existing_settings={
        "hooks": {
            "FutureEvent": [None],
            "MessageDisplay": [{
                "matcher": "[",
                "hooks": [{
                    "type": "http",
                    "url": "http://127.0.0.1:8080/hook",
                    "headers": {"Authorization": "Bearer ${TOKEN}"},
                    "allowedEnvVars": ["TOKEN"],
                    "timeout": 10,
                    "once": True,
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
    assert settings["hooks"]["MessageDisplay"][0]["matcher"] == "["
    assert settings["hooks"]["Stop"][0]["hooks"][0]["type"] == "prompt"


@pytest.mark.parametrize(
    "source",
    [
        "{ malformed",
        "[]",
        '{ "owner": true, }',
        '{ "hooks": {}, "hooks": {} }',
        '{ "disableAllHooks": "yes" }',
        '{ "hooks": null }',
        '{ "hooks": [] }',
        '{ "hooks": { "PreToolUse": null } }',
        '{ "hooks": { "PreToolUse": [null] } }',
        '{ "hooks": { "PreToolUse": [{ "matcher": 1, "hooks": [] }] } }',
        '{ "hooks": { "PreToolUse": [{ "matcher": "[", "hooks": [] }] } }',
        '{ "hooks": { "Notification": [{ "matcher": "[", "hooks": [] }] } }',
        '{ "hooks": { "PreToolUse": [{ "sequential": 1, "hooks": [] }] } }',
        '{ "hooks": { "PreToolUse": [{}] } }',
        '{ "hooks": { "PreToolUse": [{ "hooks": [null] }] } }',
        '{ "hooks": { "PreToolUse": [{ "hooks": [{ "type": "function" }] }] } }',
        '{ "hooks": { "PreToolUse": [{ "hooks": [{ "type": "command" }] }] } }',
        '{ "hooks": { "PreToolUse": [{ "hooks": [{ "type": "http" }] }] } }',
        '{ "hooks": { "Stop": [{ "hooks": [{ "type": "prompt" }] }] } }',
        '{ "hooks": { "PreToolUse": [{ "hooks": [{ "type": "command", "command": "x", "timeout": -1 }] }] } }',
        '{ "security": { "folderTrust": { "enabled": "yes" } } }',
    ],
)
def test_install_rejects_malformed_sources_before_every_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, source: str
) -> None:
    fixture = prepare_fixture(
        monkeypatch, tmp_path, existing_settings=source
    )
    with pytest.raises((OSError, ValueError), match="Qwen"):
        fixture.install()
    assert fixture.source() == source
    assert not fixture.agent_dir.exists()


def test_install_surfaces_malformed_read_only_sources_and_routing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    system = prepare_fixture(monkeypatch, tmp_path / "system")
    write_text(system.system_path, "{ malformed")
    with pytest.raises(ValueError, match="system override"):
        system.install()
    assert not system.config_path.exists()
    assert not system.agent_dir.exists()

    routing = prepare_fixture(monkeypatch, tmp_path / "routing")
    (routing.home_dir / ".qwen" / ".env").mkdir(parents=True)
    with pytest.raises(OSError, match="Qwen Code home environment"):
        routing.install()
    assert not routing.config_path.exists()
    assert not routing.agent_dir.exists()


def test_disable_precedence_respects_workspace_trust(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    user = prepare_fixture(
        monkeypatch,
        tmp_path / "user",
        existing_settings={"disableAllHooks": False},
    )
    write_json(user.system_defaults_path, {"disableAllHooks": True})
    user.install()

    system = prepare_fixture(monkeypatch, tmp_path / "system")
    write_json(system.system_path, {"disableAllHooks": True})
    with pytest.raises(ValueError, match="system override"):
        system.install()

    untrusted = prepare_fixture(
        monkeypatch,
        tmp_path / "untrusted",
        existing_settings={"security": {"folderTrust": {"enabled": True}}},
    )
    write_json(
        untrusted.project_dir / ".qwen" / "settings.json",
        {"disableAllHooks": True},
    )
    write_json(
        untrusted.trusted_folders_path,
        {str(untrusted.project_dir): "DO_NOT_TRUST"},
    )
    untrusted.install()

    trusted = prepare_fixture(
        monkeypatch,
        tmp_path / "trusted",
        existing_settings={"security": {"folderTrust": {"enabled": True}}},
    )
    write_json(
        trusted.project_dir / ".qwen" / "settings.json",
        {"disableAllHooks": True},
    )
    write_json(
        trusted.trusted_folders_path,
        {str(trusted.project_dir): "TRUST_FOLDER"},
    )
    with pytest.raises(ValueError, match="workspace settings"):
        trusted.install()


def test_transaction_aborts_when_read_only_source_changes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    write_json(fixture.system_path, {"owner": "before"})
    sources = read_qwen_sources()
    paths = preflight_qwen_installation(fixture.config, sources)
    rendered = render_qwen_document(sources.user, None, {
        "PreToolUse": build_qwen_group(paths.guard_path, GUARD_HOOK_NAME),
        "PostToolUse": build_qwen_group(paths.audit_path, AUDIT_HOOK_NAME),
        "PostToolUseFailure": build_qwen_group(
            paths.audit_path, AUDIT_HOOK_NAME
        ),
    })
    changes = prepare_qwen_installation(fixture.config, paths, rendered)
    write_json(fixture.system_path, {"owner": "after"})
    with pytest.raises(OSError, match="system override settings changed"):
        commit_qwen_installation(changes, sources)
    assert json.loads(fixture.system_path.read_text()) == {"owner": "after"}
    assert not fixture.config_path.exists()
    assert not fixture.agent_dir.exists()


def test_transaction_rolls_back_every_runtime_and_settings_change(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(
        monkeypatch, tmp_path, existing_settings={"owner": "user"}
    )
    original = fixture.source()
    real_replace = _transaction.os.replace
    failed = False

    def fail_settings_commit(source: Any, destination: Any) -> None:
        nonlocal failed
        if not failed and Path(destination) == fixture.config_path:
            failed = True
            raise OSError("simulated settings commit failure")
        real_replace(source, destination)

    monkeypatch.setattr(_transaction.os, "replace", fail_settings_commit)
    with pytest.raises(OSError, match="Install Qwen Code hooks"):
        fixture.install()
    assert failed
    assert fixture.source() == original
    for file_path in (
        fixture.guard_path,
        fixture.audit_path,
        fixture.runtime_config_path,
        fixture.private_key_path,
    ):
        assert not file_path.exists()
    assert [
        path
        for path in fixture.home_dir.rglob("*")
        if path.suffix in {".tmp", ".rollback"}
    ] == []


def test_install_migrates_legacy_and_uninstall_preserves_lookalikes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    lookalike = legacy_group(fixture.guard_path)
    lookalike["hooks"][0]["timeout"] = 9_000
    write_json(fixture.config_path, {
        "owner": "user",
        "hooks": {
            "PreToolUse": [legacy_group(fixture.guard_path), lookalike],
            "PostToolUse": [legacy_group(fixture.audit_path)],
        },
    })
    fixture.install()
    settings = fixture.settings()
    assert_managed_triple(settings)
    managed = settings["hooks"]["PreToolUse"][-1]
    managed["userField"] = "preserve-group"
    managed["hooks"].append({"type": "command", "command": "user-command"})
    write_json(fixture.config_path, settings)

    fixture.plugin.uninstall(AGENT_ID)
    remaining = fixture.settings()
    assert remaining["owner"] == "user"
    assert any(
        group["hooks"][0].get("timeout") == 9_000
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
        existing_settings={"theme": "GitHub", "hooks": {"Notification": []}},
    )
    user.install()
    user.plugin.uninstall(AGENT_ID)
    assert user.settings() == {
        "theme": "GitHub",
        "hooks": {"Notification": []},
    }

    owned = prepare_fixture(monkeypatch, tmp_path / "owned")
    owned.install()
    assert owned.source().startswith("// Managed by Elydora")
    owned.plugin.uninstall(AGENT_ID)
    assert not owned.config_path.exists()


def test_status_requires_exact_contract_and_runtime_identity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    assert fixture.plugin.status()["installed"] is True
    settings = fixture.settings()
    settings["hooks"]["PostToolUseFailure"].append(
        settings["hooks"]["PostToolUseFailure"][-1]
    )
    write_json(fixture.config_path, settings)
    assert fixture.plugin.status()["installed"] is False

    fixture.install()
    write_text(fixture.private_key_path, "invalid")
    with pytest.raises(ValueError, match="private key"):
        fixture.plugin.status()
    fixture.install()
    write_text(fixture.guard_path, "tampered")
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
    assert not identity.config_path.exists()

    invalid = prepare_fixture(monkeypatch, tmp_path / "invalid")
    invalid.config["agent_id"] = "../escape"
    with pytest.raises(ValueError, match="Invalid agent ID"):
        invalid.install()
    assert not invalid.config_path.exists()


def test_qwen_cli_install_status_and_uninstall_end_to_end(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    key_file = tmp_path / "install-private.key"
    token_file = tmp_path / "install-token.txt"
    write_text(key_file, VALID_PRIVATE_KEY + "\n")
    write_text(token_file, "token-1\n")
    install = run_cli(fixture, [
        "install",
        "--agent", "qwen",
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
    assert "Qwen Code" in status.stdout and "[installed]" in status.stdout
    uninstall = run_cli(fixture, [
        "uninstall", "--agent", "qwen", "--agent_id", AGENT_ID
    ])
    assert uninstall.returncode == 0, uninstall.stderr
    assert not fixture.config_path.exists()
    assert not fixture.agent_dir.exists()
