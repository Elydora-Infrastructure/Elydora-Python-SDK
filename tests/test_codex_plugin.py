from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from codex_support import (
    AGENT_ID,
    VALID_PRIVATE_KEY,
    assert_native_handler,
    legacy_handler,
    managed_handler,
    prepare_fixture,
    symlink_or_skip,
    write_json,
    write_text,
)
from elydora.plugins.codex_contract import (
    AUDIT_STATUS,
    GUARD_STATUS,
    build_handler,
)
from elydora.plugins.registry import SUPPORTED_AGENTS


def test_codex_registry_points_at_native_user_hooks() -> None:
    assert SUPPORTED_AGENTS["codex"] == {
        "name": "OpenAI Codex",
        "hook_event": "PreToolUse/PostToolUse",
        "config_path": "~/.codex/hooks.json",
    }


def test_codex_follows_and_canonicalizes_codex_home(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    target = tmp_path / "custom Codex home"
    configured = tmp_path / "codex-home-link"
    target.mkdir()
    try:
        configured.symlink_to(target, target_is_directory=True)
    except OSError:
        configured = target
    monkeypatch.setenv("CODEX_HOME", str(configured))

    fixture.install()

    expected = Path(os.path.realpath(target)) / "hooks.json"
    assert expected.is_file()
    assert fixture.config_path.exists() is False
    status = fixture.plugin.status()
    assert status["installed"] is True
    assert status["details"] == f"Config: {expected}"


@pytest.mark.parametrize("kind", ["missing", "file"])
def test_codex_rejects_invalid_codex_home_before_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    kind: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    configured = tmp_path / f"{kind}-codex-home"
    if kind == "file":
        write_text(configured, "not a directory")

    monkeypatch.setenv("CODEX_HOME", str(configured))
    with pytest.raises(OSError, match="CODEX_HOME"):
        fixture.install()

    assert list(fixture.agent_dir.iterdir()) == []
    assert fixture.config_path.exists() is False


def test_install_preserves_sources_migrates_legacy_and_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    write_json(
        fixture.config_path,
        {
            "description": "User hooks",
            "metadata": {"owner": "user"},
            "hooks": {
                "SessionStart": [
                    {"matcher": "*", "hooks": [{"type": "command", "command": "keep"}]}
                ],
                "PreToolUse": [
                    {
                        "matcher": "*",
                        "hooks": [legacy_handler(fixture.guard_path, GUARD_STATUS)],
                    }
                ],
                "PostToolUse": [
                    {
                        "matcher": "*",
                        "hooks": [legacy_handler(fixture.hook_path, AUDIT_STATUS)],
                    }
                ],
            },
        },
    )

    fixture.install()
    first = fixture.config_path.read_text(encoding="utf-8")
    fixture.install()
    second = fixture.config_path.read_text(encoding="utf-8")

    assert first == second
    assert "approve both Elydora command hooks" in capsys.readouterr().out
    settings = fixture.settings()
    assert settings["description"] == "User hooks"
    assert settings["metadata"] == {"owner": "user"}
    assert settings["hooks"]["SessionStart"][0]["hooks"][0]["command"] == "keep"
    assert len(settings["hooks"]["PreToolUse"]) == 1
    assert len(settings["hooks"]["PostToolUse"]) == 1
    assert_native_handler(
        managed_handler(settings, "PreToolUse", GUARD_STATUS),
        GUARD_STATUS,
    )
    assert_native_handler(
        managed_handler(settings, "PostToolUse", AUDIT_STATUS),
        AUDIT_STATUS,
    )
    runtime = json.loads(fixture.runtime_config_path.read_text(encoding="utf-8"))
    assert runtime["agent_name"] == "codex"
    assert runtime["token"] == "token-1"
    assert fixture.private_key_path.read_text(encoding="utf-8") == VALID_PRIVATE_KEY
    assert fixture.guard_path.is_file()
    assert fixture.hook_path.is_file()


@pytest.mark.parametrize(
    ("source", "error_pattern"),
    [
        ('{"hooks":{},"hooks":{}}', "duplicate field"),
        ('{"hooks":{},}', "parse Codex user hooks"),
        ('{"hooks":{/*comment*/}}', "parse Codex user hooks"),
        ("[]", "must contain a JSON object"),
        ('{"hooks":null}', 'field "hooks" must be an object'),
        ('{"hooks":{"PreToolUse":null}}', 'hooks.PreToolUse" must be an array'),
        (
            '{"hooks":{"PreToolUse":[{"hooks":null}]}}',
            "must contain a hooks array",
        ),
        (
            '{"hooks":{"PreToolUse":[{"hooks":[null]}]}}',
            "must contain a hooks array",
        ),
    ],
)
def test_install_preserves_malformed_and_ambiguous_json(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    source: str,
    error_pattern: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, existing_config=source)

    with pytest.raises(ValueError, match=error_pattern):
        fixture.install()

    assert fixture.config_path.read_text(encoding="utf-8") == source
    assert list(fixture.agent_dir.iterdir()) == []


def test_status_requires_exact_pair_identity_and_runtime_secrets(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    assert fixture.plugin.status()["installed"] is True

    fixture.private_key_path.unlink()
    status = fixture.plugin.status()
    assert status["installed"] is False
    assert "runtime files missing" in status["details"]

    fixture.install()
    settings = fixture.settings()
    guard = managed_handler(settings, "PreToolUse", GUARD_STATUS)
    guard["extra"] = True
    write_json(fixture.config_path, settings)
    assert fixture.plugin.status()["installed"] is False

    fixture.install()
    runtime = json.loads(fixture.runtime_config_path.read_text(encoding="utf-8"))
    runtime["agent_id"] = "another-agent"
    write_json(fixture.runtime_config_path, runtime)
    assert fixture.plugin.status()["installed"] is False

    write_text(fixture.runtime_config_path, "{ malformed")
    with pytest.raises(ValueError, match="parse Elydora runtime config"):
        fixture.plugin.status()


def test_uninstall_removes_exact_ownership_and_preserves_lookalikes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    settings = fixture.settings()
    agent_ten = fixture.agent_dir.parent / "agent-10"
    other_guard = build_handler(str(agent_ten / "guard.py"), GUARD_STATUS)
    other_audit = build_handler(str(agent_ten / "hook.py"), AUDIT_STATUS)
    lookalike = {
        "type": "command",
        "command": f"inspect {fixture.guard_path}",
        "commandWindows": f"inspect {fixture.guard_path}",
        "timeout": 10,
        "statusMessage": GUARD_STATUS,
    }
    managed_guard = dict(managed_handler(settings, "PreToolUse", GUARD_STATUS))
    settings["hooks"]["SessionStart"] = [
        {"matcher": "*", "hooks": [{"type": "command", "command": "keep"}]}
    ]
    settings["hooks"]["PreToolUse"].extend(
        [
            {"matcher": "*", "hooks": [other_guard]},
            {"matcher": "*", "hooks": [lookalike]},
            {"matcher": "Bash", "hooks": [managed_guard]},
        ]
    )
    settings["hooks"]["PostToolUse"].append({"matcher": "*", "hooks": [other_audit]})
    write_json(fixture.config_path, settings)

    fixture.plugin.uninstall(AGENT_ID)

    remaining = fixture.settings()
    assert remaining["hooks"]["SessionStart"][0]["hooks"][0]["command"] == "keep"
    assert len(remaining["hooks"]["PreToolUse"]) == 3
    assert len(remaining["hooks"]["PostToolUse"]) == 1
    assert remaining["hooks"]["PreToolUse"][1]["hooks"][0] == lookalike
    assert remaining["hooks"]["PreToolUse"][2] == {"matcher": "Bash", "hooks": []}


def test_uninstall_removes_an_entirely_managed_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()

    fixture.plugin.uninstall(AGENT_ID)
    fixture.plugin.uninstall(AGENT_ID)

    assert fixture.config_path.exists() is False


@pytest.mark.parametrize(
    "overrides",
    [
        {"agent_name": "cursor"},
        {"org_id": ""},
        {"agent_id": "../escape"},
        {"private_key": "invalid"},
        {"token": ""},
        {"base_url": "file:///tmp/elydora"},
        {"base_url": "https://user:secret@api.elydora.com"},
        {"base_url": "https://api.elydora.com?tenant=one"},
        {"base_url": "https://api.elydora.com\\evil"},
        {"base_url": "https://api.elydora.com/invalid path"},
        {"base_url": "https://api.elydora.com:invalid"},
        {"guard_script_path": "unmanaged.py"},
    ],
)
def test_install_validates_identity_credentials_and_api_origin(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    overrides: dict[str, str],
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.config.update(overrides)

    with pytest.raises(ValueError):
        fixture.install()

    assert fixture.config_path.exists() is False
    assert list(fixture.agent_dir.iterdir()) == []


@pytest.mark.parametrize("kind", ["hooks", "config", "key", "guard", "audit"])
def test_linked_hook_and_runtime_files_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    kind: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    if kind == "hooks":
        target = tmp_path / "hooks-target.json"
        original = '{"hooks":{}}\n'
        write_text(target, original)
        fixture.config_path.parent.mkdir(parents=True)
        symlink_or_skip(target, fixture.config_path)
        with pytest.raises(OSError, match="physical file"):
            fixture.install()
        assert target.read_text(encoding="utf-8") == original
        return

    fixture.install()
    file_path = {
        "config": fixture.runtime_config_path,
        "key": fixture.private_key_path,
        "guard": fixture.guard_path,
        "audit": fixture.hook_path,
    }[kind]
    target = tmp_path / f"{kind}-target"
    target.write_bytes(file_path.read_bytes())
    file_path.unlink()
    symlink_or_skip(target, file_path)

    with pytest.raises(OSError, match="physical file"):
        fixture.plugin.status()

    assert target.read_bytes()
