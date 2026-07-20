from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess  # nosec B404
import sys

import pytest

from augment_support import (
    AGENT_ID,
    VALID_PRIVATE_KEY,
    managed_handler,
    prepare_fixture,
    write_text,
)
from elydora import cli
from elydora.plugins import augment
from elydora.plugins import augment_contract as contract
from elydora.plugins.registry import SUPPORTED_AGENTS


def test_augment_is_registered_and_owns_its_complete_runtime() -> None:
    assert SUPPORTED_AGENTS["augment"] == {
        "name": "Augment Code CLI",
        "hook_event": "PreToolUse/PostToolUse",
        "config_path": "~/.augment/settings.json",
    }
    assert cli.PLUGIN_MAP["augment"] is augment.AugmentPlugin
    assert augment.AugmentPlugin.manages_guard_runtime is True


def test_install_preserves_official_settings_and_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    existing = {
        "telemetryEnabled": False,
        "hooks": {
            "SessionStart": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": "existing-command",
                            "args": ["one"],
                            "timeout": 5_000,
                        }
                    ],
                    "metadata": {
                        "includeConversationData": True,
                        "includeMCPMetadata": False,
                        "includeUserContext": True,
                    },
                    "label": "keep group metadata",
                }
            ],
            "PromptSubmit": [
                {"hooks": [{"type": "command", "command": "prompt-hook"}]}
            ],
            "Notification": [
                {"hooks": [{"type": "command", "command": "notification-hook"}]}
            ],
            "PreToolUse": [
                {
                    "matcher": "(?<tool>launch-process)",
                    "hooks": [{"type": "command", "command": "user-command"}],
                }
            ],
        },
    }
    fixture = prepare_fixture(monkeypatch, tmp_path, existing_settings=existing)
    fixture.install()
    first = fixture.config_path.read_text(encoding="utf-8")
    fixture.install()
    assert fixture.config_path.read_text(encoding="utf-8") == first
    assert "user-level PreToolUse and PostToolUse" in capsys.readouterr().out

    settings = fixture.settings()
    assert settings["telemetryEnabled"] is False
    for event in ("SessionStart", "PromptSubmit", "Notification"):
        assert settings["hooks"][event] == existing["hooks"][event]
    assert settings["hooks"]["PreToolUse"][0] == existing["hooks"]["PreToolUse"][0]
    assert len(settings["hooks"]["PreToolUse"]) == 2
    assert len(settings["hooks"]["PostToolUse"]) == 1
    for event, wrapper_path in (
        ("PreToolUse", fixture.guard_wrapper_path),
        ("PostToolUse", fixture.audit_wrapper_path),
    ):
        handler = managed_handler(settings, event, wrapper_path)
        assert set(handler) == {"type", "command", "timeout"}
        assert handler["type"] == "command"
        assert handler["timeout"] == 10_000

    assert json.loads(fixture.runtime_config_path.read_text(encoding="utf-8")) == {
        "org_id": "org-1",
        "agent_id": AGENT_ID,
        "kid": "key-1",
        "base_url": "http://127.0.0.1:9",
        "agent_name": "augment",
        "token": "token-1",
    }
    assert fixture.private_key_path.read_text(encoding="utf-8") == VALID_PRIVATE_KEY
    assert "NATIVE_PAYLOAD = True" in fixture.hook_path.read_text(encoding="utf-8")
    guard_wrapper = fixture.guard_wrapper_path.read_text(encoding="utf-8")
    assert fixture.guard_path.name in guard_wrapper
    assert fixture.hook_path.name in fixture.audit_wrapper_path.read_text(
        encoding="utf-8"
    )
    if os.name == "nt":
        assert guard_wrapper.startswith("@echo off\n")
        assert "exit /b %errorlevel%" in guard_wrapper
    else:
        assert fixture.guard_wrapper_path.stat().st_mode & 0o111
        assert guard_wrapper.startswith("#!/bin/sh\nexec ")
    assert not (fixture.project_dir / ".augment" / "settings.json").exists()


def test_install_replaces_stale_handlers_and_preserves_empty_groups(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    settings = fixture.settings()
    settings["hooks"]["PreToolUse"].insert(
        0, {"hooks": [], "label": "keep empty group"}
    )
    for event, wrapper_name in (
        ("PreToolUse", contract.GUARD_WRAPPER),
        ("PostToolUse", contract.AUDIT_WRAPPER),
    ):
        settings["hooks"][event].append(
            {
                "hooks": [
                    {
                        "type": "command",
                        "command": contract.build_command(
                            str(fixture.agent_dir.parent / "agent-old" / wrapper_name)
                        ),
                        "timeout": 10_000,
                    }
                ]
            }
        )
    fixture.config_path.write_text(json.dumps(settings, indent=2), encoding="utf-8")
    fixture.install()
    current = fixture.settings()
    assert "agent-old" not in json.dumps(current)
    assert current["hooks"]["PreToolUse"][0] == {
        "hooks": [],
        "label": "keep empty group",
    }
    assert len(current["hooks"]["PreToolUse"]) == 2
    assert len(current["hooks"]["PostToolUse"]) == 1


def test_uninstall_removes_exact_ownership_and_preserves_user_groups(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        existing_settings={"owner": "user", "hooks": {"Notification": []}},
    )
    fixture.install()
    settings = fixture.settings()
    settings["hooks"]["PreToolUse"][0]["hooks"].append(
        {"type": "command", "command": "user-command"}
    )
    settings["hooks"]["PreToolUse"].append(
        {
            "hooks": [
                {
                    "type": "command",
                    "command": contract.build_command(
                        str(fixture.guard_wrapper_path) + ".backup"
                    ),
                    "timeout": 10_000,
                }
            ]
        }
    )
    settings["hooks"]["PreToolUse"].append(
        {
            "hooks": [
                {
                    "type": "command",
                    "command": contract.build_command(
                        str(
                            fixture.agent_dir.parent
                            / "agent-10"
                            / contract.GUARD_WRAPPER
                        )
                    ),
                    "timeout": 10_000,
                }
            ]
        }
    )
    fixture.config_path.write_text(json.dumps(settings, indent=2), encoding="utf-8")
    uninstall_id = "AGENT-1" if os.name == "nt" else AGENT_ID
    fixture.plugin.uninstall(uninstall_id)
    remaining = fixture.settings()
    assert remaining["owner"] == "user"
    assert remaining["hooks"]["Notification"] == []
    assert remaining["hooks"]["PreToolUse"][0]["hooks"] == [
        {"type": "command", "command": "user-command"}
    ]
    raw = fixture.config_path.read_text(encoding="utf-8")
    assert "augment-guard" in raw and "backup" in raw
    assert "agent-10" in raw
    assert "PostToolUse" not in remaining["hooks"]


def test_uninstall_removes_settings_owned_entirely_by_elydora(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    fixture.plugin.uninstall(AGENT_ID)
    assert not fixture.config_path.exists()


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
    }
    root = Path(__file__).parents[1]
    base = [sys.executable, "-m", "elydora.cli"]
    install = subprocess.run(  # nosec B603
        [
            *base,
            "install",
            "--agent",
            "augment",
            "--org_id",
            "org-1",
            "--agent_id",
            AGENT_ID,
            "--private_key_file",
            str(key_path),
            "--token_file",
            str(token_path),
            "--kid",
            "key-1",
            "--base_url",
            "http://127.0.0.1:9",
        ],
        capture_output=True,
        check=False,
        cwd=root,
        env=environment,
        text=True,
    )
    assert install.returncode == 0, install.stderr
    assert "PreToolUse and PostToolUse hooks installed" in install.stdout

    status = subprocess.run(  # nosec B603
        [*base, "status"],
        capture_output=True,
        check=False,
        cwd=root,
        env=environment,
        text=True,
    )
    assert status.returncode == 0, status.stderr
    assert "Augment Code CLI" in status.stdout
    assert "[installed]" in status.stdout

    uninstall = subprocess.run(  # nosec B603
        [*base, "uninstall", "--agent", "augment", "--agent_id", AGENT_ID],
        capture_output=True,
        check=False,
        cwd=root,
        env=environment,
        text=True,
    )
    assert uninstall.returncode == 0, uninstall.stderr
    assert not fixture.config_path.exists()
    assert not fixture.agent_dir.exists()


@pytest.mark.parametrize(
    "existing",
    [
        "{ malformed",
        "null",
        "[]",
        '{"hooks":{},"hooks":{}}',
        {"hooks": None},
        {"hooks": {"UnknownEvent": []}},
        {"hooks": {"PreToolUse": None}},
        {"hooks": {"PreToolUse": [None]}},
        {"hooks": {"SessionStart": [{"matcher": ".*", "hooks": []}]}},
        {"hooks": {"PreToolUse": [{"matcher": "[", "hooks": []}]}},
        {"hooks": {"PreToolUse": [{"hooks": None}]}},
        {"hooks": {"PreToolUse": [{"hooks": [{"type": "http", "command": "x"}]}]}},
        {
            "hooks": {
                "PreToolUse": [
                    {"hooks": [{"type": "command", "command": "", "args": []}]}
                ]
            }
        },
        {
            "hooks": {
                "PreToolUse": [
                    {"hooks": [{"type": "command", "command": "x", "args": [1]}]}
                ]
            }
        },
        {
            "hooks": {
                "PreToolUse": [
                    {"hooks": [{"type": "command", "command": "x", "timeout": 0}]}
                ]
            }
        },
        {
            "hooks": {
                "PreToolUse": [{"hooks": [], "metadata": {"includeUserContext": "yes"}}]
            }
        },
    ],
)
def test_install_rejects_invalid_settings_before_writes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, existing: object
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, existing_settings=existing)
    original = fixture.config_path.read_text(encoding="utf-8")
    with pytest.raises((FileNotFoundError, ValueError)):
        fixture.install()
    assert fixture.config_path.read_text(encoding="utf-8") == original
    for path in (
        fixture.guard_path,
        fixture.hook_path,
        fixture.runtime_config_path,
        fixture.private_key_path,
        fixture.guard_wrapper_path,
        fixture.audit_wrapper_path,
    ):
        assert not path.exists()
