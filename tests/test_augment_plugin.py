from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
from typing import Any

import pytest

from elydora import cli
from elydora.plugins import augment
from elydora.plugins import augment_contract as contract
from elydora.plugins.base import InstallConfig
from elydora.plugins.registry import SUPPORTED_AGENTS


AGENT_ID = "agent-1"
MISSING = object()


@dataclass(frozen=True)
class AugmentFixture:
    plugin: augment.AugmentPlugin
    config: InstallConfig
    home_dir: Path
    workspace_dir: Path
    agent_dir: Path
    config_path: Path
    guard_path: Path
    hook_path: Path
    guard_wrapper_path: Path
    audit_wrapper_path: Path
    runtime_config_path: Path
    private_key_path: Path


def prepare_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    existing_settings: object = MISSING,
    create_guard: bool = True,
) -> AugmentFixture:
    home_dir = tmp_path / "home with spaces and 'quote"
    workspace_dir = home_dir / "workspace"
    agent_dir = home_dir / ".elydora" / AGENT_ID
    config_path = home_dir / ".augment" / "settings.json"
    guard_path = agent_dir / contract.GUARD_SCRIPT
    hook_path = agent_dir / contract.AUDIT_SCRIPT
    guard_wrapper_path = agent_dir / contract.GUARD_WRAPPER
    audit_wrapper_path = agent_dir / contract.AUDIT_WRAPPER
    workspace_dir.mkdir(parents=True)
    agent_dir.mkdir(parents=True)
    if create_guard:
        guard_path.write_text(
            "import sys\nsys.stdin.read()\n"
            "sys.stderr.write('Agent is frozen by Elydora.')\n"
            "raise SystemExit(2)\n",
            encoding="utf-8",
        )
    if existing_settings is not MISSING:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        raw = (
            str(existing_settings)
            if isinstance(existing_settings, str)
            else json.dumps(existing_settings, indent=2)
        )
        config_path.write_text(raw, encoding="utf-8")

    monkeypatch.setattr(contract, "home_dir", lambda: str(home_dir))
    config: InstallConfig = {
        "agent_id": AGENT_ID,
        "agent_name": "augment",
        "org_id": "org-1",
        "private_key": "test-key",
        "kid": "kid-1",
        "base_url": "https://api.elydora.test",
        "guard_script_path": str(guard_path),
    }
    return AugmentFixture(
        plugin=augment.AugmentPlugin(),
        config=config,
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        agent_dir=agent_dir,
        config_path=config_path,
        guard_path=guard_path,
        hook_path=hook_path,
        guard_wrapper_path=guard_wrapper_path,
        audit_wrapper_path=audit_wrapper_path,
        runtime_config_path=agent_dir / "config.json",
        private_key_path=agent_dir / "private.key",
    )


def managed_handler(
    settings: dict[str, Any], event: str, wrapper_path: Path
) -> dict[str, Any]:
    command = contract.build_command(str(wrapper_path))
    for group in settings["hooks"][event]:
        for handler in group["hooks"]:
            if handler.get("command") == command:
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
        env={
            **os.environ,
            "HOME": str(home_dir),
            "USERPROFILE": str(home_dir),
        },
        input=payload,
        text=True,
    )


def test_augment_is_registered_in_sdk_and_cli() -> None:
    assert SUPPORTED_AGENTS["augment"] == {
        "name": "Augment Code CLI",
        "hook_event": "PreToolUse/PostToolUse",
        "config_path": "~/.augment/settings.json",
    }
    assert cli.PLUGIN_MAP["augment"] is augment.AugmentPlugin


def test_install_preserves_user_settings_and_is_idempotent(
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
                    "metadata": {"includeUserContext": True},
                    "label": "keep group metadata",
                }
            ],
            "PreToolUse": [
                {
                    "matcher": "launch-process",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "user-command",
                        }
                    ],
                }
            ],
        },
    }
    fixture = prepare_fixture(monkeypatch, tmp_path, existing_settings=existing)
    fixture.plugin.install(fixture.config)
    fixture.plugin.install(fixture.config)
    assert "user-level PreToolUse and PostToolUse" in capsys.readouterr().out
    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    assert settings["telemetryEnabled"] is False
    assert settings["hooks"]["SessionStart"] == existing["hooks"]["SessionStart"]
    assert settings["hooks"]["PreToolUse"][0] == existing["hooks"]["PreToolUse"][0]
    assert len(settings["hooks"]["PreToolUse"]) == 2
    assert len(settings["hooks"]["PostToolUse"]) == 1
    assert settings["hooks"]["PreToolUse"][1]["matcher"] == ".*"
    for event, wrapper_path in (
        ("PreToolUse", fixture.guard_wrapper_path),
        ("PostToolUse", fixture.audit_wrapper_path),
    ):
        handler = managed_handler(settings, event, wrapper_path)
        assert set(handler) == {"type", "command", "timeout"}
        assert handler["type"] == "command"
        assert handler["timeout"] == 10_000
    guard_wrapper = fixture.guard_wrapper_path.read_text(encoding="utf-8")
    audit_wrapper = fixture.audit_wrapper_path.read_text(encoding="utf-8")
    assert fixture.guard_path.name in guard_wrapper
    assert fixture.hook_path.name in audit_wrapper
    if os.name == "nt":
        assert guard_wrapper.startswith("@echo off\n")
        assert "exit /b %errorlevel%" in guard_wrapper
    else:
        assert fixture.guard_wrapper_path.stat().st_mode & 0o111
        assert guard_wrapper.startswith("#!/bin/sh\nexec ")
    assert (
        json.loads(fixture.runtime_config_path.read_text(encoding="utf-8"))[
            "agent_name"
        ]
        == "augment"
    )
    assert fixture.private_key_path.read_text(encoding="utf-8") == "test-key"
    assert (fixture.workspace_dir / ".augment" / "settings.json").exists() is False
    assert (
        fixture.workspace_dir / ".augment" / "settings.local.json"
    ).exists() is False


def test_wrappers_block_and_forward_official_payload_byte_for_byte(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    capture_path = tmp_path / "captured-event.json"
    fixture.hook_path.write_text(
        "from pathlib import Path\nimport sys\n"
        f"Path({str(capture_path)!r}).write_text("
        "sys.stdin.read(), encoding='utf-8')\n",
        encoding="utf-8",
    )
    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    pre_payload = json.dumps(
        {
            "hook_event_name": "PreToolUse",
            "conversation_id": "conversation-1",
            "workspace_roots": [str(fixture.workspace_dir)],
            "tool_name": "launch-process",
            "tool_input": {"command": "echo test"},
            "is_mcp_tool": False,
        },
        separators=(",", ":"),
    )
    guard = managed_handler(settings, "PreToolUse", fixture.guard_wrapper_path)
    guard_result = run_command(guard["command"], fixture.home_dir, pre_payload)
    assert guard_result.returncode == 2
    assert "Agent is frozen by Elydora" in guard_result.stderr

    post_payload = json.dumps(
        {
            "hook_event_name": "PostToolUse",
            "conversation_id": "conversation-1",
            "workspace_roots": [str(fixture.workspace_dir)],
            "tool_name": "launch-process",
            "tool_input": {"command": "echo test"},
            "tool_output": "test",
            "is_mcp_tool": False,
        },
        separators=(",", ":"),
    )
    audit = managed_handler(settings, "PostToolUse", fixture.audit_wrapper_path)
    audit_result = run_command(audit["command"], fixture.home_dir, post_payload)
    assert audit_result.returncode == 0
    assert capture_path.read_text(encoding="utf-8") == post_payload


def test_status_requires_complete_pair_core_runtimes_and_wrappers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    assert fixture.plugin.status()["installed"] is True

    fixture.guard_wrapper_path.unlink()
    status = fixture.plugin.status()
    assert status["installed"] is False
    assert "wrappers missing" in status["details"]

    fixture.plugin.install(fixture.config)
    fixture.hook_path.unlink()
    assert fixture.plugin.status()["installed"] is False

    fixture.plugin.install(fixture.config)
    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    del settings["hooks"]["PostToolUse"]
    fixture.config_path.write_text(json.dumps(settings), encoding="utf-8")
    assert fixture.plugin.status()["installed"] is False


def test_uninstall_removes_exact_ownership_and_preserves_user_groups(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        existing_settings={"owner": "user", "hooks": {"Notification": []}},
    )
    fixture.plugin.install(fixture.config)
    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    settings["hooks"]["PreToolUse"].insert(
        0, {"hooks": [], "label": "keep empty group"}
    )
    settings["hooks"]["PreToolUse"][1]["hooks"].append(
        {
            "type": "command",
            "command": "user-command",
        }
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
    remaining = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    assert remaining["owner"] == "user"
    assert remaining["hooks"]["Notification"] == []
    assert len(remaining["hooks"]["PreToolUse"]) == 4
    assert remaining["hooks"]["PreToolUse"][0] == {
        "hooks": [],
        "label": "keep empty group",
    }
    assert remaining["hooks"]["PreToolUse"][1]["hooks"] == [
        {
            "type": "command",
            "command": "user-command",
        }
    ]
    raw = fixture.config_path.read_text(encoding="utf-8")
    assert "augment-guard" in raw and "backup" in raw
    assert "agent-10" in raw
    assert "PostToolUse" not in remaining["hooks"]


def test_install_replaces_stale_handlers_and_preserves_empty_groups(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
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
    fixture.plugin.install(fixture.config)
    current = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    assert "agent-old" not in json.dumps(current)
    assert current["hooks"]["PreToolUse"][0] == {
        "hooks": [],
        "label": "keep empty group",
    }
    assert len(current["hooks"]["PreToolUse"]) == 2
    assert len(current["hooks"]["PostToolUse"]) == 1


def test_uninstall_removes_settings_owned_entirely_by_elydora(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    fixture.plugin.uninstall(AGENT_ID)
    assert fixture.config_path.exists() is False


@pytest.mark.parametrize(
    "existing",
    [
        "{ malformed",
        "null",
        "[]",
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
def test_install_rejects_malformed_settings_before_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    existing: object,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, existing_settings=existing)
    original = fixture.config_path.read_text(encoding="utf-8")

    with pytest.raises(ValueError):
        fixture.plugin.install(fixture.config)

    assert fixture.config_path.read_text(encoding="utf-8") == original
    assert fixture.hook_path.exists() is False
    assert fixture.runtime_config_path.exists() is False
    assert fixture.private_key_path.exists() is False
    assert fixture.guard_wrapper_path.exists() is False
    assert fixture.audit_wrapper_path.exists() is False


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
    assert fixture.guard_wrapper_path.exists() is False


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
