from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import sys
from typing import Any

import pytest

from cursor_support import (
    AGENT_ID,
    assert_native_handler,
    managed_handler,
    prepare_fixture,
    write_json,
)
from elydora.plugins.registry import SUPPORTED_AGENTS


EVENTS = (
    ("preToolUse", "guard.py"),
    ("postToolUse", "hook.py"),
    ("postToolUseFailure", "hook.py"),
)


def test_cursor_registry_declares_complete_native_contract() -> None:
    assert SUPPORTED_AGENTS["cursor"] == {
        "name": "Cursor",
        "hook_event": "preToolUse/postToolUse/postToolUseFailure",
        "config_path": "~/.cursor/hooks.json",
    }


def test_install_preserves_user_hooks_migrates_legacy_and_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    write_json(
        fixture.config_path,
        {
            "description": "user-owned",
            "hooks": {
                "sessionStart": [{"command": "user-session"}],
                "preToolUse": [
                    {"command": "user-pre"},
                    {"command": f'"{sys.executable}" {fixture.guard_path}'},
                ],
                "postToolUse": [{"command": str(fixture.hook_path)}],
            },
        },
    )

    fixture.install()
    fixture.install()

    settings = fixture.settings()
    assert settings["version"] == 1
    assert settings["description"] == "user-owned"
    assert settings["hooks"]["sessionStart"] == [{"command": "user-session"}]
    assert settings["hooks"]["preToolUse"][0] == {"command": "user-pre"}
    assert len(settings["hooks"]["preToolUse"]) == 2
    assert len(settings["hooks"]["postToolUse"]) == 1
    assert len(settings["hooks"]["postToolUseFailure"]) == 1
    for event, script in EVENTS:
        assert_native_handler(managed_handler(settings, event, script))


def test_status_requires_complete_contract_identity_and_physical_runtimes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    assert fixture.plugin.status()["installed"] is True

    settings = fixture.settings()
    settings["hooks"].pop("postToolUseFailure")
    write_json(fixture.config_path, settings)
    assert fixture.plugin.status()["installed"] is False

    fixture.install()
    hook_source = fixture.hook_path.read_text(encoding="utf-8")
    fixture.hook_path.unlink()
    assert fixture.plugin.status()["installed"] is False
    fixture.hook_path.write_text(hook_source, encoding="utf-8")

    write_json(
        fixture.runtime_config_path,
        {"agent_id": "another-agent", "agent_name": "cursor"},
    )
    assert fixture.plugin.status()["installed"] is False
    write_json(fixture.runtime_config_path, "{ malformed")
    with pytest.raises(ValueError, match="parse Elydora runtime config"):
        fixture.plugin.status()


def test_uninstall_uses_exact_ownership_for_all_events(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        existing_config={
            "version": 1,
            "hooks": {"sessionStart": [{"command": "keep"}]},
        },
    )
    fixture.install()
    settings = fixture.settings()
    for event, script in EVENTS:
        other = deepcopy(managed_handler(settings, event, script))
        other["command"] = other["command"].replace(AGENT_ID, "agent-10")
        settings["hooks"][event].append(other)
    settings["hooks"]["preToolUse"].append(
        {
            "command": "echo elydora agent-1 guard.py",
            "timeout": 10,
            "failClosed": True,
        }
    )
    write_json(fixture.config_path, settings)

    fixture.plugin.uninstall(AGENT_ID)

    remaining = fixture.settings()
    assert remaining["hooks"]["sessionStart"] == [{"command": "keep"}]
    assert len(remaining["hooks"]["preToolUse"]) == 2
    assert len(remaining["hooks"]["postToolUse"]) == 1
    assert len(remaining["hooks"]["postToolUseFailure"]) == 1
    assert "agent-10" in remaining["hooks"]["postToolUse"][0]["command"]


@pytest.mark.parametrize(
    "existing_config",
    [
        "{ malformed",
        "[]\n",
        '{"hooks":{}}\n',
        '{"version":2,"hooks":{}}\n',
        '{"version":1,"hooks":null}\n',
        '{"version":1,"hooks":{"preToolUse":null}}\n',
        '{"version":1,"hooks":{"preToolUse":[null]}}\n',
        '{"version":1,"version":1,"hooks":{}}\n',
        '{"version":1,"hooks":{},}\n',
    ],
)
def test_invalid_config_is_preserved_before_runtime_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    existing_config: str,
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        existing_config=existing_config,
    )

    with pytest.raises(ValueError):
        fixture.install()

    assert fixture.config_path.read_text(encoding="utf-8") == existing_config
    for path in (
        fixture.guard_path,
        fixture.hook_path,
        fixture.runtime_config_path,
        fixture.private_key_path,
    ):
        assert path.exists() is False


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("org_id", "", "org_id is required"),
        ("kid", "", "kid is required"),
        ("agent_name", "codex", "requires agent_name cursor"),
        ("private_key", "invalid", "canonical 32-byte base64url"),
        ("base_url", "relative", "absolute HTTP or HTTPS URL"),
        ("token", 42, "token must be a string"),
    ],
)
def test_invalid_install_values_fail_before_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    field: str,
    value: Any,
    message: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.config[field] = value  # type: ignore[assignment]

    with pytest.raises(ValueError, match=message):
        fixture.install()

    assert fixture.config_path.exists() is False
    assert list(fixture.agent_dir.iterdir()) == []


def test_install_creates_all_runtimes_and_rejects_unmanaged_guard(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    for path in (
        fixture.guard_path,
        fixture.hook_path,
        fixture.runtime_config_path,
        fixture.private_key_path,
    ):
        assert path.is_file()

    other = prepare_fixture(monkeypatch, tmp_path / "unmanaged")
    unmanaged = other.home_dir / "unmanaged-guard.py"
    unmanaged.write_text("pass\n", encoding="utf-8")
    other.config["guard_script_path"] = str(unmanaged)
    with pytest.raises(ValueError, match="managed agent directory"):
        other.install()
    assert other.config_path.exists() is False


def test_uninstall_removes_entirely_managed_config_and_preserves_absence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    fixture.plugin.uninstall(AGENT_ID)
    assert fixture.config_path.exists() is False
    fixture.plugin.uninstall(AGENT_ID)
    assert fixture.config_path.exists() is False

    source = '{"version":1,"hooks":{}}\n'
    fixture.config_path.write_text(source, encoding="utf-8")
    fixture.plugin.uninstall(AGENT_ID)
    assert fixture.config_path.read_text(encoding="utf-8") == source


def test_runtime_files_have_private_modes_on_posix(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    if os.name == "nt":
        pytest.skip("POSIX mode contract")
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    assert fixture.guard_path.stat().st_mode & 0o777 == 0o700
    assert fixture.hook_path.stat().st_mode & 0o777 == 0o700
    assert fixture.runtime_config_path.stat().st_mode & 0o777 == 0o600
    assert fixture.private_key_path.stat().st_mode & 0o777 == 0o600
