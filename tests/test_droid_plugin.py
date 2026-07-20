from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time
from typing import Any

import pytest

from elydora import cli
from elydora.plugins import droid
from elydora.plugins.registry import SUPPORTED_AGENTS

from droid_support import (
    AGENT_ID,
    VALID_PRIVATE_KEY,
    ApiServer,
    DroidFixture,
    assert_native_group,
    assert_no_transaction_files,
    load_jsonc,
    managed_group,
    managed_handler,
    read_raw,
    run_hook,
    snapshot,
    write_json,
)


def _current_hooks(path: Path) -> dict[str, Any]:
    return load_jsonc(path)["hooks"]


def test_droid_is_registered_in_the_sdk_and_cli() -> None:
    assert SUPPORTED_AGENTS["droid"] == {
        "name": "Factory Droid",
        "hook_event": "PreToolUse/PostToolUse",
        "config_path": "~/.factory/hooks.json",
    }
    assert cli.PLUGIN_MAP["droid"] is droid.DroidPlugin


def test_install_writes_current_container_and_complete_runtime(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture = DroidFixture(monkeypatch, tmp_path)
    fixture.install()
    output = capsys.readouterr().out
    source = fixture.root_path.read_text(encoding="utf-8")
    assert source.startswith("// Managed by Elydora\n")
    hooks = _current_hooks(fixture.root_path)
    assert_native_group(managed_group(hooks, "PreToolUse", "guard.py"))
    assert_native_group(managed_group(hooks, "PostToolUse", "hook.py"))
    guard = managed_handler(hooks, "PreToolUse", "guard.py")
    assert guard is not None
    if os.name == "nt":
        assert guard["command"].startswith("& '")
        assert guard["command"].endswith("; exit $LASTEXITCODE")
    runtime = json.loads(fixture.runtime_config.read_text(encoding="utf-8"))
    assert runtime == {
        "org_id": "org-1",
        "agent_id": AGENT_ID,
        "kid": "kid-1",
        "base_url": "http://127.0.0.1:9",
        "agent_name": "droid",
        "token": "token-1",
    }
    assert fixture.private_key_path.read_text(encoding="utf-8") == VALID_PRIVATE_KEY
    assert "AGENT_NAME = 'droid'" in fixture.guard_path.read_text(encoding="utf-8")
    assert "NATIVE_PAYLOAD = True" in fixture.audit_path.read_text(encoding="utf-8")
    assert "run /hooks" in output

    paths = (
        fixture.root_path,
        fixture.guard_path,
        fixture.audit_path,
        fixture.runtime_config,
        fixture.private_key_path,
    )
    before = snapshot(paths)
    fixture.install()
    assert snapshot(paths) == before
    assert_no_transaction_files(tmp_path)


@pytest.mark.skipif(os.name != "nt", reason="Windows migration contract")
def test_install_migrates_legacy_windows_commands(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = DroidFixture(monkeypatch, tmp_path, root_config={"hooks": {}})

    def group(script: Path) -> dict[str, Any]:
        return {
            "matcher": "*",
            "hooks": [{
                "type": "command",
                "command": f'"{sys.executable}" "{script}"',
                "timeout": 10,
            }],
        }

    write_json(fixture.root_path, {
        "hooks": {
            "PreToolUse": [group(fixture.guard_path)],
            "PostToolUse": [group(fixture.audit_path)],
        },
    })
    fixture.install()
    hooks = _current_hooks(fixture.root_path)
    assert len(hooks["PreToolUse"]) == 1
    assert len(hooks["PostToolUse"]) == 1
    assert hooks["PreToolUse"][0]["hooks"][0]["command"].startswith("& '")


def test_root_hook_file_has_whole_source_precedence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = """{
  // active root source
  "hooks": {
    "PreToolUse": [
      { "matcher": "Read", "hooks": [{ "type": "command", "command": "root-user" }] }
    ]
  }
}
"""
    settings = """{
  // inactive settings source
  "theme": "dark",
  "hooks": {
    "PostToolUse": [
      { "matcher": "Edit", "hooks": [{ "type": "command", "command": "settings-user" }] }
    ]
  }
}
"""
    fixture = DroidFixture(
        monkeypatch,
        tmp_path,
        root_config=root,
        settings=settings,
    )
    fixture.install()
    root_source = fixture.root_path.read_text(encoding="utf-8")
    hooks = _current_hooks(fixture.root_path)
    assert "active root source" in root_source
    assert hooks["PreToolUse"][0]["hooks"][0]["command"] == "root-user"
    assert_native_group(managed_group(hooks, "PreToolUse", "guard.py"))
    assert_native_group(managed_group(hooks, "PostToolUse", "hook.py"))
    assert fixture.settings_path.read_text(encoding="utf-8") == settings


def test_settings_and_local_settings_follow_source_precedence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = '{\r\n\t"theme": "dark",\r\n\t"hooks": {}\r\n}\r\n'
    fixture = DroidFixture(monkeypatch, tmp_path / "base", settings=settings)
    fixture.install()
    assert not fixture.root_path.exists()
    source = read_raw(fixture.settings_path)
    hooks = load_jsonc(fixture.settings_path)["hooks"]
    assert '\r\n\t\t"PreToolUse"' in source
    assert_native_group(managed_group(hooks, "PreToolUse", "guard.py"))
    assert_native_group(managed_group(hooks, "PostToolUse", "hook.py"))

    local_fixture = DroidFixture(
        monkeypatch,
        tmp_path / "local",
        settings={"hooks": {"Notification": []}},
        local_settings={"hooks": {"SessionStart": []}},
    )
    base_before = local_fixture.settings_path.read_text(encoding="utf-8")
    local_fixture.install()
    assert local_fixture.settings_path.read_text(encoding="utf-8") == base_before
    local_hooks = load_jsonc(local_fixture.local_settings_path)["hooks"]
    assert_native_group(managed_group(local_hooks, "PreToolUse", "guard.py"))
    assert_native_group(managed_group(local_hooks, "PostToolUse", "hook.py"))


def test_legacy_hook_file_stays_active_until_factory_migrates_it(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = DroidFixture(
        monkeypatch,
        tmp_path,
        legacy_config={
            "PreToolUse": [{
                "matcher": "Read",
                "hooks": [{"type": "command", "command": "legacy-user"}],
            }],
        },
        settings={"hooks": {"PostToolUse": []}},
    )
    settings_before = fixture.settings_path.read_text(encoding="utf-8")
    fixture.install()
    assert not fixture.root_path.exists()
    legacy = load_jsonc(fixture.legacy_path)
    assert_native_group(managed_group(legacy, "PreToolUse", "guard.py"))
    assert_native_group(managed_group(legacy, "PostToolUse", "hook.py"))
    assert fixture.settings_path.read_text(encoding="utf-8") == settings_before


def test_guard_blocks_and_audit_preserves_native_payload(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    api = ApiServer()
    try:
        fixture = DroidFixture(
            monkeypatch,
            tmp_path,
            base_url=api.base_url,
        )
        fixture.install()
        hooks = _current_hooks(fixture.root_path)
        guard = managed_handler(hooks, "PreToolUse", "guard.py")
        audit = managed_handler(hooks, "PostToolUse", "hook.py")
        assert guard is not None and audit is not None
        write_json(fixture.agent_dir / "status-cache.json", {
            "status": "frozen",
            "cached_at": time.time(),
        })
        pre_payload = {
            "session_id": "session-1",
            "transcript_path": str(fixture.home_dir / "transcript.jsonl"),
            "cwd": str(fixture.workspace_dir),
            "permission_mode": "auto-high",
            "hook_event_name": "PreToolUse",
            "tool_name": "Execute",
            "tool_input": {"command": "echo test"},
        }
        guard_result = run_hook(guard["command"], json.dumps(pre_payload))
        assert guard_result.returncode == 2
        assert 'Agent "droid" is frozen' in guard_result.stderr

        post_payload = {
            **pre_payload,
            "hook_event_name": "PostToolUse",
            "tool_response": {"output": "test", "success": True},
        }
        audit_result = run_hook(audit["command"], json.dumps(post_payload))
        assert audit_result.returncode == 0, audit_result.stderr
        request = next(item for item in api.requests if item[0] == "POST")
        operation = json.loads(request[2])
        assert operation["payload"] == post_payload
        assert operation["subject"] == {"session_id": "session-1"}
        assert operation["action"] == {"tool": "Execute"}
    finally:
        api.close()


def test_status_requires_exact_hooks_and_runtime_sources(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = DroidFixture(monkeypatch, tmp_path)
    fixture.install()
    assert fixture.plugin.status() == {
        "installed": True,
        "agent": "droid",
        "details": f"Config: {fixture.root_path}",
    }
    fixture.audit_path.write_text("tampered\n", encoding="utf-8")
    status = fixture.plugin.status()
    assert status["installed"] is False
    assert "incomplete" in status["details"]


@pytest.mark.parametrize(
    ("mutation", "pattern"),
    [
        ("config", "parse Elydora runtime config"),
        ("key", "canonical 32-byte"),
    ],
)
def test_status_surfaces_malformed_runtime_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mutation: str,
    pattern: str,
) -> None:
    fixture = DroidFixture(monkeypatch, tmp_path)
    fixture.install()
    target = fixture.runtime_config if mutation == "config" else fixture.private_key_path
    target.write_text("{ malformed" if mutation == "config" else "invalid", encoding="utf-8")
    with pytest.raises(ValueError, match=pattern):
        fixture.plugin.status()


@pytest.mark.parametrize(
    ("root_config", "legacy_config", "settings", "local_settings", "pattern"),
    [
        ("{ malformed", None, None, None, "parse Factory Droid hooks"),
        ([], None, None, None, "JSON object"),
        ('{"hooks":{"PreToolUse":[],"PreToolUse":[]}}', None, None, None, "duplicate"),
        ({"hooks": {"PreToolUse": None}}, None, None, None, "must be an array"),
        ({"hooks": {"PreToolUse": [None]}}, None, None, None, "must be an object"),
        (
            {"hooks": {"PreToolUse": [{"matcher": "[", "hooks": []}]}},
            None,
            None,
            None,
            "regular expression",
        ),
        (
            {"hooks": {"PreToolUse": [{"hooks": [{
                "type": "command",
                "command": "",
            }]}]}},
            None,
            None,
            None,
            "non-empty",
        ),
        (
            {"hooks": {"PreToolUse": [{"hooks": [{
                "type": "command",
                "command": "user",
                "timeout": 0,
            }]}]}},
            None,
            None,
            None,
            "positive",
        ),
        (None, "{ malformed", None, None, "legacy hooks"),
        (None, None, {"hooks": None}, None, "JSON object"),
        (None, None, None, {"hooksDisabled": "yes"}, "boolean"),
    ],
)
def test_install_preserves_malformed_sources_before_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    root_config: Any,
    legacy_config: Any,
    settings: Any,
    local_settings: Any,
    pattern: str,
) -> None:
    fixture = DroidFixture(
        monkeypatch,
        tmp_path,
        root_config=root_config,
        legacy_config=legacy_config,
        settings=settings,
        local_settings=local_settings,
    )
    originals = {
        path: path.read_text(encoding="utf-8")
        for path in (
            fixture.root_path,
            fixture.legacy_path,
            fixture.settings_path,
            fixture.local_settings_path,
        )
        if path.exists()
    }
    with pytest.raises((ValueError, OSError), match=pattern):
        fixture.install()
    for path, source in originals.items():
        assert path.read_text(encoding="utf-8") == source
    assert not fixture.runtime_config.exists()
    assert not fixture.root_path.exists() or fixture.root_path in originals


def test_unknown_events_and_extension_fields_remain_valid(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = DroidFixture(
        monkeypatch,
        tmp_path,
        root_config={
            "hooks": {
                "FutureFactoryEvent": [{
                    "matcher": ".*",
                    "commandRegex": "^factory",
                    "owner": "user",
                    "hooks": [{
                        "type": "command",
                        "command": "user-command",
                        "timeout": 1,
                        "future": True,
                    }],
                }],
            },
        },
    )
    fixture.install()
    current = load_jsonc(fixture.root_path)
    assert current["hooks"]["FutureFactoryEvent"][0]["owner"] == "user"


def test_uninstall_preserves_users_and_exact_ownership(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = DroidFixture(
        monkeypatch,
        tmp_path,
        root_config={"hooks": {"Notification": []}},
    )
    fixture.install()
    root = load_jsonc(fixture.root_path)
    group = managed_group(root["hooks"], "PreToolUse", "guard.py")
    assert group is not None
    command = group["hooks"][0]["command"]
    group["hooks"].append({"type": "command", "command": "user-command"})
    root["hooks"]["PreToolUse"].extend([
        {
            "matcher": "*",
            "hooks": [{
                "type": "command",
                "command": command.replace("guard.py", "guard.py.backup"),
                "timeout": 10,
            }],
        },
        {
            "matcher": "*",
            "hooks": [{
                "type": "command",
                "command": command.replace("agent-1", "agent-10"),
                "timeout": 10,
            }],
        },
    ])
    write_json(fixture.root_path, root)
    fixture.plugin.uninstall("AGENT-1" if os.name == "nt" else AGENT_ID)
    remaining = load_jsonc(fixture.root_path)
    raw = json.dumps(remaining)
    assert "user-command" in raw
    assert "guard.py.backup" in raw
    assert "agent-10" in raw
    assert "PostToolUse" not in remaining["hooks"]


def test_uninstall_removes_owned_empty_file_and_keeps_absence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = DroidFixture(monkeypatch, tmp_path / "installed")
    fixture.install()
    fixture.plugin.uninstall(AGENT_ID)
    assert not fixture.root_path.exists()

    empty = DroidFixture(monkeypatch, tmp_path / "empty")
    empty.plugin.uninstall(AGENT_ID)
    assert not empty.root_path.exists()


@pytest.mark.parametrize("kind", ["factory", "hook", "runtime"])
def test_install_rejects_linked_paths_before_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    kind: str,
) -> None:
    fixture = DroidFixture(monkeypatch, tmp_path)
    target = tmp_path / f"{kind}-target"
    target.mkdir()
    try:
        if kind == "factory":
            fixture.home_dir.mkdir(parents=True)
            fixture.factory_dir.symlink_to(target, target_is_directory=True)
        elif kind == "hook":
            fixture.factory_dir.mkdir(parents=True)
            target_file = target / "hooks.json"
            write_json(target_file, {"hooks": {}})
            fixture.root_path.symlink_to(target_file)
        else:
            fixture.home_dir.mkdir(parents=True)
            (fixture.home_dir / ".elydora").symlink_to(
                target,
                target_is_directory=True,
            )
    except OSError as error:
        pytest.skip(f"Symbolic links unavailable: {error}")
    with pytest.raises(OSError, match="physical (directory|file)"):
        fixture.install()
