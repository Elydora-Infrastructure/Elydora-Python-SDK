from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Mapping

import pytest

from elydora.plugins import cursor
from elydora.plugins.cursor import CursorPlugin
from elydora.plugins.hook_template import generate_guard_script
from elydora.plugins.registry import SUPPORTED_AGENTS


AGENT_ID = "agent-1"


@dataclass
class CursorFixture:
    home_dir: Path
    config_path: Path
    agent_dir: Path
    guard_path: Path
    hook_path: Path
    runtime_config_path: Path
    private_key_path: Path
    plugin: CursorPlugin
    config: dict[str, str]

    def install(self) -> None:
        self.plugin.install(self.config)


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    source = value if isinstance(value, str) else json.dumps(value, indent=2) + "\n"
    path.write_text(source, encoding="utf-8")


def _prepare_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    existing_config: object | None = None,
    create_guard: bool = True,
) -> CursorFixture:
    home_dir = tmp_path / "home with spaces and 'quote"
    config_path = home_dir / ".cursor" / "hooks.json"
    agent_dir = home_dir / ".elydora" / AGENT_ID
    guard_path = agent_dir / "guard.py"
    hook_path = agent_dir / "hook.py"
    runtime_config_path = agent_dir / "config.json"
    private_key_path = agent_dir / "private.key"
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("USERPROFILE", str(home_dir))
    monkeypatch.setattr(cursor, "SETTINGS_PATH", str(config_path), raising=False)
    monkeypatch.setattr(
        cursor,
        "ELYDORA_DIR",
        str(home_dir / ".elydora"),
        raising=False,
    )
    agent_dir.mkdir(parents=True)
    if create_guard:
        guard_path.write_text(
            generate_guard_script("cursor", AGENT_ID),
            encoding="utf-8",
        )
    if existing_config is not None:
        _write_json(config_path, existing_config)
    return CursorFixture(
        home_dir=home_dir,
        config_path=config_path,
        agent_dir=agent_dir,
        guard_path=guard_path,
        hook_path=hook_path,
        runtime_config_path=runtime_config_path,
        private_key_path=private_key_path,
        plugin=CursorPlugin(),
        config={
            "org_id": "org-1",
            "agent_id": AGENT_ID,
            "agent_name": "cursor",
            "private_key": "private-key",
            "kid": "key-1",
            "token": "token-1",
            "base_url": "https://api.elydora.com",
            "guard_script_path": str(guard_path),
        },
    )


def _managed_handler(settings: Mapping[str, Any], event: str, script: str) -> dict:
    handlers = settings["hooks"][event]
    return next(handler for handler in handlers if script in handler.get("command", ""))


def _assert_native_handler(handler: dict) -> None:
    assert set(handler) == {"command", "timeout", "failClosed"}
    assert handler["timeout"] == 10
    assert handler["failClosed"] is True
    assert sys.executable.lower() in handler["command"].lower()
    if os.name == "nt":
        assert handler["command"].startswith("& '")
        assert handler["command"].endswith("; exit $LASTEXITCODE")
    else:
        assert handler["command"].startswith("'")


def _run_handler(
    handler: Mapping[str, Any], payload: bytes,
    environment: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    if os.name == "nt":
        arguments = [
            "powershell.exe", "-NoProfile", "-NonInteractive",
            "-Command", handler["command"],
        ]
    else:
        arguments = ["/bin/sh", "-c", handler["command"]]
    return subprocess.run(
        arguments,
        input=payload,
        capture_output=True,
        check=False,
        env={**os.environ, **(environment or {})},
    )


def _symlink_or_skip(target: Path, link: Path) -> None:
    try:
        link.symlink_to(target)
    except OSError as error:
        pytest.skip(f"Symbolic links unavailable: {error}")


def test_cursor_registry_declares_both_native_events() -> None:
    assert SUPPORTED_AGENTS["cursor"] == {
        "name": "Cursor", "hook_event": "PreToolUse/PostToolUse",
        "config_path": "~/.cursor/hooks.json",
    }
def test_install_preserves_user_hooks_migrates_legacy_and_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    _write_json(
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

    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    assert settings["version"] == 1
    assert settings["description"] == "user-owned"
    assert settings["hooks"]["sessionStart"] == [{"command": "user-session"}]
    assert settings["hooks"]["preToolUse"][0] == {"command": "user-pre"}
    assert len(settings["hooks"]["preToolUse"]) == 2
    assert len(settings["hooks"]["postToolUse"]) == 1
    _assert_native_handler(_managed_handler(settings, "preToolUse", "guard.py"))
    _assert_native_handler(_managed_handler(settings, "postToolUse", "hook.py"))
def test_handlers_block_frozen_agent_and_forward_official_input_byte_for_byte(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    guard = _managed_handler(settings, "preToolUse", "guard.py")
    audit = _managed_handler(settings, "postToolUse", "hook.py")
    _write_json(
        fixture.agent_dir / "status-cache.json",
        {"status": "active", "cached_at": time.time()},
    )
    assert json.loads(_run_handler(guard, b"{}\n").stdout) == {"permission": "allow"}
    _write_json(
        fixture.agent_dir / "status-cache.json",
        {"status": "frozen", "cached_at": time.time()},
    )
    pre_payload = (
        json.dumps(
            {
                "conversation_id": "conversation-1",
                "generation_id": "generation-1",
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {"command": "Get-ChildItem"},
                "tool_use_id": "call-1",
                "cwd": str(tmp_path),
            },
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
    guard_result = _run_handler(guard, pre_payload)
    assert guard_result.returncode == 2
    assert b"frozen by Elydora" in guard_result.stderr
    capture_path = tmp_path / "captured-event.json"
    fixture.hook_path.write_text(
        "import os, pathlib, sys\n"
        "pathlib.Path(os.environ['ELYDORA_CAPTURE']).write_bytes(sys.stdin.buffer.read())\n"
        "print('{}')\n",
        encoding="utf-8",
    )
    post_payload = (
        json.dumps(
            {
                "conversation_id": "conversation-1",
                "generation_id": "generation-1",
                "hook_event_name": "postToolUse",
                "tool_name": "Shell",
                "tool_input": {"command": "Get-ChildItem"},
                "tool_output": '{"exitCode":0,"stdout":"ok"}',
                "tool_use_id": "call-1",
                "cwd": str(tmp_path),
                "duration": 42,
            },
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
    audit_result = _run_handler(audit, post_payload, {"ELYDORA_CAPTURE": str(capture_path)})
    assert audit_result.returncode == 0
    assert json.loads(audit_result.stdout) == {}
    assert capture_path.read_bytes() == post_payload


def test_status_requires_exact_pair_identity_and_physical_runtimes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    assert fixture.plugin.status()["installed"] is True

    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    _managed_handler(settings, "preToolUse", "guard.py")["failClosed"] = False
    _write_json(fixture.config_path, settings)
    assert fixture.plugin.status()["installed"] is False

    fixture.install()
    hook_source = fixture.hook_path.read_text(encoding="utf-8")
    fixture.hook_path.unlink()
    assert fixture.plugin.status()["installed"] is False
    fixture.hook_path.write_text(hook_source, encoding="utf-8")

    _write_json(
        fixture.runtime_config_path,
        {"agent_id": "another-agent", "agent_name": "cursor"},
    )
    assert fixture.plugin.status()["installed"] is False
    fixture.runtime_config_path.write_text("{ malformed", encoding="utf-8")
    with pytest.raises(ValueError, match="parse Elydora runtime config"):
        fixture.plugin.status()


def test_uninstall_uses_exact_ownership_and_preserves_user_entries(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(
        monkeypatch,
        tmp_path,
        existing_config={
            "version": 1,
            "hooks": {"sessionStart": [{"command": "keep"}]},
        },
    )
    fixture.install()
    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    other_guard = deepcopy(_managed_handler(settings, "preToolUse", "guard.py"))
    other_audit = deepcopy(_managed_handler(settings, "postToolUse", "hook.py"))
    other_guard["command"] = other_guard["command"].replace(AGENT_ID, "agent-10")
    other_audit["command"] = other_audit["command"].replace(AGENT_ID, "agent-10")
    settings["hooks"]["preToolUse"].extend(
        [
            other_guard,
            {
                "command": "echo elydora agent-1 guard.py",
                "timeout": 10,
                "failClosed": True,
            },
        ]
    )
    settings["hooks"]["postToolUse"].append(other_audit)
    _write_json(fixture.config_path, settings)

    fixture.plugin.uninstall(AGENT_ID)

    remaining = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    assert remaining["hooks"]["sessionStart"] == [{"command": "keep"}]
    assert len(remaining["hooks"]["preToolUse"]) == 2
    assert len(remaining["hooks"]["postToolUse"]) == 1
    assert "agent-10" in remaining["hooks"]["preToolUse"][0]["command"]


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
    fixture = _prepare_fixture(
        monkeypatch,
        tmp_path,
        existing_config=existing_config,
    )
    original_guard = fixture.guard_path.read_text(encoding="utf-8")

    with pytest.raises(ValueError):
        fixture.install()

    assert fixture.config_path.read_text(encoding="utf-8") == existing_config
    assert fixture.guard_path.read_text(encoding="utf-8") == original_guard
    assert fixture.hook_path.exists() is False
    assert fixture.runtime_config_path.exists() is False
    assert fixture.private_key_path.exists() is False


def test_install_creates_missing_guard_and_rejects_unmanaged_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path, create_guard=False)
    fixture.install()
    assert fixture.guard_path.is_file()

    fixture = _prepare_fixture(monkeypatch, tmp_path / "unmanaged", create_guard=False)
    unmanaged = fixture.home_dir / "unmanaged-guard.py"
    unmanaged.write_text("pass\n", encoding="utf-8")
    fixture.config["guard_script_path"] = str(unmanaged)
    with pytest.raises(ValueError, match="managed agent directory"):
        fixture.install()
    assert fixture.config_path.exists() is False


@pytest.mark.parametrize("runtime_name", ["guard.py", "hook.py"])
def test_symbolic_link_runtime_is_rejected_before_config_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    runtime_name: str,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    runtime_path = fixture.agent_dir / runtime_name
    target = fixture.home_dir / f"{runtime_name}.target"
    target.write_text("pass\n", encoding="utf-8")
    if runtime_path.exists():
        runtime_path.unlink()
    _symlink_or_skip(target, runtime_path)

    with pytest.raises(OSError, match="physical file"):
        fixture.install()

    assert fixture.config_path.exists() is False
    assert target.read_text(encoding="utf-8") == "pass\n"


def test_symbolic_link_config_is_rejected_and_target_is_preserved(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    target = fixture.home_dir / "cursor-hooks.target.json"
    original = '{"version":1,"hooks":{}}\n'
    target.write_text(original, encoding="utf-8")
    fixture.config_path.parent.mkdir(parents=True)
    _symlink_or_skip(target, fixture.config_path)

    with pytest.raises(OSError, match="physical file"):
        fixture.install()

    assert target.read_text(encoding="utf-8") == original
    assert fixture.config_path.is_symlink()


@pytest.mark.parametrize("runtime_name", ["config.json", "private.key", "guard.py", "hook.py"])
def test_status_rejects_symbolic_link_runtime_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    runtime_name: str,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    runtime_path = fixture.agent_dir / runtime_name
    contents = runtime_path.read_bytes()
    target = fixture.home_dir / f"status-{runtime_name}.target"
    target.write_bytes(contents)
    runtime_path.unlink()
    _symlink_or_skip(target, runtime_path)

    with pytest.raises(OSError, match="physical file"):
        fixture.plugin.status()


def test_uninstall_removes_entirely_managed_config_and_keeps_absence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    fixture.plugin.uninstall(AGENT_ID)
    assert fixture.config_path.exists() is False
    fixture.plugin.uninstall(AGENT_ID)
    assert fixture.config_path.exists() is False
    user_source = '{"version":1,"hooks":{}}\n'
    fixture.config_path.write_text(user_source, encoding="utf-8")
    fixture.plugin.uninstall(AGENT_ID)
    assert fixture.config_path.read_text(encoding="utf-8") == user_source


def test_transaction_rolls_back_runtime_files_when_config_commit_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(
        monkeypatch,
        tmp_path,
        existing_config={"version": 1, "hooks": {"sessionStart": []}},
        create_guard=False,
    )
    original = fixture.config_path.read_text(encoding="utf-8")
    real_replace = os.replace
    failed = False
    def fail_config_once(source: str, destination: str) -> None:
        nonlocal failed
        if os.path.abspath(destination) == str(fixture.config_path) and not failed:
            failed = True
            raise OSError("injected config commit failure")
        real_replace(source, destination)
    monkeypatch.setattr(os, "replace", fail_config_once)
    with pytest.raises(OSError, match="injected config commit failure"):
        fixture.install()
    assert fixture.config_path.read_text(encoding="utf-8") == original
    assert fixture.guard_path.exists() is False
    assert fixture.hook_path.exists() is False
    assert fixture.runtime_config_path.exists() is False
    assert fixture.private_key_path.exists() is False
    assert not list(fixture.home_dir.rglob("*.tmp"))
    assert not list(fixture.home_dir.rglob("*.rollback"))


def test_atomic_config_write_detects_concurrent_source_change(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from elydora.plugins._transaction import write_changes
    from elydora.plugins.cursor_contract import render_document
    from elydora.plugins.cursor_io import read_document, rendered_change

    fixture = _prepare_fixture(
        monkeypatch,
        tmp_path,
        existing_config={
            "version": 1,
            "hooks": {"sessionStart": [{"command": "original"}]},
        },
    )
    document = read_document()
    rendered = render_document(document, {})
    change = rendered_change(rendered)
    assert change is not None
    concurrent = '{"version":1,"hooks":{"sessionStart":[]}}\n'
    fixture.config_path.write_text(concurrent, encoding="utf-8")

    with pytest.raises(OSError, match="changed during installation"):
        write_changes([change], "Update Cursor hooks")

    assert fixture.config_path.read_text(encoding="utf-8") == concurrent
    assert not list(fixture.config_path.parent.glob("*.tmp"))
