from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
from typing import Any

import pytest
from tomlkit import parse

from elydora import cli
from elydora.plugins import kimi
from elydora.plugins.base import InstallConfig
from elydora.plugins.registry import SUPPORTED_AGENTS


AGENT_ID = "agent-1"
MISSING = object()


@dataclass(frozen=True)
class KimiFixture:
    plugin: kimi.KimiPlugin
    config: InstallConfig
    home_dir: Path
    agent_dir: Path
    modern_path: Path
    legacy_path: Path
    guard_path: Path
    hook_path: Path
    runtime_config_path: Path
    private_key_path: Path


def write_optional(path: Path, value: object) -> None:
    if value is MISSING:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(value), encoding="utf-8")


def prepare_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    modern_config: object = MISSING,
    legacy_config: object = MISSING,
    legacy_installed: bool = True,
    explicit_kimi_home: bool = True,
    create_guard: bool = True,
) -> KimiFixture:
    home_dir = tmp_path / "home with spaces"
    agent_dir = home_dir / ".elydora" / AGENT_ID
    kimi_home = (
        home_dir / "custom kimi code"
        if explicit_kimi_home
        else home_dir / ".kimi-code"
    )
    modern_path = kimi_home / "config.toml"
    legacy_path = home_dir / ".kimi" / "config.toml"
    guard_path = agent_dir / "guard.py"
    hook_path = agent_dir / "hook.py"
    agent_dir.mkdir(parents=True)
    if create_guard:
        guard_path.write_text(
            "import sys\nsys.stdin.read()\n"
            "sys.stderr.write('Agent is frozen by Elydora.')\n"
            "raise SystemExit(2)\n",
            encoding="utf-8",
        )
    write_optional(modern_path, modern_config)
    write_optional(legacy_path, legacy_config)

    monkeypatch.setattr(kimi, "ELYDORA_DIR", str(agent_dir.parent))
    monkeypatch.setattr(kimi, "_home_dir", lambda: str(home_dir))
    monkeypatch.setattr(
        kimi.shutil,
        "which",
        lambda command: str(home_dir / "bin" / command)
        if legacy_installed and command == "kimi-cli"
        else None,
    )
    if explicit_kimi_home:
        monkeypatch.setenv("KIMI_CODE_HOME", str(kimi_home))
    else:
        monkeypatch.delenv("KIMI_CODE_HOME", raising=False)

    config: InstallConfig = {
        "agent_id": AGENT_ID,
        "agent_name": "kimi",
        "org_id": "org-1",
        "private_key": "test-key",
        "kid": "kid-1",
        "base_url": "https://api.elydora.test",
        "guard_script_path": str(guard_path),
    }
    return KimiFixture(
        plugin=kimi.KimiPlugin(),
        config=config,
        home_dir=home_dir,
        agent_dir=agent_dir,
        modern_path=modern_path,
        legacy_path=legacy_path,
        guard_path=guard_path,
        hook_path=hook_path,
        runtime_config_path=agent_dir / "config.json",
        private_key_path=agent_dir / "private.key",
    )


def parsed_hooks(path: Path) -> list[dict[str, Any]]:
    document = parse(path.read_text(encoding="utf-8"))
    value = document["hooks"].unwrap()
    assert isinstance(value, list)
    return value


def managed_hook(
    hooks: list[dict[str, Any]], event: str, script_name: str
) -> dict[str, Any]:
    return next(
        hook
        for hook in hooks
        if hook.get("event") == event and script_name in str(hook.get("command"))
    )


def assert_strict_hook(hook: dict[str, Any]) -> None:
    assert set(hook) == {"event", "command", "timeout"}
    assert hook["timeout"] == 10


def run_command(
    command: str, home_dir: Path, payload: dict[str, Any]
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        shell=True,
        capture_output=True,
        check=False,
        env={**os.environ, "HOME": str(home_dir), "USERPROFILE": str(home_dir)},
        input=json.dumps(payload),
        text=True,
    )


def test_kimi_is_registered_in_sdk_and_cli() -> None:
    assert SUPPORTED_AGENTS["kimi"] == {
        "name": "Kimi Code",
        "hook_event": "PreToolUse/PostToolUse",
        "config_path": "~/.kimi-code/config.toml",
    }
    assert cli.PLUGIN_MAP["kimi"] is kimi.KimiPlugin


def test_install_preserves_both_configs_and_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    modern = (
        '# modern user config\ndefault_model = "kimi-code/k3"\n\n'
        '[[hooks]]\nevent = "SessionStart"\ncommand = "existing-modern"\n'
        "timeout = 30 # keep modern hook\n"
    )
    legacy = (
        "# legacy user config\ntelemetry = false\n\n"
        '[[hooks]]\nevent = "SessionEnd"\ncommand = "existing-legacy"\n'
    )
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        modern_config=modern,
        legacy_config=legacy,
    )

    fixture.plugin.install(fixture.config)
    fixture.plugin.install(fixture.config)

    assert "Kimi Code and kimi-cli" in capsys.readouterr().out
    for path, comment, command in (
        (fixture.modern_path, "# modern user config", "existing-modern"),
        (fixture.legacy_path, "# legacy user config", "existing-legacy"),
    ):
        raw = path.read_text(encoding="utf-8")
        hooks = parsed_hooks(path)
        assert comment in raw
        assert command in raw
        assert len(hooks) == 3
        assert_strict_hook(managed_hook(hooks, "PreToolUse", "guard.py"))
        assert_strict_hook(managed_hook(hooks, "PostToolUse", "hook.py"))
    assert (fixture.home_dir / ".kimi-code" / "config.toml").exists() is False


def test_install_preserves_inline_hook_array_style(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    modern = (
        '# inline user hook\nhooks = [{ event = "SessionStart", '
        'command = "existing-inline" }] # keep array\n'
    )
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        modern_config=modern,
        legacy_installed=False,
    )

    fixture.plugin.install(fixture.config)
    fixture.plugin.install(fixture.config)

    raw = fixture.modern_path.read_text(encoding="utf-8")
    assert "# inline user hook" in raw
    assert "# keep array" in raw
    assert "hooks = [" in raw
    assert len(parsed_hooks(fixture.modern_path)) == 3


def test_modern_install_avoids_false_legacy_migration_source(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, legacy_installed=False)
    fixture.plugin.install(fixture.config)

    assert len(parsed_hooks(fixture.modern_path)) == 2
    assert fixture.legacy_path.exists() is False


def test_empty_home_override_uses_official_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        explicit_kimi_home=False,
        legacy_installed=False,
    )
    fixture.plugin.install(fixture.config)
    monkeypatch.setenv("KIMI_CODE_HOME", "")

    assert fixture.plugin.status()["installed"] is True


def test_legacy_install_avoids_premature_modern_migration_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, explicit_kimi_home=False)
    fixture.plugin.install(fixture.config)

    assert len(parsed_hooks(fixture.legacy_path)) == 2
    assert fixture.modern_path.exists() is False
    monkeypatch.setattr(kimi.shutil, "which", lambda command: None)
    assert fixture.plugin.status()["installed"] is True


def test_commands_block_and_forward_official_payload(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    capture_path = tmp_path / "captured-event.json"
    fixture.hook_path.write_text(
        "from pathlib import Path\nimport sys\n"
        f"Path({str(capture_path)!r}).write_text(sys.stdin.read(), encoding='utf-8')\n",
        encoding="utf-8",
    )
    hooks = parsed_hooks(fixture.modern_path)
    payload = {
        "hook_event_name": "PreToolUse",
        "session_id": "session-1",
        "cwd": str(fixture.home_dir),
        "tool_name": "Bash",
        "tool_input": {"command": "echo test"},
        "tool_call_id": "call-1",
    }

    guard = managed_hook(hooks, "PreToolUse", "guard.py")
    guard_result = run_command(guard["command"], fixture.home_dir, payload)
    assert guard_result.returncode == 2
    assert "Agent is frozen by Elydora" in guard_result.stderr

    payload["hook_event_name"] = "PostToolUse"
    payload["tool_output"] = {"output": "test"}
    audit = managed_hook(hooks, "PostToolUse", "hook.py")
    audit_result = run_command(audit["command"], fixture.home_dir, payload)
    assert audit_result.returncode == 0
    assert json.loads(capture_path.read_text(encoding="utf-8")) == payload


def test_status_accepts_either_contract_and_requires_both_scripts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    fixture.modern_path.unlink()
    assert fixture.plugin.status()["installed"] is True

    fixture.plugin.install(fixture.config)
    fixture.legacy_path.unlink()
    assert fixture.plugin.status()["installed"] is True

    fixture.guard_path.unlink()
    assert fixture.plugin.status()["installed"] is False


def test_uninstall_preserves_user_hooks_in_both_contracts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    user_hook = (
        "# user hook\n[[hooks]]\nevent = \"SessionStart\"\n"
        'command = "existing-command"\ntimeout = 30 # keep timeout\n'
    )
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        modern_config=user_hook,
        legacy_config=user_hook,
    )
    fixture.plugin.install(fixture.config)

    fixture.plugin.uninstall(AGENT_ID)

    for path in (fixture.modern_path, fixture.legacy_path):
        raw = path.read_text(encoding="utf-8")
        assert "# user hook" in raw
        assert "# keep timeout" in raw
        assert parsed_hooks(path) == [{
            "event": "SessionStart",
            "command": "existing-command",
            "timeout": 30,
        }]


def test_uninstall_removes_configs_created_by_elydora(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)

    fixture.plugin.uninstall(AGENT_ID)

    assert fixture.modern_path.exists() is False
    assert fixture.legacy_path.exists() is False


def test_install_parses_every_config_before_runtime_writes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    modern = '# untouched modern\ndefault_model = "kimi-code/k3"\n'
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        modern_config=modern,
        legacy_config="[malformed",
    )

    with pytest.raises(ValueError, match="parse kimi-cli legacy hooks config"):
        fixture.plugin.install(fixture.config)

    assert fixture.modern_path.read_text(encoding="utf-8") == modern
    assert fixture.legacy_path.read_text(encoding="utf-8") == "[malformed"
    assert fixture.hook_path.exists() is False
    assert fixture.runtime_config_path.exists() is False
    assert fixture.private_key_path.exists() is False


def test_install_rejects_invalid_hook_shape_without_writes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    modern = (
        '[[hooks]]\nevent = "PreToolUse"\ncommand = "existing-command"\n'
        'cwd = "/tmp"\n'
    )
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        modern_config=modern,
        legacy_installed=False,
    )

    with pytest.raises(ValueError, match='unsupported field "cwd"'):
        fixture.plugin.install(fixture.config)

    assert fixture.modern_path.read_text(encoding="utf-8") == modern
    assert fixture.hook_path.exists() is False
    assert fixture.runtime_config_path.exists() is False


def test_install_rejects_missing_guard_before_creating_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, create_guard=False)

    with pytest.raises(FileNotFoundError, match="guard runtime is missing"):
        fixture.plugin.install(fixture.config)

    assert fixture.modern_path.exists() is False
    assert fixture.legacy_path.exists() is False
    assert fixture.hook_path.exists() is False
    assert fixture.runtime_config_path.exists() is False


def test_status_surfaces_malformed_runtime_metadata(
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

    for directory in (fixture.modern_path.parent, fixture.legacy_path.parent):
        assert all(path.suffix != ".tmp" for path in directory.iterdir())
