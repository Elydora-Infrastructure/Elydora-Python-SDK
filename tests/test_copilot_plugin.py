from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest

from elydora import cli
from elydora.plugins import _transaction, copilot
from elydora.plugins.base import InstallConfig
from elydora.plugins.registry import SUPPORTED_AGENTS


AGENT_ID = "agent-1"
MISSING = object()


@dataclass(frozen=True)
class CopilotFixture:
    plugin: copilot.CopilotPlugin
    config: InstallConfig
    home_dir: Path
    copilot_home: Path
    project_dir: Path
    agent_dir: Path
    config_path: Path
    legacy_path: Path
    guard_path: Path
    hook_path: Path
    runtime_config_path: Path
    private_key_path: Path


def write_json_or_text(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    source = value if isinstance(value, str) else json.dumps(value, indent=2)
    path.write_text(source, encoding="utf-8")


def prepare_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    user_config: object = MISSING,
    legacy_config: object = MISSING,
    create_guard: bool = True,
) -> CopilotFixture:
    home_dir = tmp_path / "home with spaces"
    project_dir = tmp_path / "project with spaces"
    copilot_home = home_dir / "custom copilot"
    agent_dir = home_dir / ".elydora" / AGENT_ID
    config_path = copilot_home / "hooks" / "elydora-audit.json"
    legacy_path = project_dir / ".github" / "hooks" / "hooks.json"
    guard_path = agent_dir / "guard.py"
    hook_path = agent_dir / "hook.py"
    agent_dir.mkdir(parents=True)
    project_dir.mkdir(parents=True)
    if create_guard:
        guard_path.write_text(
            "import sys\nsys.stdin.read()\n"
            "sys.stderr.write('Agent is frozen by Elydora.')\n"
            "raise SystemExit(2)\n",
            encoding="utf-8",
        )
    if user_config is not MISSING:
        write_json_or_text(config_path, user_config)
    if legacy_config is not MISSING:
        write_json_or_text(legacy_path, legacy_config)

    monkeypatch.chdir(project_dir)
    monkeypatch.setattr(copilot, "ELYDORA_DIR", str(agent_dir.parent))
    monkeypatch.setattr(copilot, "_home_dir", lambda: str(home_dir), raising=False)
    monkeypatch.setenv("COPILOT_HOME", str(copilot_home))
    config: InstallConfig = {
        "agent_id": AGENT_ID,
        "agent_name": "copilot",
        "org_id": "org-1",
        "private_key": "test-key",
        "kid": "kid-1",
        "base_url": "https://api.elydora.test",
        "guard_script_path": str(guard_path),
    }
    return CopilotFixture(
        plugin=copilot.CopilotPlugin(),
        config=config,
        home_dir=home_dir,
        copilot_home=copilot_home,
        project_dir=project_dir,
        agent_dir=agent_dir,
        config_path=config_path,
        legacy_path=legacy_path,
        guard_path=guard_path,
        hook_path=hook_path,
        runtime_config_path=agent_dir / "config.json",
        private_key_path=agent_dir / "private.key",
    )


def managed_handler(
    settings: dict[str, Any], event: str, script_name: str
) -> dict[str, Any]:
    for handler in settings.get("hooks", {}).get(event, []):
        if script_name in str(handler.get("bash")):
            return handler
    raise AssertionError(f"managed {event} handler not found")


def assert_native_handler(handler: dict[str, Any]) -> None:
    assert set(handler) == {"type", "bash", "powershell", "timeoutSec"}
    assert handler["type"] == "command"
    assert handler["timeoutSec"] == 10
    assert Path(sys.executable).name in handler["bash"]
    assert handler["powershell"].startswith("& ")
    assert handler["powershell"].endswith("; exit $LASTEXITCODE")


def legacy_managed_config(
    fixture: CopilotFixture,
    extra_hooks: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "version": 1,
        "hooks": {
            "preToolUse": [{
                "type": "command",
                "bash": f'"{sys.executable}" {fixture.guard_path}',
                "powershell": f'"{sys.executable}" {fixture.guard_path}',
                "timeoutSec": 5,
            }],
            "postToolUse": [{
                "type": "command",
                "bash": str(fixture.hook_path),
                "powershell": str(fixture.hook_path),
                "timeoutSec": 5,
            }],
            **(extra_hooks or {}),
        },
    }


def run_hook(
    handler: dict[str, Any],
    home_dir: Path,
    payload: str,
) -> subprocess.CompletedProcess[str]:
    if os.name == "nt":
        command = [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            handler["powershell"],
        ]
    else:
        command = ["/bin/sh", "-c", handler["bash"]]
    return subprocess.run(
        command,
        capture_output=True,
        check=False,
        env={**os.environ, "HOME": str(home_dir), "USERPROFILE": str(home_dir)},
        input=payload,
        text=True,
    )


def test_copilot_is_registered_with_native_user_hooks() -> None:
    assert SUPPORTED_AGENTS["copilot"] == {
        "name": "GitHub Copilot CLI",
        "hook_event": "preToolUse/postToolUse",
        "config_path": "~/.copilot/hooks/elydora-audit.json",
    }
    assert cli.PLUGIN_MAP["copilot"] is copilot.CopilotPlugin


def test_install_preserves_user_hooks_migrates_legacy_and_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        user_config={
            "version": 1,
            "disableAllHooks": False,
            "hooks": {
                "sessionStart": [{"type": "command", "command": "user-session"}],
                "preToolUse": [{"type": "command", "command": "user-pre"}],
            },
        },
    )
    write_json_or_text(
        fixture.legacy_path,
        legacy_managed_config(fixture, {
            "notification": [{"type": "command", "command": "user-notification"}],
        }),
    )

    fixture.plugin.install(fixture.config)
    fixture.plugin.install(fixture.config)

    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    assert settings["disableAllHooks"] is False
    assert settings["hooks"]["sessionStart"] == [
        {"type": "command", "command": "user-session"}
    ]
    assert settings["hooks"]["preToolUse"][0] == {
        "type": "command",
        "command": "user-pre",
    }
    assert len(settings["hooks"]["preToolUse"]) == 2
    assert len(settings["hooks"]["postToolUse"]) == 1
    assert_native_handler(managed_handler(settings, "preToolUse", "guard.py"))
    assert_native_handler(managed_handler(settings, "postToolUse", "hook.py"))
    legacy = json.loads(fixture.legacy_path.read_text(encoding="utf-8"))
    assert legacy == {
        "version": 1,
        "hooks": {
            "notification": [{"type": "command", "command": "user-notification"}],
        },
    }
    assert fixture.runtime_config_path.is_file()
    assert fixture.private_key_path.read_text(encoding="utf-8") == "test-key"
    assert fixture.hook_path.is_file()


def test_migration_removes_legacy_file_owned_entirely_by_elydora(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    write_json_or_text(fixture.legacy_path, legacy_managed_config(fixture))

    fixture.plugin.install(fixture.config)

    assert fixture.legacy_path.exists() is False
    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    assert_native_handler(managed_handler(settings, "preToolUse", "guard.py"))


def test_commands_block_and_forward_native_payload_byte_for_byte(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    capture_path = tmp_path / "captured-event.json"
    fixture.hook_path.write_text(
        "from pathlib import Path\nimport sys\n"
        f"Path({str(capture_path)!r}).write_text(sys.stdin.read(), encoding='utf-8')\n",
        encoding="utf-8",
    )
    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    pre_payload = json.dumps({
        "sessionId": "session-1",
        "timestamp": 1,
        "cwd": str(fixture.project_dir),
        "toolName": "powershell",
        "toolArgs": {"command": "Get-ChildItem"},
    }, separators=(",", ":"))
    guard = managed_handler(settings, "preToolUse", "guard.py")
    guard_result = run_hook(guard, fixture.home_dir, pre_payload)
    assert guard_result.returncode == 2, guard_result.stderr
    assert "Agent is frozen by Elydora" in guard_result.stderr

    post_payload = json.dumps({
        "sessionId": "session-1",
        "timestamp": 2,
        "cwd": str(fixture.project_dir),
        "toolName": "powershell",
        "toolArgs": {"command": "Get-ChildItem"},
        "toolResult": {"output": "ok"},
    }, separators=(",", ":"))
    audit = managed_handler(settings, "postToolUse", "hook.py")
    audit_result = run_hook(audit, fixture.home_dir, post_payload)
    assert audit_result.returncode == 0, audit_result.stderr
    assert capture_path.read_text(encoding="utf-8") == post_payload


def test_empty_home_override_uses_official_default(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    monkeypatch.setenv("COPILOT_HOME", "")
    fixture.plugin.install(fixture.config)
    default_path = fixture.home_dir / ".copilot" / "hooks" / "elydora-audit.json"
    settings = json.loads(default_path.read_text(encoding="utf-8"))
    assert_native_handler(managed_handler(settings, "preToolUse", "guard.py"))
    assert str(default_path) in fixture.plugin.status()["details"]


def test_status_requires_complete_pair_and_valid_runtime_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    assert fixture.plugin.status()["installed"] is True
    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    del settings["hooks"]["postToolUse"]
    write_json_or_text(fixture.config_path, settings)
    assert fixture.plugin.status()["installed"] is False

    fixture.plugin.install(fixture.config)
    fixture.runtime_config_path.write_text("{ malformed", encoding="utf-8")
    with pytest.raises(ValueError, match="parse Elydora runtime config"):
        fixture.plugin.status()


def test_uninstall_removes_exact_ownership_and_preserves_user_entries(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        user_config={
            "version": 1,
            "hooks": {"notification": [{"type": "command", "command": "keep"}]},
        },
    )
    fixture.plugin.install(fixture.config)
    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    settings["hooks"]["preToolUse"].append({
        "type": "command",
        "bash": f"{sys.executable} {fixture.agent_dir.parent / 'agent-10' / 'guard.py'}",
        "powershell": "user-decoy",
        "timeoutSec": 10,
    })
    write_json_or_text(fixture.config_path, settings)

    fixture.plugin.uninstall(AGENT_ID.upper() if os.name == "nt" else AGENT_ID)

    remaining = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    assert remaining["hooks"]["notification"] == [
        {"type": "command", "command": "keep"}
    ]
    assert "postToolUse" not in remaining["hooks"]
    assert len(remaining["hooks"]["preToolUse"]) == 1
    assert "agent-10" in remaining["hooks"]["preToolUse"][0]["bash"]


def test_uninstall_leaves_absent_sources_absent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.uninstall(AGENT_ID)
    assert fixture.config_path.exists() is False
    assert fixture.legacy_path.exists() is False


@pytest.mark.parametrize(
    "existing",
    [
        "{ malformed",
        {"hooks": {}},
        {"version": 2, "hooks": {}},
        {"version": 1, "hooks": None},
        {"version": 1, "hooks": {"preToolUse": None}},
        {"version": 1, "hooks": {"preToolUse": [None]}},
    ],
)
def test_invalid_config_is_preserved_before_runtime_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    existing: object,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, user_config=existing)
    original = fixture.config_path.read_text(encoding="utf-8")
    with pytest.raises((ValueError, json.JSONDecodeError)):
        fixture.plugin.install(fixture.config)
    assert fixture.config_path.read_text(encoding="utf-8") == original
    assert fixture.runtime_config_path.exists() is False
    assert fixture.private_key_path.exists() is False
    assert fixture.hook_path.exists() is False


def test_missing_guard_is_rejected_before_creating_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, create_guard=False)
    with pytest.raises(FileNotFoundError, match="guard runtime is missing"):
        fixture.plugin.install(fixture.config)
    assert fixture.config_path.exists() is False
    assert fixture.runtime_config_path.exists() is False
    assert fixture.private_key_path.exists() is False
    assert fixture.hook_path.exists() is False


def test_transaction_rolls_back_every_file_after_commit_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        user_config={"version": 1, "hooks": {"notification": []}},
        legacy_config={"version": 1, "hooks": {"sessionStart": []}},
    )
    user_before = fixture.config_path.read_text(encoding="utf-8")
    legacy_before = fixture.legacy_path.read_text(encoding="utf-8")
    original_commit = _transaction._commit
    commits = 0

    def fail_after_first_commit(staged: Any) -> None:
        nonlocal commits
        original_commit(staged)
        commits += 1
        if commits == 1:
            raise OSError("injected commit failure")

    monkeypatch.setattr(_transaction, "_commit", fail_after_first_commit)
    with pytest.raises(OSError, match="injected commit failure"):
        fixture.plugin.install(fixture.config)
    assert fixture.config_path.read_text(encoding="utf-8") == user_before
    assert fixture.legacy_path.read_text(encoding="utf-8") == legacy_before
    assert fixture.runtime_config_path.exists() is False
    assert fixture.private_key_path.exists() is False
    assert fixture.hook_path.exists() is False


def test_atomic_writes_leave_no_transaction_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    for directory in (fixture.agent_dir, fixture.config_path.parent):
        assert all(
            path.suffix not in {".tmp", ".rollback"}
            for path in directory.iterdir()
        )
