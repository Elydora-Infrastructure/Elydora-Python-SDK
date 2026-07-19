from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import subprocess  # nosec B404
from typing import Any, Dict, Optional

import pytest

from elydora import cli
from elydora.plugins import droid, droid_io, droid_jsonc
from elydora.plugins.base import InstallConfig
from elydora.plugins.registry import SUPPORTED_AGENTS


AGENT_ID = "agent-1"
JsonObject = Dict[str, Any]


class DroidFixture:
    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        *,
        hooks: Any = None,
        legacy_hooks: Any = None,
        settings: Any = None,
        create_guard: bool = True,
    ) -> None:
        self.home_dir = tmp_path / "home with spaces and 'quote"
        self.workspace_dir = self.home_dir / "workspace"
        self.factory_dir = self.home_dir / ".factory"
        self.config_path = self.factory_dir / "hooks.json"
        self.legacy_path = self.factory_dir / "hooks" / "hooks.json"
        self.settings_path = self.factory_dir / "settings.json"
        self.agent_dir = self.home_dir / ".elydora" / AGENT_ID
        self.guard_path = self.agent_dir / "guard.py"
        self.audit_path = self.agent_dir / "hook.py"
        self.runtime_config = self.agent_dir / "config.json"
        self.private_key_path = self.agent_dir / "private.key"
        self.workspace_dir.mkdir(parents=True)
        self.agent_dir.mkdir(parents=True)
        if create_guard:
            self.guard_path.write_text(
                "import sys\nsys.stdin.read()\n"
                "sys.stderr.write('Agent is frozen by Elydora.\\n')\n"
                "raise SystemExit(2)\n",
                encoding="utf-8",
            )
        self._write(self.config_path, hooks)
        self._write(self.legacy_path, legacy_hooks)
        self._write(self.settings_path, settings)
        monkeypatch.setenv("HOME", str(self.home_dir))
        monkeypatch.setenv("USERPROFILE", str(self.home_dir))
        private_key = base64.urlsafe_b64encode(bytes([1]) * 32).rstrip(b"=").decode()
        self.config: InstallConfig = {
            "agent_id": AGENT_ID,
            "agent_name": "droid",
            "org_id": "org-1",
            "private_key": private_key,
            "kid": "kid-1",
            "base_url": "https://api.elydora.test",
            "guard_script_path": str(self.guard_path),
        }
        self.plugin = droid.DroidPlugin()

    @staticmethod
    def _write(path: Path, value: Any) -> None:
        if value is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = value if isinstance(value, str) else json.dumps(value, indent=2) + "\n"
        with open(path, "w", encoding="utf-8", newline="") as file:
            file.write(raw)

    def install(self) -> None:
        self.plugin.install(self.config)


def _load(path: Path) -> JsonObject:
    value = droid_jsonc.parse_jsonc(path.read_text(encoding="utf-8"), str(path))
    assert isinstance(value, dict)
    return value


def _managed_handler(groups: Any, script_path: Path) -> Optional[JsonObject]:
    for group in groups or []:
        for handler in group["hooks"]:
            if str(script_path) in handler.get("command", ""):
                return handler
    return None


def _run_command(command: str, payload: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # nosec B602
        command,
        shell=True,
        input=payload,
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )


def test_droid_is_registered_in_the_sdk_and_cli() -> None:
    assert SUPPORTED_AGENTS["droid"] == {
        "name": "Factory Droid",
        "hook_event": "PreToolUse/PostToolUse",
        "config_path": "~/.factory/hooks.json",
    }
    assert cli.PLUGIN_MAP["droid"] is droid.DroidPlugin


def test_install_preserves_jsonc_and_uses_per_event_precedence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    hooks = """{
  // root hook source
  "PreToolUse": [
    // keep root group comment
    { "matcher": "Read", "hooks": [{ "type": "command", "command": "root-user" }] }
  ],
  "Notification": []
}
"""
    settings = """{
  // general setting
  "theme": "dark",
  "hooks": {
    // settings fallback event
    "PostToolUse": [
      // keep settings group comment
      { "matcher": "Edit", "hooks": [{ "type": "command", "command": "settings-user" }] }
    ],
    "showHookOutput": true,
  },
}
"""
    fixture = DroidFixture(monkeypatch, tmp_path, hooks=hooks, settings=settings)
    fixture.install()
    fixture.install()
    output = capsys.readouterr().out
    root_raw = fixture.config_path.read_text(encoding="utf-8")
    settings_raw = fixture.settings_path.read_text(encoding="utf-8")
    root = _load(fixture.config_path)
    user_settings = _load(fixture.settings_path)
    assert "root hook source" in root_raw
    assert "keep root group comment" in root_raw
    assert "general setting" in settings_raw
    assert "settings fallback event" in settings_raw
    assert "keep settings group comment" in settings_raw
    assert len(root["PreToolUse"]) == 2
    assert root["PreToolUse"][0]["hooks"][0]["command"] == "root-user"
    assert "PostToolUse" not in root
    assert user_settings["theme"] == "dark"
    assert len(user_settings["hooks"]["PostToolUse"]) == 2
    assert "PreToolUse" not in user_settings["hooks"]
    for groups, path in (
        (root["PreToolUse"], fixture.guard_path),
        (user_settings["hooks"]["PostToolUse"], fixture.audit_path),
    ):
        handler = _managed_handler(groups, path)
        assert handler is not None
        assert sorted(handler) == ["command", "timeout", "type"]
        assert handler["type"] == "command"
        assert handler["timeout"] == 10
    assert "run /hooks" in output
    assert not (fixture.workspace_dir / ".factory" / "hooks.json").exists()


def test_install_keeps_active_legacy_source(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = DroidFixture(
        monkeypatch,
        tmp_path,
        legacy_hooks={"PreToolUse": []},
        settings={"hooks": {"PostToolUse": []}},
    )
    fixture.install()
    assert not fixture.config_path.exists()
    assert _managed_handler(_load(fixture.legacy_path)["PreToolUse"], fixture.guard_path)
    assert _managed_handler(
        _load(fixture.settings_path)["hooks"]["PostToolUse"],
        fixture.audit_path,
    )


def test_install_reuses_settings_container_and_formatting(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = '{\r\n\t"owner": "user",\r\n\t"hooks": {}\r\n}\r\n'
    fixture = DroidFixture(monkeypatch, tmp_path, settings=source)
    fixture.install()
    assert not fixture.config_path.exists()
    with open(fixture.settings_path, "r", encoding="utf-8", newline="") as file:
        raw = file.read()
    settings = _load(fixture.settings_path)
    assert "\r\n\t\t\"PreToolUse\"" in raw
    assert "\r\n\t\t\"PostToolUse\"" in raw
    assert settings["owner"] == "user"


def test_commands_block_and_forward_official_input_byte_for_byte(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = DroidFixture(monkeypatch, tmp_path)
    fixture.install()
    capture_path = tmp_path / "captured-event.json"
    fixture.audit_path.write_text(
        "import pathlib, sys\n"
        f"pathlib.Path({str(capture_path)!r}).write_bytes(sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    root = _load(fixture.config_path)
    guard = _managed_handler(root["PreToolUse"], fixture.guard_path)
    audit = _managed_handler(root["PostToolUse"], fixture.audit_path)
    assert guard is not None and audit is not None
    pre_payload = json.dumps({
        "session_id": "session-1",
        "transcript_path": str(tmp_path / "transcript.jsonl"),
        "cwd": str(fixture.workspace_dir),
        "permission_mode": "auto-high",
        "hook_event_name": "PreToolUse",
        "tool_name": "Execute",
        "tool_input": {"command": "echo test"},
    })
    guard_result = _run_command(guard["command"], pre_payload)
    assert guard_result.returncode == 2
    assert "Agent is frozen by Elydora" in guard_result.stderr
    post_payload = json.dumps({
        **json.loads(pre_payload),
        "hook_event_name": "PostToolUse",
        "tool_response": {"output": "test", "success": True},
    })
    audit_result = _run_command(audit["command"], post_payload)
    assert audit_result.returncode == 0, audit_result.stderr
    assert capture_path.read_text(encoding="utf-8") == post_payload


def test_status_requires_enabled_pair_and_runtime_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = DroidFixture(
        monkeypatch,
        tmp_path,
        hooks={"PreToolUse": []},
        settings={"hooks": {"PostToolUse": []}},
    )
    fixture.install()
    assert fixture.plugin.status()["installed"] is True
    fixture.audit_path.unlink()
    assert fixture.plugin.status()["installed"] is False
    root = _load(fixture.config_path)
    root["hooksDisabled"] = True
    fixture.config_path.write_text(json.dumps(root), encoding="utf-8")
    status = fixture.plugin.status()
    assert status["installed"] is False
    assert "disabled" in status["details"].lower()


def test_uninstall_preserves_user_sources_and_exact_ownership(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    hooks = '{\n  // keep root comment\n  "PreToolUse": []\n}\n'
    settings = (
        '{\n  "theme": "dark",\n  "hooks": {\n'
        '    // keep settings comment\n    "PostToolUse": []\n  }\n}\n'
    )
    fixture = DroidFixture(monkeypatch, tmp_path, hooks=hooks, settings=settings)
    fixture.install()
    fixture.plugin.uninstall("agent-10")
    assert _managed_handler(_load(fixture.config_path)["PreToolUse"], fixture.guard_path)
    uninstall_id = "AGENT-1" if os.name == "nt" else AGENT_ID
    fixture.plugin.uninstall(uninstall_id)
    root_raw = fixture.config_path.read_text(encoding="utf-8")
    settings_raw = fixture.settings_path.read_text(encoding="utf-8")
    assert "keep root comment" in root_raw
    assert "keep settings comment" in settings_raw
    assert _load(fixture.config_path)["PreToolUse"] == []
    current_settings = _load(fixture.settings_path)
    assert current_settings["hooks"]["PostToolUse"] == []
    assert current_settings["theme"] == "dark"


def test_uninstall_deletes_only_an_owned_empty_hook_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = DroidFixture(monkeypatch, tmp_path)
    fixture.install()
    assert fixture.config_path.read_text(encoding="utf-8").startswith(
        "// Managed by Elydora"
    )
    fixture.plugin.uninstall(AGENT_ID)
    assert not fixture.config_path.exists()


def test_uninstall_preserves_mixed_groups_and_lookalikes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = DroidFixture(monkeypatch, tmp_path)
    fixture.install()
    root = _load(fixture.config_path)
    group = next(
        item for item in root["PreToolUse"]
        if _managed_handler([item], fixture.guard_path)
    )
    command = group["hooks"][0]["command"]
    group["hooks"].append({"type": "command", "command": "user-command"})
    group["owner"] = "user"
    root["PreToolUse"].extend([
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
    fixture.config_path.write_text(json.dumps(root, indent=2) + "\n", encoding="utf-8")
    fixture.plugin.uninstall(AGENT_ID)
    remaining = _load(fixture.config_path)
    raw = json.dumps(remaining)
    assert "user-command" in raw
    assert "guard.py.backup" in raw
    assert "agent-10" in raw
    assert remaining["PostToolUse"] == []


@pytest.mark.parametrize(
    ("hooks", "legacy", "settings", "pattern"),
    [
        ("{ malformed", None, None, "parse Factory Droid hooks"),
        ("[]", None, None, "JSON object"),
        ('{ "PreToolUse": [], "PreToolUse": [] }', None, None, "duplicate"),
        ({"PreToolUse": None}, None, None, "must be an array"),
        ({"PreToolUse": [None]}, None, None, "must be an object"),
        ({"PreToolUse": [{"matcher": "[", "hooks": []}]}, None, None, "regular expression"),
        ({"PreToolUse": [{"hooks": [{"type": "command", "command": 1}]}]}, None, None, "string"),
        (None, "{ malformed", None, "legacy hooks"),
        ({"PreToolUse": []}, None, "{ malformed", "settings"),
        (None, None, {"hooks": None}, "must contain a JSON object"),
    ],
)
def test_install_preserves_every_malformed_source_before_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    hooks: Any,
    legacy: Any,
    settings: Any,
    pattern: str,
) -> None:
    fixture = DroidFixture(
        monkeypatch,
        tmp_path,
        hooks=hooks,
        legacy_hooks=legacy,
        settings=settings,
    )
    targets = [
        (fixture.config_path, hooks),
        (fixture.legacy_path, legacy),
        (fixture.settings_path, settings),
    ]
    originals = {
        path: path.read_text(encoding="utf-8") for path, value in targets if value is not None
    }
    with pytest.raises((ValueError, RuntimeError), match=pattern):
        fixture.install()
    for path, raw in originals.items():
        assert path.read_text(encoding="utf-8") == raw
    assert not fixture.audit_path.exists()
    assert not fixture.runtime_config.exists()
    assert not fixture.private_key_path.exists()


def test_install_rejects_missing_guard_before_creating_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = DroidFixture(monkeypatch, tmp_path, create_guard=False)
    with pytest.raises(FileNotFoundError, match="guard runtime is missing"):
        fixture.install()
    assert not fixture.config_path.exists()
    assert not fixture.audit_path.exists()
    assert not fixture.runtime_config.exists()


def test_transaction_rolls_back_all_files_and_cleans_staging(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = DroidFixture(
        monkeypatch,
        tmp_path,
        hooks={"PreToolUse": []},
        settings={"hooks": {"PostToolUse": []}},
    )
    original_root = fixture.config_path.read_text(encoding="utf-8")
    original_settings = fixture.settings_path.read_text(encoding="utf-8")
    real_replace = os.replace
    failed = False

    def fail_settings_commit(source: Any, destination: Any) -> None:
        nonlocal failed
        if not failed and Path(destination) == fixture.settings_path:
            failed = True
            raise OSError("simulated settings commit failure")
        real_replace(source, destination)

    monkeypatch.setattr(droid_io.os, "replace", fail_settings_commit)
    with pytest.raises(OSError, match="Write Factory Droid installation"):
        fixture.install()
    assert failed is True
    assert fixture.config_path.read_text(encoding="utf-8") == original_root
    assert fixture.settings_path.read_text(encoding="utf-8") == original_settings
    assert not fixture.audit_path.exists()
    assert not fixture.runtime_config.exists()
    assert not fixture.private_key_path.exists()
    staging = [
        path for path in fixture.home_dir.rglob("*")
        if path.suffix in {".tmp", ".rollback"}
    ]
    assert staging == []
