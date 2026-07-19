from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest

from elydora.plugins import kirocli
from elydora.plugins.base import InstallConfig
from elydora.plugins.registry import SUPPORTED_AGENTS


AGENT_ID = "agent-1"
MISSING = object()


@dataclass(frozen=True)
class KiroFixture:
    plugin: kirocli.KiroCliPlugin
    config: InstallConfig
    home_dir: Path
    guard_path: Path
    hook_path: Path
    runtime_config_path: Path
    v2_path: Path
    v3_path: Path


def write_json_or_text(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = value if isinstance(value, str) else json.dumps(value, indent=2)
    path.write_text(content, encoding="utf-8")


def prepare_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    existing_v2: Any = MISSING,
    existing_v3: Any = MISSING,
) -> KiroFixture:
    home_dir = tmp_path / "home with spaces"
    elydora_dir = home_dir / ".elydora"
    agent_dir = elydora_dir / AGENT_ID
    v2_path = home_dir / ".kiro" / "agents" / "elydora-audit.json"
    v3_path = home_dir / ".kiro" / "hooks" / "elydora-audit.json"
    agent_dir.mkdir(parents=True)

    guard_path = agent_dir / "guard.py"
    guard_path.write_text(
        "import sys\nsys.stderr.write('Agent is frozen by Elydora.')\nraise SystemExit(2)\n",
        encoding="utf-8",
    )

    if existing_v2 is not MISSING:
        write_json_or_text(v2_path, existing_v2)
    if existing_v3 is not MISSING:
        write_json_or_text(v3_path, existing_v3)

    monkeypatch.setattr(kirocli, "ELYDORA_DIR", str(elydora_dir))
    monkeypatch.setattr(kirocli, "V2_AGENT_PATH", str(v2_path))
    monkeypatch.setattr(kirocli, "V3_HOOKS_PATH", str(v3_path))

    config: InstallConfig = {
        "agent_id": AGENT_ID,
        "agent_name": "kirocli",
        "org_id": "org-1",
        "private_key": "test-key",
        "kid": "kid-1",
        "base_url": "https://api.elydora.test",
        "guard_script_path": str(guard_path),
    }
    return KiroFixture(
        plugin=kirocli.KiroCliPlugin(),
        config=config,
        home_dir=home_dir,
        guard_path=guard_path,
        hook_path=agent_dir / "hook.py",
        runtime_config_path=agent_dir / "config.json",
        v2_path=v2_path,
        v3_path=v3_path,
    )


def find_v3_hook(config: dict[str, Any], name: str) -> dict[str, Any]:
    return next(hook for hook in config["hooks"] if hook.get("name") == name)


def run_command(
    command: str,
    home_dir: Path,
    payload: dict[str, Any],
) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "HOME": str(home_dir),
        "USERPROFILE": str(home_dir),
    }
    return subprocess.run(
        command,
        shell=True,
        capture_output=True,
        check=False,
        env=env,
        input=json.dumps(payload),
        text=True,
    )


def test_kirocli_registry_points_at_v3_global_hook_contract() -> None:
    assert SUPPORTED_AGENTS["kirocli"] == {
        "name": "Kiro CLI",
        "hook_event": "PreToolUse/PostToolUse",
        "config_path": "~/.kiro/hooks/elydora-audit.json",
    }


def test_install_preserves_user_hooks_and_writes_idempotent_v2_v3_contracts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        existing_v2={
            "description": "User Kiro agent",
            "tools": ["read"],
            "hooks": {
                "agentSpawn": [{"command": "existing-spawn"}],
                "preToolUse": [{"matcher": "read", "command": "existing-v2"}],
            },
        },
        existing_v3={
            "version": "v1",
            "hooks": [{
                "name": "existing-v3",
                "trigger": "SessionStart",
                "action": {"type": "command", "command": "existing-command"},
            }],
        },
    )

    fixture.plugin.install(fixture.config)
    fixture.plugin.install(fixture.config)

    output = capsys.readouterr().out
    assert "kiro-cli --agent elydora-audit" in output
    assert "kiro-cli --v3" in output

    v2 = json.loads(fixture.v2_path.read_text(encoding="utf-8"))
    assert v2["description"] == "User Kiro agent"
    assert v2["tools"] == ["read"]
    assert v2["hooks"]["agentSpawn"] == [{"command": "existing-spawn"}]
    assert len(v2["hooks"]["preToolUse"]) == 2
    assert len(v2["hooks"]["postToolUse"]) == 1
    assert v2["hooks"]["preToolUse"][1]["matcher"] == "*"
    assert v2["hooks"]["preToolUse"][1]["timeout_ms"] == 5000

    v3 = json.loads(fixture.v3_path.read_text(encoding="utf-8"))
    assert v3["version"] == "v1"
    assert len(v3["hooks"]) == 3
    assert v3["hooks"][0]["name"] == "existing-v3"
    assert find_v3_hook(v3, "elydora-guard") == {
        "name": "elydora-guard",
        "description": "Block tool use when the Elydora agent is frozen",
        "trigger": "PreToolUse",
        "matcher": ".*",
        "action": {
            "type": "command",
            "command": find_v3_hook(v3, "elydora-guard")["action"]["command"],
        },
        "timeout": 5,
        "enabled": True,
    }
    assert find_v3_hook(v3, "elydora-audit")["trigger"] == "PostToolUse"


def test_hook_commands_block_frozen_agents_and_forward_official_event_payload(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    capture_path = tmp_path / "captured-event.json"
    fixture.hook_path.write_text(
        "import pathlib, sys\n"
        f"pathlib.Path({str(capture_path)!r}).write_text(sys.stdin.read(), encoding='utf-8')\n",
        encoding="utf-8",
    )
    v3 = json.loads(fixture.v3_path.read_text(encoding="utf-8"))
    payload = {
        "hook_event_name": "PreToolUse",
        "cwd": str(fixture.home_dir),
        "session_id": "session-1",
        "tool_name": "execute_bash",
        "tool_input": {"command": "echo test"},
    }

    guard_result = run_command(
        find_v3_hook(v3, "elydora-guard")["action"]["command"],
        fixture.home_dir,
        payload,
    )
    assert guard_result.returncode == 2
    assert "Agent is frozen by Elydora" in guard_result.stderr

    payload["hook_event_name"] = "PostToolUse"
    payload["tool_response"] = {"success": True, "result": "test"}
    audit_result = run_command(
        find_v3_hook(v3, "elydora-audit")["action"]["command"],
        fixture.home_dir,
        payload,
    )
    assert audit_result.returncode == 0
    assert json.loads(capture_path.read_text(encoding="utf-8")) == payload


def test_status_accepts_either_contract_and_requires_both_runtime_scripts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    assert fixture.plugin.status() == {
        "installed": True,
        "agent": "kirocli",
        "details": f"Config: {fixture.v3_path}",
    }

    fixture.v3_path.unlink()
    assert fixture.plugin.status()["details"] == f"Config: {fixture.v2_path}"

    fixture.plugin.install(fixture.config)
    fixture.v2_path.unlink()
    assert fixture.plugin.status()["details"] == f"Config: {fixture.v3_path}"

    fixture.guard_path.unlink()
    status = fixture.plugin.status()
    assert status["installed"] is False
    assert status["details"] == f"Configured at {fixture.v3_path}; runtime scripts missing"


def test_status_surfaces_malformed_referenced_runtime_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    fixture.runtime_config_path.write_text("{ malformed", encoding="utf-8")

    with pytest.raises(ValueError, match="parse Elydora runtime config"):
        fixture.plugin.status()


def test_uninstall_preserves_unrelated_v2_and_v3_hooks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        existing_v2={
            "hooks": {"preToolUse": [{"matcher": "read", "command": "existing-v2"}]},
        },
        existing_v3={
            "version": "v1",
            "hooks": [{
                "name": "existing-v3",
                "trigger": "SessionStart",
                "action": {"type": "command", "command": "existing-command"},
            }],
        },
    )
    fixture.plugin.install(fixture.config)

    fixture.plugin.uninstall(AGENT_ID)

    v2 = json.loads(fixture.v2_path.read_text(encoding="utf-8"))
    assert v2["hooks"]["preToolUse"] == [{"matcher": "read", "command": "existing-v2"}]
    assert v2["hooks"]["postToolUse"] == []
    v3 = json.loads(fixture.v3_path.read_text(encoding="utf-8"))
    assert v3["hooks"] == [{
        "name": "existing-v3",
        "trigger": "SessionStart",
        "action": {"type": "command", "command": "existing-command"},
    }]


def test_uninstall_removes_configs_owned_entirely_by_elydora(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)

    fixture.plugin.uninstall(AGENT_ID)

    assert fixture.v2_path.exists() is False
    assert fixture.v3_path.exists() is False


@pytest.mark.parametrize("malformed_contract", ["v2", "v3"])
def test_install_preserves_malformed_configs_before_any_runtime_write(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    malformed_contract: str,
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        existing_v2="{ malformed" if malformed_contract == "v2" else MISSING,
        existing_v3="{ malformed" if malformed_contract == "v3" else MISSING,
    )
    malformed_path = fixture.v2_path if malformed_contract == "v2" else fixture.v3_path

    with pytest.raises(ValueError, match=f"parse Kiro CLI {malformed_contract}"):
        fixture.plugin.install(fixture.config)

    assert malformed_path.read_text(encoding="utf-8") == "{ malformed"
    assert fixture.hook_path.exists() is False
    assert fixture.runtime_config_path.exists() is False


@pytest.mark.parametrize(
    ("existing_v2", "existing_v3", "error_pattern"),
    [
        ({"hooks": None}, MISSING, 'field "hooks" must be an object'),
        (MISSING, {"version": None, "hooks": []}, 'field "version" must be "v1"'),
        (MISSING, {"version": "v1", "hooks": None}, 'field "hooks" must be an array'),
    ],
)
def test_install_rejects_invalid_contract_shapes_before_any_runtime_write(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    existing_v2: Any,
    existing_v3: Any,
    error_pattern: str,
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        existing_v2=existing_v2,
        existing_v3=existing_v3,
    )

    with pytest.raises(ValueError, match=error_pattern):
        fixture.plugin.install(fixture.config)

    assert fixture.hook_path.exists() is False
    assert fixture.runtime_config_path.exists() is False
