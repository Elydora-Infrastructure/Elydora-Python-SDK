from __future__ import annotations

import json
import os
from pathlib import Path
import time
from typing import Any

import pytest

from elydora import cli
from elydora.plugins import kiroide
from elydora.plugins.registry import SUPPORTED_AGENTS

from kiroide_support import (
    AGENT_ID,
    AuditHandler,
    PRIVATE_KEY,
    find_hook,
    install_config,
    legacy_document,
    prepare_fixture,
    run_command,
    start_audit_server,
    write_json,
)


def test_kiroide_uses_current_workspace_v1_hook_contract(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    home = tmp_path / "home with spaces"
    workspace = tmp_path / "workspace with spaces"
    home.mkdir()
    workspace.mkdir()
    config_path = workspace / ".kiro" / "hooks" / "elydora-audit.json"
    existing_hook = {
        "name": "workspace-context",
        "trigger": "SessionStart",
        "action": {"type": "agent", "prompt": "Read AGENTS.md"},
        "enabled": True,
    }
    write_json(
        config_path,
        {"version": "v1", "owner": "workspace", "hooks": [existing_hook]},
    )
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.chdir(workspace)

    plugin = kiroide.KiroIdePlugin()
    plugin.install(install_config(home))
    first_source = config_path.read_text(encoding="utf-8")
    plugin.install(install_config(home))

    assert SUPPORTED_AGENTS["kiroide"] == {
        "name": "Kiro IDE",
        "hook_event": "PreToolUse/PostToolUse",
        "config_path": ".kiro/hooks/elydora-audit.json",
    }
    assert config_path.read_text(encoding="utf-8") == first_source
    document = json.loads(first_source)
    assert document["version"] == "v1"
    assert document["owner"] == "workspace"
    assert document["hooks"][0] == existing_hook
    assert document["hooks"][1]["trigger"] == "PreToolUse"
    assert document["hooks"][2]["trigger"] == "PostToolUse"
    assert all(hook["matcher"] == ".*" for hook in document["hooks"][1:])
    assert all(hook["timeout"] == 10 for hook in document["hooks"][1:])
    assert all(hook["enabled"] is True for hook in document["hooks"][1:])
    assert not (home / ".kiro" / "hooks" / "elydora-audit.json").exists()
    private_key_path = home / ".elydora" / AGENT_ID / "private.key"
    audit_path = home / ".elydora" / AGENT_ID / "hook.py"
    assert private_key_path.read_text(encoding="utf-8") == PRIVATE_KEY
    assert PRIVATE_KEY not in audit_path.read_text(encoding="utf-8")
    if os.name != "nt":
        assert private_key_path.stat().st_mode & 0o777 == 0o600
        assert audit_path.stat().st_mode & 0o777 == 0o700


def test_kiroide_commands_block_frozen_agents_and_forward_native_events(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    api = start_audit_server()
    try:
        fixture = prepare_fixture(
            monkeypatch, tmp_path, base_url=api.base_url
        )
        fixture.plugin.install(fixture.config)
        document = json.loads(fixture.config_path.read_text(encoding="utf-8"))
        payload = {
            "hook_event_name": "preToolUse",
            "cwd": str(fixture.workspace),
            "session_id": "session-1",
            "tool_name": "execute_bash",
            "tool_input": {"command": "pytest -q"},
            "future_field": {"retained": True},
        }
        status_cache_path = fixture.agent_directory / "status-cache.json"
        write_json(
            status_cache_path,
            {"status": "frozen", "cached_at": time.time()},
        )
        if os.name != "nt":
            status_cache_path.chmod(0o600)

        blocked = run_command(
            find_hook(document, "elydora-guard")["action"]["command"],
            fixture,
            payload,
        )
        assert blocked.returncode == 2
        assert "Tool execution blocked" in blocked.stderr

        payload["hook_event_name"] = "postToolUse"
        payload["tool_response"] = {"success": True, "result": "12 passed"}
        audited = run_command(
            find_hook(document, "elydora-audit")["action"]["command"],
            fixture,
            payload,
        )
        assert audited.returncode == 0, audited.stderr
        assert AuditHandler.operations[-1]["payload"] == payload
        assert AuditHandler.operations[-1]["action"] == {
            "tool": "execute_bash"
        }
        assert AuditHandler.operations[-1]["subject"] == {
            "session_id": "session-1"
        }
    finally:
        api.close()


def test_kiroide_status_requires_exact_enabled_hooks_and_runtime_sources(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    assert fixture.plugin.status() == {
        "installed": True,
        "agent": "kiroide",
        "details": f"Config: {fixture.config_path}",
    }

    document = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    find_hook(document, "elydora-guard")["enabled"] = False
    write_json(fixture.config_path, document)
    assert fixture.plugin.status() == {
        "installed": False,
        "agent": "kiroide",
        "details": (
            "Managed hooks are incomplete or invalid: "
            f"{fixture.config_path}"
        ),
    }

    fixture.plugin.install(fixture.config)
    fixture.guard_path.write_text("tampered\n", encoding="utf-8")
    status = fixture.plugin.status()
    assert status["installed"] is False
    assert "runtime files are missing or invalid" in status["details"]


def test_kiroide_status_surfaces_malformed_runtime_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    (fixture.agent_directory / "config.json").write_text(
        "{ malformed", encoding="utf-8"
    )

    with pytest.raises(ValueError, match="parse Elydora runtime config"):
        fixture.plugin.status()


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("{ malformed", "parse Kiro IDE hooks"),
        (
            '{"version":"v1","version":"v1","hooks":[]}',
            'duplicate field "version"',
        ),
        ({"version": "v0", "hooks": []}, 'version must be "v1"'),
        ({"version": "v1", "hooks": None}, 'field "hooks" must be an array'),
        (
            {
                "version": "v1",
                "hooks": [
                    {
                        "name": "bad",
                        "trigger": "FutureEvent",
                        "action": {"type": "command", "command": "echo bad"},
                    }
                ],
            },
            "unsupported trigger",
        ),
    ],
)
def test_kiroide_rejects_invalid_workspace_hooks_before_runtime_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    source: Any,
    message: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, current=source)
    original = fixture.config_path.read_text(encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        fixture.plugin.install(fixture.config)

    assert fixture.config_path.read_text(encoding="utf-8") == original
    assert not fixture.agent_directory.exists()


def test_kiroide_cli_preflight_rejects_workspace_before_runtime_creation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, current="{ malformed")
    private_key_file = tmp_path / "private.key"
    token_file = tmp_path / "token"
    private_key_file.write_text(PRIVATE_KEY, encoding="utf-8")
    token_file.write_text("token-1", encoding="utf-8")
    if os.name != "nt":
        private_key_file.chmod(0o600)
        token_file.chmod(0o600)
    args = cli.build_parser().parse_args(
        [
            "install",
            "--agent",
            "kiroide",
            "--org_id",
            "org-1",
            "--agent_id",
            AGENT_ID,
            "--private_key_file",
            str(private_key_file),
            "--token_file",
            str(token_file),
            "--kid",
            "kid-1",
        ]
    )

    with pytest.raises(ValueError, match="parse Kiro IDE hooks"):
        cli.cmd_install(args)

    assert fixture.config_path.read_text(encoding="utf-8") == "{ malformed"
    assert not fixture.agent_directory.exists()


def test_kiroide_rejects_noncanonical_private_keys_before_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.config["private_key"] = PRIVATE_KEY + "="

    with pytest.raises(ValueError, match="canonical 32-byte base64url"):
        fixture.plugin.install(fixture.config)

    assert not fixture.config_path.exists()
    assert not fixture.agent_directory.exists()


def test_kiroide_rejects_managed_name_collisions(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    current = {
        "version": "v1",
        "hooks": [
            {
                "name": "elydora-guard",
                "trigger": "PreToolUse",
                "action": {"type": "command", "command": "user-command"},
            }
        ],
    }
    fixture = prepare_fixture(monkeypatch, tmp_path, current=current)

    with pytest.raises(ValueError, match="conflicts with the Elydora contract"):
        fixture.plugin.install(fixture.config)

    assert json.loads(fixture.config_path.read_text(encoding="utf-8")) == current
    assert not fixture.agent_directory.exists()


def test_kiroide_rejects_linked_workspace_configuration_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    external = tmp_path / "external-kiro"
    external.mkdir()
    try:
        (fixture.workspace / ".kiro").symlink_to(external, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"Directory symbolic links are unavailable: {error}")

    with pytest.raises(OSError, match="not a physical directory"):
        fixture.plugin.install(fixture.config)

    assert not (external / "hooks" / "elydora-audit.json").exists()
    assert not fixture.agent_directory.exists()


def test_kiroide_migrates_only_the_matching_legacy_python_hook(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    write_json(fixture.legacy_path, legacy_document(fixture))

    fixture.plugin.install(fixture.config)
    assert not fixture.legacy_path.exists()

    write_json(fixture.legacy_path, legacy_document(fixture, "agent-2"))
    fixture.plugin.install(fixture.config)
    assert fixture.legacy_path.exists()


def test_kiroide_preserves_unrelated_legacy_hook_and_rejects_malformed_legacy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    unrelated = {
        "name": "User Hook",
        "version": "1.0.0",
        "hooks": {"post_tool_use": {"command": "user-command"}},
    }
    fixture = prepare_fixture(monkeypatch, tmp_path, legacy=unrelated)
    fixture.plugin.install(fixture.config)
    assert json.loads(fixture.legacy_path.read_text(encoding="utf-8")) == unrelated

    fixture.plugin.uninstall(AGENT_ID)
    fixture.legacy_path.write_text("{ malformed", encoding="utf-8")
    with pytest.raises(ValueError, match="parse legacy Kiro IDE hook"):
        fixture.plugin.install(fixture.config)
    assert fixture.legacy_path.read_text(encoding="utf-8") == "{ malformed"
