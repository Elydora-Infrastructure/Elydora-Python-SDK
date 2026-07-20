from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from elydora import cli
from elydora.plugins import copilot
from elydora.plugins.registry import SUPPORTED_AGENTS

from copilot_support import (
    AGENT_ID,
    VALID_PRIVATE_KEY,
    assert_native_handler,
    assert_runtime_absent,
    legacy_managed_config,
    managed_handler,
    prepare_fixture,
    run_hook,
    write_json_or_text,
)


def test_copilot_is_registered_with_complete_native_contract() -> None:
    assert SUPPORTED_AGENTS["copilot"] == {
        "name": "GitHub Copilot CLI",
        "hook_event": "preToolUse/postToolUse/postToolUseFailure",
        "config_path": "~/.copilot/hooks/elydora-audit.json",
    }
    assert cli.PLUGIN_MAP["copilot"] is copilot.CopilotPlugin
    assert copilot.CopilotPlugin.manages_guard_runtime is True


def test_install_preserves_hooks_migrates_legacy_and_is_idempotent(
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
                "sessionStart": [
                    {"type": "command", "command": "user-session"}
                ],
                "preToolUse": [
                    {"type": "command", "command": "user-pre"}
                ],
            },
        },
    )
    write_json_or_text(
        fixture.legacy_path,
        legacy_managed_config(fixture, {
            "notification": [
                {"type": "command", "command": "user-notification"}
            ],
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
    assert len(settings["hooks"]["postToolUseFailure"]) == 1
    assert_native_handler(managed_handler(settings, "preToolUse", "guard.py"))
    assert_native_handler(managed_handler(settings, "postToolUse", "hook.py"))
    assert_native_handler(
        managed_handler(settings, "postToolUseFailure", "hook.py")
    )
    legacy = json.loads(fixture.legacy_path.read_text(encoding="utf-8"))
    assert legacy == {
        "version": 1,
        "hooks": {
            "notification": [
                {"type": "command", "command": "user-notification"}
            ],
        },
    }
    runtime = json.loads(
        fixture.runtime_config_path.read_text(encoding="utf-8")
    )
    assert runtime["agent_id"] == AGENT_ID
    assert runtime["agent_name"] == "copilot"
    assert fixture.private_key_path.read_text(encoding="utf-8") == (
        VALID_PRIVATE_KEY
    )
    assert fixture.guard_path.is_file()
    assert fixture.hook_path.is_file()
    assert fixture.plugin.status()["installed"] is True


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


def test_commands_block_and_forward_success_and_failure_payloads(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    capture_path = tmp_path / "captured-event.json"
    fixture.guard_path.write_text(
        "import sys\nsys.stdin.read()\n"
        "sys.stderr.write('Agent is frozen by Elydora.')\n"
        "raise SystemExit(2)\n",
        encoding="utf-8",
    )
    fixture.hook_path.write_text(
        "from pathlib import Path\nimport sys\n"
        f"Path({str(capture_path)!r}).write_text(sys.stdin.read(), encoding='utf-8')\n",
        encoding="utf-8",
    )
    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    base = {
        "sessionId": "session-1",
        "timestamp": 1,
        "cwd": str(fixture.project_dir),
        "toolName": "powershell",
        "toolArgs": {"command": "Get-ChildItem"},
    }
    pre_payload = json.dumps(base, separators=(",", ":"))
    guard = managed_handler(settings, "preToolUse", "guard.py")
    guard_result = run_hook(guard, fixture, pre_payload)
    assert guard_result.returncode == 2, guard_result.stderr
    assert "Agent is frozen by Elydora" in guard_result.stderr

    success_payload = json.dumps(
        {**base, "toolResult": {"resultType": "success", "textResultForLlm": "ok"}},
        separators=(",", ":"),
    )
    success = managed_handler(settings, "postToolUse", "hook.py")
    success_result = run_hook(success, fixture, success_payload)
    assert success_result.returncode == 0, success_result.stderr
    assert capture_path.read_text(encoding="utf-8") == success_payload

    failure_payload = json.dumps(
        {**base, "error": "command failed"},
        separators=(",", ":"),
    )
    failure = managed_handler(settings, "postToolUseFailure", "hook.py")
    failure_result = run_hook(failure, fixture, failure_payload)
    assert failure_result.returncode == 0, failure_result.stderr
    assert capture_path.read_text(encoding="utf-8") == failure_payload


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


def test_status_requires_complete_contract_and_exact_runtime_sources(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    assert fixture.plugin.status()["installed"] is True

    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    del settings["hooks"]["postToolUseFailure"]
    write_json_or_text(fixture.config_path, settings)
    assert fixture.plugin.status()["installed"] is False

    fixture.plugin.install(fixture.config)
    fixture.guard_path.write_text("# tampered\n", encoding="utf-8")
    assert fixture.plugin.status()["installed"] is False

    fixture.plugin.install(fixture.config)
    valid_runtime = fixture.runtime_config_path.read_text(encoding="utf-8")
    fixture.runtime_config_path.write_text("{ malformed", encoding="utf-8")
    with pytest.raises(ValueError, match="runtime config"):
        fixture.plugin.status()

    fixture.runtime_config_path.write_text(valid_runtime, encoding="utf-8")
    fixture.private_key_path.write_text("invalid", encoding="utf-8")
    with pytest.raises(ValueError, match="private key"):
        fixture.plugin.status()


def test_settings_precedence_allows_later_false_and_preserves_jsonc(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    user_source = "{\n  // user policy\n  \"disableAllHooks\": true,\n}\n"
    claude_source = "{\n  \"disableAllHooks\": true,\n}\n"
    repository_source = "{\n  \"disableAllHooks\": false,\n}\n"
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        user_settings=user_source,
        claude_local_settings=claude_source,
        repository_settings=repository_source,
    )

    fixture.plugin.install(fixture.config)

    assert fixture.user_settings_path.read_text(encoding="utf-8") == user_source
    assert fixture.claude_local_settings_path.read_text(
        encoding="utf-8"
    ) == claude_source
    assert fixture.repository_settings_path.read_text(
        encoding="utf-8"
    ) == repository_source
    assert fixture.plugin.status()["installed"] is True


@pytest.mark.parametrize(
    ("kwargs", "source_name"),
    [
        ({"repository_settings": {"disableAllHooks": True}}, "repository"),
        (
            {
                "claude_local_settings": {"disableAllHooks": True},
                "repository_settings": {"disableAllHooks": True},
            },
            "repository",
        ),
    ],
)
def test_effective_disabled_settings_block_before_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    kwargs: dict[str, object],
    source_name: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, **kwargs)
    with pytest.raises(ValueError, match=source_name):
        fixture.plugin.install(fixture.config)
    assert fixture.config_path.exists() is False
    assert_runtime_absent(fixture)


def test_managed_file_disable_flag_remains_authoritative(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        user_config={"version": 1, "disableAllHooks": True, "hooks": {}},
        local_settings={"disableAllHooks": False},
    )
    with pytest.raises(ValueError, match="user hooks"):
        fixture.plugin.install(fixture.config)
    assert_runtime_absent(fixture)


def test_matchers_use_official_javascript_regular_expression_syntax(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        user_config={
            "version": 1,
            "hooks": {
                "preToolUse": [{
                    "type": "command",
                    "command": "user-pre",
                    "matcher": "(?<tool>shell)",
                }],
            },
        },
    )

    fixture.plugin.install(fixture.config)

    settings = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    assert settings["hooks"]["preToolUse"][0]["matcher"] == (
        "(?<tool>shell)"
    )


@pytest.mark.parametrize(
    "existing",
    [
        "{ malformed",
        '{"version":1,"version":1,"hooks":{}}',
        {"hooks": {}},
        {"version": True, "hooks": {}},
        {"version": 1, "hooks": None},
        {"version": 1, "hooks": {"unknownEvent": []}},
        {"version": 1, "hooks": {"preToolUse": None}},
        {"version": 1, "hooks": {"preToolUse": [None]}},
        {"version": 1, "hooks": {"preToolUse": [{}]}},
        {"version": 1, "hooks": {"preToolUse": [{"command": 1}]}},
        {"version": 1, "hooks": {"preToolUse": [{"command": "x", "timeoutSec": 0}]}},
        {"version": 1, "hooks": {"preToolUse": [{"command": "x", "matcher": "["}]}},
        {"version": 1, "hooks": {"postToolUse": [{"type": "prompt", "prompt": "x"}]}},
        {"version": 1, "hooks": {"postToolUse": [{"type": "http", "url": "http://example.com"}]}},
    ],
)
def test_invalid_hook_documents_are_preserved_before_runtime_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    existing: object,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, user_config=existing)
    original = fixture.config_path.read_text(encoding="utf-8")
    with pytest.raises(ValueError):
        fixture.plugin.install(fixture.config)
    assert fixture.config_path.read_text(encoding="utf-8") == original
    assert_runtime_absent(fixture)


@pytest.mark.parametrize(
    "settings",
    [
        "{ malformed",
        '{"disableAllHooks":true,"disableAllHooks":false}',
        '{"disableAllHooks":"yes"}',
    ],
)
def test_invalid_settings_are_preserved_before_runtime_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    settings: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, user_settings=settings)
    with pytest.raises(ValueError):
        fixture.plugin.install(fixture.config)
    assert fixture.user_settings_path.read_text(encoding="utf-8") == settings
    assert_runtime_absent(fixture)


def test_uninstall_removes_exact_ownership_and_preserves_adjacent_handlers(
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
        "bash": "user-pre",
        "powershell": "user-pre",
        "timeoutSec": 10,
    })
    write_json_or_text(fixture.config_path, settings)

    fixture.plugin.uninstall(AGENT_ID.upper() if os.name == "nt" else AGENT_ID)

    remaining = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    assert remaining["hooks"]["notification"] == [
        {"type": "command", "command": "keep"}
    ]
    assert remaining["hooks"]["preToolUse"] == [{
        "type": "command",
        "bash": "user-pre",
        "powershell": "user-pre",
        "timeoutSec": 10,
    }]
    assert "postToolUse" not in remaining["hooks"]
    assert "postToolUseFailure" not in remaining["hooks"]


def test_uninstall_leaves_absent_sources_absent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.uninstall(AGENT_ID)
    assert fixture.config_path.exists() is False
    assert fixture.legacy_path.exists() is False


def test_preflight_validates_credentials_and_runtime_path_without_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    invalid = dict(fixture.config)
    invalid["private_key"] = "invalid"
    with pytest.raises(ValueError, match="private_key"):
        fixture.plugin.preflight_install(invalid)  # type: ignore[arg-type]
    assert fixture.config_path.exists() is False
    assert_runtime_absent(fixture)
