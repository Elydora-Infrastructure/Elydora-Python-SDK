from __future__ import annotations

import json
from pathlib import Path

import pytest

from augment_support import (
    ElydoraApiHandler,
    managed_handler,
    prepare_fixture,
    run_handler,
    server_base_url,
    start_api_server,
)


def encoded(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def official_payload(event: str, **overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "hook_event_name": event,
        "conversation_id": "conversation-1",
        "workspace_roots": ["/workspace"],
        "tool_name": "launch-process",
        "tool_input": {"command": "pytest", "nested": {"preserve": True}},
        "is_mcp_tool": False,
        "conversation_data": [{"role": "user", "content": "preserve this"}],
        "mcp_metadata": {"server": "local", "transport": "stdio"},
        "user_context": {"account": "user-1"},
        "future_field": {"survives": ["exactly", 2]},
    }
    value.update(overrides)
    return value


@pytest.mark.parametrize("status", ["frozen", "revoked"])
def test_guard_propagates_official_blocking_exit_code(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    status: str,
) -> None:
    server = start_api_server(status=status)
    try:
        fixture = prepare_fixture(
            monkeypatch, tmp_path, base_url=server_base_url(server)
        )
        fixture.install()
        handler = managed_handler(
            fixture.settings(), "PreToolUse", fixture.guard_wrapper_path
        )
        result = run_handler(handler, encoded(official_payload("PreToolUse")), fixture)
    finally:
        server.shutdown()
        server.server_close()

    assert result.returncode == 2
    assert result.stdout == b""
    assert status.encode() in result.stderr.lower()
    assert b"Tool execution blocked" in result.stderr


def test_audit_preserves_complete_native_hook_payload(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server = start_api_server()
    payload = official_payload(
        "PostToolUse",
        tool_output={"stdout": "passed", "stderr": "", "exit_code": 0},
    )
    try:
        fixture = prepare_fixture(
            monkeypatch, tmp_path, base_url=server_base_url(server)
        )
        fixture.install()
        handler = managed_handler(
            fixture.settings(), "PostToolUse", fixture.audit_wrapper_path
        )
        result = run_handler(handler, encoded(payload), fixture)
    finally:
        server.shutdown()
        server.server_close()

    assert result.returncode == 0
    request = next(
        item for item in ElydoraApiHandler.requests if item["method"] == "POST"
    )
    assert request["json"]["payload"] == payload
    assert request["authorization"] == "Bearer token-1"


def test_status_requires_exact_runtime_identity_key_scripts_and_wrappers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    assert fixture.plugin.status()["installed"] is True

    fixture.guard_wrapper_path.unlink()
    assert fixture.plugin.status()["installed"] is False
    fixture.install()

    fixture.hook_path.unlink()
    assert fixture.plugin.status()["installed"] is False
    fixture.install()

    fixture.audit_wrapper_path.write_text("tampered wrapper\n", encoding="utf-8")
    assert fixture.plugin.status()["installed"] is False
    fixture.install()

    fixture.private_key_path.write_text("invalid", encoding="utf-8")
    with pytest.raises(ValueError, match="private key.*canonical 32-byte"):
        fixture.plugin.status()


@pytest.mark.parametrize(
    ("source", "pattern"),
    [
        ("{ malformed", "parse Elydora runtime config"),
        ('{"agent_name":"augment","agent_name":"augment"}', "duplicate field"),
        (
            json.dumps(
                {
                    "org_id": "org-1",
                    "agent_id": "other-agent",
                    "kid": "key-1",
                    "base_url": "https://api.elydora.com",
                    "agent_name": "augment",
                }
            ),
            "identity does not match",
        ),
        (
            json.dumps(
                {
                    "org_id": "org-1",
                    "agent_id": "agent-1",
                    "kid": "key-1",
                    "base_url": "https://api.elydora.com",
                    "agent_name": "augment",
                    "hidden": True,
                }
            ),
            "unsupported field",
        ),
    ],
)
def test_status_surfaces_invalid_runtime_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    source: str,
    pattern: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    fixture.runtime_config_path.write_text(source, encoding="utf-8")
    with pytest.raises(ValueError, match=pattern):
        fixture.plugin.status()


def test_status_ignores_incomplete_managed_hook_pairs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    settings = fixture.settings()
    del settings["hooks"]["PostToolUse"]
    fixture.config_path.write_text(json.dumps(settings), encoding="utf-8")
    status = fixture.plugin.status()
    assert status["installed"] is False
    assert status["details"] == "Not installed"


def test_runtime_failures_remain_observable_and_fail_open(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    settings = fixture.settings()
    guard = managed_handler(settings, "PreToolUse", fixture.guard_wrapper_path)
    audit = managed_handler(settings, "PostToolUse", fixture.audit_wrapper_path)
    guard_result = run_handler(guard, encoded(official_payload("PreToolUse")), fixture)
    audit_result = run_handler(audit, encoded(official_payload("PostToolUse")), fixture)
    malformed = run_handler(audit, b"{ malformed", fixture)

    assert guard_result.returncode == 0
    assert b"Failed to resolve agent status" in guard_result.stderr
    assert audit_result.returncode == 0
    assert malformed.returncode == 0
    log = (fixture.agent_dir / "error.log").read_text(encoding="utf-8")
    assert "invalid JSON" in log
    assert "refused" in log.lower() or "urlopen" in log.lower()
