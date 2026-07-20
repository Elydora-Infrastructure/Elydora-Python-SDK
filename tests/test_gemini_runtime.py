from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from gemini_support import (
    ElydoraApiHandler,
    managed_handler,
    prepare_fixture,
    run_handler,
    server_base_url,
    start_api_server,
)


GUARD_NAME = "elydora-guard"
AUDIT_NAME = "elydora-audit"


def official_payload(event: str, **overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "session_id": "session-1",
        "transcript_path": "/tmp/session-1.jsonl",
        "cwd": "/tmp/project",
        "hook_event_name": event,
        "timestamp": "2026-07-19T00:00:00.000Z",
        "tool_name": "run_shell_command",
        "tool_input": {"command": "pytest"},
    }
    if event == "AfterTool":
        value["tool_response"] = {"output": "passed", "error": None}
    value.update(overrides)
    return value


def encoded(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def test_guard_accepts_active_agents_with_valid_json_stdout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server = start_api_server()
    try:
        fixture = prepare_fixture(
            monkeypatch, tmp_path, base_url=server_base_url(server)
        )
        fixture.install()
        result = run_handler(
            managed_handler(fixture.settings(), "BeforeTool", GUARD_NAME),
            encoded(official_payload("BeforeTool")),
            fixture,
        )
    finally:
        server.shutdown()
        server.server_close()

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {}
    assert [request["method"] for request in ElydoraApiHandler.requests] == ["GET"]


@pytest.mark.parametrize("status", ["frozen", "revoked"])
def test_guard_propagates_official_exit_code_two(
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
        result = run_handler(
            managed_handler(fixture.settings(), "BeforeTool", GUARD_NAME),
            encoded(official_payload("BeforeTool")),
            fixture,
        )
    finally:
        server.shutdown()
        server.server_close()

    assert result.returncode == 2
    assert result.stdout == b""
    assert status.encode() in result.stderr.lower()


def test_audit_preserves_complete_native_after_tool_payload(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server = start_api_server()
    try:
        fixture = prepare_fixture(
            monkeypatch, tmp_path, base_url=server_base_url(server)
        )
        fixture.install()
        payload = official_payload(
            "AfterTool",
            mcp_context={"server_name": "filesystem", "tool_name": "write_file"},
            original_request_name="write_file",
            future_provider_field={"preserved": True},
        )
        result = run_handler(
            managed_handler(fixture.settings(), "AfterTool", AUDIT_NAME),
            encoded(payload),
            fixture,
        )
    finally:
        server.shutdown()
        server.server_close()

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {}
    operation = next(
        request["json"]
        for request in ElydoraApiHandler.requests
        if request["method"] == "POST"
    )
    assert operation["payload"] == payload
    assert operation["subject"] == {"session_id": "session-1"}
    assert operation["action"] == {"tool": "run_shell_command"}


def test_runtime_failures_stay_observable_and_fail_open(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    settings = fixture.settings()
    guard = managed_handler(settings, "BeforeTool", GUARD_NAME)
    audit = managed_handler(settings, "AfterTool", AUDIT_NAME)

    invalid_guard = run_handler(guard, b"{ malformed", fixture)
    audit_result = run_handler(
        audit, encoded(official_payload("AfterTool")), fixture
    )

    assert invalid_guard.returncode == 0
    assert json.loads(invalid_guard.stdout) == {}
    assert b"invalid JSON" in invalid_guard.stderr
    assert audit_result.returncode == 0
    assert json.loads(audit_result.stdout) == {}
    log = (fixture.agent_dir / "error.log").read_text(encoding="utf-8")
    assert "[elydora-hook]" in log
    assert "refused" in log.lower() or "urlerror" in log.lower()


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits apply on POSIX")
def test_runtime_artifacts_use_private_modes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    for path, expected in (
        (fixture.runtime_config_path, 0o600),
        (fixture.private_key_path, 0o600),
        (fixture.guard_path, 0o700),
        (fixture.hook_path, 0o700),
        (fixture.config_path, 0o600),
    ):
        assert path.stat().st_mode & 0o777 == expected
