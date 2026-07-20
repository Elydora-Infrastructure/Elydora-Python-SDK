from __future__ import annotations

import json
from pathlib import Path

import pytest

from claudecode_support import (
    ElydoraApiHandler,
    managed_handler,
    prepare_fixture,
    run_handler,
    server_base_url,
    start_api_server,
)


def official_payload(event: str, **overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "session_id": "session-1",
        "prompt_id": "302d811d-0d17-41ad-a359-d2cb618fd42b",
        "transcript_path": "/tmp/session-1.jsonl",
        "cwd": "/tmp/project",
        "permission_mode": "default",
        "effort": {"level": "high"},
        "hook_event_name": event,
        "tool_name": "Bash",
        "tool_input": {"command": "pytest", "description": "Run tests"},
        "tool_use_id": "toolu_01ABC123",
    }
    value.update(overrides)
    return value


def encoded(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def test_runtimes_preserve_success_and_failure_payloads(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server = start_api_server()
    try:
        fixture = prepare_fixture(
            monkeypatch, tmp_path, base_url=server_base_url(server)
        )
        fixture.install()
        settings = fixture.settings()
        guard = managed_handler(settings, "PreToolUse")
        success_audit = managed_handler(settings, "PostToolUse")
        failure_audit = managed_handler(settings, "PostToolUseFailure")

        pre = official_payload("PreToolUse")
        guard_result = run_handler(guard, encoded(pre), fixture)
        success = official_payload(
            "PostToolUse",
            tool_response={
                "stdout": "tests passed",
                "stderr": "",
                "interrupted": False,
                "isImage": False,
            },
        )
        success_result = run_handler(success_audit, encoded(success), fixture)
        failure = official_payload(
            "PostToolUseFailure",
            error="Command exited with non-zero status code 1",
            is_interrupt=False,
            duration_ms=4187,
        )
        failure_result = run_handler(failure_audit, encoded(failure), fixture)
    finally:
        server.shutdown()
        server.server_close()

    assert guard_result.returncode == 0
    assert guard_result.stdout == b""
    assert guard_result.stderr == b""
    assert success_result.returncode == 0
    assert failure_result.returncode == 0
    assert [request["method"] for request in ElydoraApiHandler.requests] == [
        "GET", "POST", "POST",
    ]
    success_operation = ElydoraApiHandler.requests[1]["json"]
    failure_operation = ElydoraApiHandler.requests[2]["json"]
    assert success_operation["payload"] == success
    assert failure_operation["payload"] == failure
    assert success_operation["subject"] == {"session_id": "session-1"}
    assert success_operation["action"] == {"tool": "Bash"}
    assert ElydoraApiHandler.requests[1]["authorization"] == "Bearer token-1"
    assert failure_operation["prev_chain_hash"] == success_operation["chain_hash"]


@pytest.mark.parametrize("status", ["frozen", "revoked"])
def test_guard_returns_official_exit_code_two(
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
            managed_handler(fixture.settings(), "PreToolUse"),
            encoded(official_payload("PreToolUse")),
            fixture,
        )
    finally:
        server.shutdown()
        server.server_close()

    assert result.returncode == 2
    assert result.stdout == b""
    assert status.encode() in result.stderr.lower()
    assert b"Tool execution blocked" in result.stderr


def test_runtime_failures_are_observable_and_fail_open(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    settings = fixture.settings()
    guard = managed_handler(settings, "PreToolUse")
    audit = managed_handler(settings, "PostToolUse")

    guard_result = run_handler(
        guard, encoded(official_payload("PreToolUse")), fixture
    )
    audit_result = run_handler(
        audit,
        encoded(official_payload("PostToolUse", tool_response={"stdout": ""})),
        fixture,
    )
    malformed = run_handler(audit, b"{ malformed", fixture)

    assert guard_result.returncode == 0
    assert b"Failed to resolve agent status" in guard_result.stderr
    assert audit_result.returncode == 0
    assert malformed.returncode == 0
    log = (fixture.agent_dir / "error.log").read_text(encoding="utf-8")
    assert "invalid JSON" in log
    assert "refused" in log.lower() or "urlopen" in log.lower()
