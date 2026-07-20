from __future__ import annotations

import json
from pathlib import Path

import pytest

from grok_support import (
    GrokApiHandler,
    managed_handler,
    prepare_fixture,
    run_hook,
    server_base_url,
    start_api_server,
)


PRE_PAYLOAD = {
    "hookEventName": "pre_tool_use",
    "sessionId": "session-1",
    "cwd": "C:/project",
    "workspaceRoot": "C:/project",
    "toolName": "run_terminal_command",
    "toolInput": {"command": "npm test"},
    "toolUseId": "tool-use-1",
    "toolInputTruncated": False,
    "timestamp": "2026-07-19T12:00:00Z",
}


def test_runtimes_enforce_active_state_and_preserve_native_payloads(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server = start_api_server()
    fixture = prepare_fixture(
        monkeypatch, tmp_path, base_url=server_base_url(server)
    )
    try:
        fixture.install()
        settings = fixture.settings()
        guard = managed_handler(settings, "PreToolUse")
        success_audit = managed_handler(settings, "PostToolUse")
        failure_audit = managed_handler(settings, "PostToolUseFailure")

        guard_result = run_hook(
            str(guard["command"]),
            json.dumps(PRE_PAYLOAD),
            fixture,
            {"GROK_HOOK_EVENT": "injected-command-fragment"},
        )
        assert guard_result.returncode == 0, guard_result.stderr
        assert guard_result.stdout == ""

        success_payload = {
            **PRE_PAYLOAD,
            "hookEventName": "post_tool_use",
            "toolResult": {"output": "tests passed"},
            "toolResultTruncated": False,
            "durationMs": 125,
        }
        success = run_hook(
            str(success_audit["command"]),
            json.dumps(success_payload),
            fixture,
        )
        assert success.returncode == 0, success.stderr

        failure_payload = {
            **PRE_PAYLOAD,
            "hookEventName": "post_tool_use_failure",
            "toolResult": {"error": "command failed", "exitCode": 1},
            "toolResultTruncated": False,
            "durationMs": 40,
        }
        failure = run_hook(
            str(failure_audit["command"]),
            json.dumps(failure_payload),
            fixture,
        )
        assert failure.returncode == 0, failure.stderr

        operations = [
            request["json"]
            for request in GrokApiHandler.requests
            if request["method"] == "POST"
        ]
        assert len(operations) == 2
        assert operations[0]["payload"] == success_payload
        assert operations[1]["payload"] == failure_payload
        assert operations[0]["subject"]["session_id"] == "session-1"
        assert operations[1]["action"]["tool"] == "run_terminal_command"
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("status", ["frozen", "revoked"])
def test_guard_emits_official_deny_json_and_exit_code_two(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    status: str,
) -> None:
    server = start_api_server(status=status)
    fixture = prepare_fixture(
        monkeypatch, tmp_path, base_url=server_base_url(server)
    )
    try:
        fixture.install()
        command = managed_handler(
            fixture.settings(), "PreToolUse"
        )["command"]
        result = run_hook(str(command), json.dumps(PRE_PAYLOAD), fixture)

        assert result.returncode == 2
        assert status in result.stderr.lower()
        decision = json.loads(result.stdout)
        assert set(decision) == {"decision", "reason"}
        assert decision["decision"] == "deny"
        assert status in decision["reason"].lower()
    finally:
        server.shutdown()
        server.server_close()


def test_audit_runtime_records_malformed_input_and_api_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server = start_api_server(operation_status=503)
    fixture = prepare_fixture(
        monkeypatch, tmp_path, base_url=server_base_url(server)
    )
    try:
        fixture.install()
        command = managed_handler(
            fixture.settings(), "PostToolUse"
        )["command"]

        malformed = run_hook(str(command), "{ malformed", fixture)
        assert malformed.returncode == 0
        assert malformed.stderr == ""

        upstream = run_hook(
            str(command),
            json.dumps({
                **PRE_PAYLOAD,
                "hookEventName": "post_tool_use",
                "toolResult": {"output": "test"},
            }),
            fixture,
        )
        assert upstream.returncode == 0
        assert upstream.stderr == ""
        log = (fixture.agent_dir / "error.log").read_text(encoding="utf-8")
        assert "invalid JSON" in log
        assert "HTTP 503" in log
    finally:
        server.shutdown()
        server.server_close()
