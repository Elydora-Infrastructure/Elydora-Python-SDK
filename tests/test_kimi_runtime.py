from __future__ import annotations

import json
from pathlib import Path

import pytest

from kimi_support import (
    KimiApiHandler,
    managed_hook,
    parsed_hooks,
    prepare_fixture,
    run_hook,
    server_base_url,
    start_api_server,
)


PRE_PAYLOAD = {
    "hook_event_name": "PreToolUse",
    "session_id": "session-1",
    "cwd": "C:/project",
    "tool_name": "Bash",
    "tool_input": {"command": "echo test"},
    "tool_call_id": "call-1",
}


def test_runtimes_enforce_active_state_and_preserve_success_and_failure_payloads(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server = start_api_server()
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        base_url=server_base_url(server),
        legacy_detected=False,
    )
    try:
        fixture.install()
        hooks = parsed_hooks(fixture.stable_path)
        guard = managed_hook(hooks, "PreToolUse")
        success_audit = managed_hook(hooks, "PostToolUse")
        failure_audit = managed_hook(hooks, "PostToolUseFailure")

        guard_result = run_hook(
            str(guard["command"]),
            json.dumps(PRE_PAYLOAD),
            fixture,
            {"ELYDORA_HOOK_PATH": "injected-command-fragment"},
        )
        assert guard_result.returncode == 0, guard_result.stderr

        success_payload = {
            **PRE_PAYLOAD,
            "hook_event_name": "PostToolUse",
            "tool_output": "test\n",
        }
        success = run_hook(
            str(success_audit["command"]),
            json.dumps(success_payload),
            fixture,
        )
        assert success.returncode == 0, success.stderr

        failure_payload = {
            **PRE_PAYLOAD,
            "hook_event_name": "PostToolUseFailure",
            "error": {
                "name": "ToolError",
                "message": "command failed",
                "code": "tool.failed",
            },
        }
        failure = run_hook(
            str(failure_audit["command"]),
            json.dumps(failure_payload),
            fixture,
        )
        assert failure.returncode == 0, failure.stderr

        operations = [
            request["json"]
            for request in KimiApiHandler.requests
            if request["method"] == "POST"
        ]
        assert len(operations) == 2
        assert operations[0]["payload"] == success_payload
        assert operations[1]["payload"] == failure_payload
        assert operations[0]["subject"]["session_id"] == "session-1"
        assert operations[1]["action"]["tool"] == "Bash"
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("status", ["frozen", "revoked"])
def test_guard_propagates_exit_code_two_for_blocked_agents(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    status: str,
) -> None:
    server = start_api_server(status=status)
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        base_url=server_base_url(server),
        legacy_detected=False,
    )
    try:
        fixture.install()
        command = managed_hook(
            parsed_hooks(fixture.stable_path), "PreToolUse"
        )["command"]
        result = run_hook(str(command), json.dumps(PRE_PAYLOAD), fixture)
        assert result.returncode == 2
        assert status in result.stderr.lower()
    finally:
        server.shutdown()
        server.server_close()


def test_audit_runtime_records_malformed_input_and_api_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server = start_api_server(operation_status=503)
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        base_url=server_base_url(server),
        legacy_detected=False,
    )
    try:
        fixture.install()
        command = managed_hook(
            parsed_hooks(fixture.stable_path), "PostToolUse"
        )["command"]

        malformed = run_hook(str(command), "{ malformed", fixture)
        assert malformed.returncode == 0
        assert malformed.stderr == ""

        upstream = run_hook(
            str(command),
            json.dumps(
                {
                    **PRE_PAYLOAD,
                    "hook_event_name": "PostToolUse",
                    "tool_output": "test",
                }
            ),
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
