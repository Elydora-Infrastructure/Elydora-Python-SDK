from __future__ import annotations

import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any

import pytest

from claudecode_support import (
    ElydoraApiHandler,
    managed_handler,
    prepare_fixture,
    run_handler,
    server_base_url,
    start_api_server,
    write_json,
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


class _MismatchApi(BaseHTTPRequestHandler):
    submissions: list[dict[str, Any]] = []
    rejections = 1
    delay = 0.0
    state_path: Path | None = None
    expected = "Rxlf4j36C3KvIQ3hWuOkX698BR5iDypUFuB70JjEuvM"

    @classmethod
    def reset(cls, rejections: int, delay: float = 0.0) -> None:
        cls.submissions = []
        cls.rejections = rejections
        cls.delay = delay
        cls.state_path = None

    def _respond(self, status: int, value: object) -> None:
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self._respond(200, {"agent": {"status": "active"}})

    def do_POST(self) -> None:
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        cls = type(self)
        cls.submissions.append(json.loads(raw))
        count = len(cls.submissions)
        if cls.delay:
            time.sleep(cls.delay)
        if cls.state_path is not None:
            write_json(cls.state_path, {"prev_chain_hash": "B" * 43})
        if count > cls.rejections:
            self._respond(202, {"receipt": {"seq_no": count}})
            return
        expected = cls.expected if cls.rejections == 1 else str(count).rjust(43, "A")
        self._respond(400, {"error": {
            "code": "PREV_HASH_MISMATCH",
            "message": f'Expected prev_chain_hash "{expected}", got "x".',
        }})

    def log_message(self, _format: str, *_args: object) -> None:
        return


def _mismatch_server(rejections: int, delay: float = 0.0) -> ThreadingHTTPServer:
    _MismatchApi.reset(rejections, delay)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _MismatchApi)
    Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_audit_retries_rejected_prev_chain_hash_with_server_value(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server = _mismatch_server(1)
    fixture = prepare_fixture(monkeypatch, tmp_path, base_url=server_base_url(server))
    try:
        fixture.install()
        audit = managed_handler(fixture.settings(), "PostToolUse")
        result = run_handler(
            audit, encoded(official_payload("PostToolUse", tool_response={"stdout": "ok"})), fixture
        )
        assert result.returncode == 0, result.stderr
        submissions = _MismatchApi.submissions
        assert len(submissions) == 2
        assert submissions[1]["prev_chain_hash"] == _MismatchApi.expected
        assert submissions[1]["operation_id"] != submissions[0]["operation_id"]
        assert submissions[1]["nonce"] != submissions[0]["nonce"]
        state = json.loads((fixture.agent_dir / "chain-state.json").read_text(encoding="utf-8"))
        assert state["prev_chain_hash"] == submissions[1]["chain_hash"]
        assert "resynced to server: Rxlf" in (fixture.agent_dir / "error.log").read_text(encoding="utf-8")
    finally:
        server.shutdown()


def test_audit_stops_after_five_rejected_prev_chain_hash_attempts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server = _mismatch_server(99)
    fixture = prepare_fixture(monkeypatch, tmp_path, base_url=server_base_url(server))
    try:
        fixture.install()
        audit = managed_handler(fixture.settings(), "PostToolUse")
        result = run_handler(
            audit, encoded(official_payload("PostToolUse", tool_response={"stdout": "ok"})), fixture
        )
        assert result.returncode == 0, result.stderr
        assert len(_MismatchApi.submissions) == 5
        assert _MismatchApi.submissions[4]["prev_chain_hash"] == "4".rjust(43, "A")
        assert "rejected prev_chain_hash 5 times" in (fixture.agent_dir / "error.log").read_text(encoding="utf-8")
    finally:
        server.shutdown()


def test_audit_stops_retrying_when_the_submit_budget_is_spent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server = _mismatch_server(99, delay=2.6)
    fixture = prepare_fixture(monkeypatch, tmp_path, base_url=server_base_url(server))
    try:
        fixture.install()
        audit = managed_handler(fixture.settings(), "PostToolUse")
        started = time.monotonic()
        result = run_handler(
            audit, encoded(official_payload("PostToolUse", tool_response={"stdout": "ok"})), fixture
        )
        elapsed = time.monotonic() - started
        assert result.returncode == 0, result.stderr
        assert elapsed < 7.5, elapsed
        assert 2 <= len(_MismatchApi.submissions) <= 3
        log = (fixture.agent_dir / "error.log").read_text(encoding="utf-8").lower()
        assert "timed out" in log or "retry budget exhausted" in log
    finally:
        server.shutdown()


def test_audit_does_not_regress_a_chain_head_advanced_by_a_concurrent_hook(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server = _mismatch_server(0)
    fixture = prepare_fixture(monkeypatch, tmp_path, base_url=server_base_url(server))
    try:
        fixture.install()
        _MismatchApi.state_path = fixture.agent_dir / "chain-state.json"
        audit = managed_handler(fixture.settings(), "PostToolUse")
        result = run_handler(
            audit, encoded(official_payload("PostToolUse", tool_response={"stdout": "ok"})), fixture
        )
        assert result.returncode == 0, result.stderr
        assert _MismatchApi.submissions[0]["prev_chain_hash"] == "A" * 43
        state = json.loads((fixture.agent_dir / "chain-state.json").read_text(encoding="utf-8"))
        assert state["prev_chain_hash"] == "B" * 43
    finally:
        server.shutdown()


def test_audit_clears_a_stale_chain_state_lock_and_proceeds(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server = _mismatch_server(0)
    fixture = prepare_fixture(monkeypatch, tmp_path, base_url=server_base_url(server))
    try:
        fixture.install()
        lock_path = fixture.agent_dir / "chain-state.json.lock"
        lock_path.touch(mode=0o600)
        stale = time.time() - 10
        os.utime(lock_path, (stale, stale))
        audit = managed_handler(fixture.settings(), "PostToolUse")
        result = run_handler(
            audit, encoded(official_payload("PostToolUse", tool_response={"stdout": "ok"})), fixture
        )
        assert result.returncode == 0, result.stderr
        assert len(_MismatchApi.submissions) == 1
        assert not lock_path.exists()
        state = json.loads((fixture.agent_dir / "chain-state.json").read_text(encoding="utf-8"))
        assert state["prev_chain_hash"] == _MismatchApi.submissions[0]["chain_hash"]
    finally:
        server.shutdown()


def test_audit_does_not_reclaim_a_lock_whose_owner_is_alive(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server = _mismatch_server(0)
    fixture = prepare_fixture(monkeypatch, tmp_path, base_url=server_base_url(server))
    try:
        fixture.install()
        lock_path = fixture.agent_dir / "chain-state.json.lock"
        lock_path.touch(mode=0o600)
        lock_path.write_text(str(os.getpid()), encoding="ascii")
        stale = time.time() - 10
        os.utime(lock_path, (stale, stale))
        audit = managed_handler(fixture.settings(), "PostToolUse")
        result = run_handler(
            audit, encoded(official_payload("PostToolUse", tool_response={"stdout": "ok"})), fixture
        )
        assert result.returncode == 0, result.stderr
        assert len(_MismatchApi.submissions) == 1
        assert lock_path.exists()
        assert "lock timed out" in (fixture.agent_dir / "error.log").read_text(encoding="utf-8")
    finally:
        server.shutdown()
