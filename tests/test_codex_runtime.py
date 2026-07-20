from __future__ import annotations

import json
from pathlib import Path
import time

import pytest

from codex_support import (
    ElydoraApiHandler,
    managed_handler,
    prepare_fixture,
    run_handler,
    server_base_url,
    start_api_server,
    symlink_or_skip,
    write_json,
    write_text,
)
from elydora.plugins.codex_contract import AUDIT_STATUS, GUARD_STATUS


def payload(event: str, *, failed: bool = False) -> dict[str, object]:
    value: dict[str, object] = {
        "hook_event_name": event,
        "session_id": "session-1",
        "turn_id": "turn-1",
        "transcript_path": None,
        "cwd": "C:/workspace",
        "model": "gpt-5",
        "permission_mode": "default",
        "tool_name": "Bash",
        "tool_use_id": "call-1",
        "tool_input": {"command": "echo test"},
    }
    if event == "PostToolUse":
        value["tool_response"] = (
            {"success": False, "error": "command failed", "exit_code": 1}
            if failed
            else {"success": True, "output": "test"}
        )
    return value


def encoded(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def test_runtimes_enforce_active_state_and_preserve_native_event_json(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    server = start_api_server()
    try:
        fixture = prepare_fixture(
            monkeypatch,
            tmp_path,
            base_url=server_base_url(server),
        )
        fixture.install()
        settings = fixture.settings()
        guard = managed_handler(settings, "PreToolUse", GUARD_STATUS)
        audit = managed_handler(settings, "PostToolUse", AUDIT_STATUS)

        pre = payload("PreToolUse")
        first = payload("PostToolUse")
        failed = payload("PostToolUse", failed=True)
        guard_result = run_handler(guard, encoded(pre), fixture)
        first_result = run_handler(audit, encoded(first), fixture)
        failed_result = run_handler(audit, encoded(failed), fixture)
    finally:
        server.shutdown()
        server.server_close()

    assert guard_result.returncode == 0
    assert guard_result.stdout == b""
    assert guard_result.stderr == b""
    assert first_result.returncode == 0
    assert failed_result.returncode == 0
    requests = ElydoraApiHandler.requests
    assert [request["method"] for request in requests] == ["GET", "POST", "POST"]
    assert [request["authorization"] for request in requests] == [
        "Bearer token-1",
        "Bearer token-1",
        "Bearer token-1",
    ]
    assert requests[1]["json"]["payload"] == first
    assert requests[2]["json"]["payload"] == failed
    assert requests[2]["json"]["prev_chain_hash"] == requests[1]["json"]["chain_hash"]


@pytest.mark.parametrize("status", ["frozen", "revoked"])
def test_guard_propagates_exit_two_for_blocked_agents(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    status: str,
) -> None:
    server = start_api_server()
    ElydoraApiHandler.agent_status = status
    try:
        fixture = prepare_fixture(
            monkeypatch,
            tmp_path,
            base_url=server_base_url(server),
        )
        fixture.install()
        guard = managed_handler(fixture.settings(), "PreToolUse", GUARD_STATUS)
        result = run_handler(guard, encoded(payload("PreToolUse")), fixture)
    finally:
        server.shutdown()
        server.server_close()

    assert result.returncode == 2
    assert status.encode() in result.stderr
    assert b"Tool execution blocked" in result.stderr


def test_guard_uses_a_protected_cached_blocking_status(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    write_json(
        fixture.agent_dir / "status-cache.json",
        {"status": "frozen", "cached_at": time.time()},
    )
    guard = managed_handler(fixture.settings(), "PreToolUse", GUARD_STATUS)

    result = run_handler(guard, encoded(payload("PreToolUse")), fixture)

    assert result.returncode == 2
    assert b"Tool execution blocked" in result.stderr


def test_fail_open_guard_reports_input_config_and_status_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    server = start_api_server()
    try:
        fixture = prepare_fixture(
            monkeypatch,
            tmp_path,
            base_url=server_base_url(server),
        )
        fixture.install()
        guard = managed_handler(fixture.settings(), "PreToolUse", GUARD_STATUS)
        runtime_config = json.loads(
            fixture.runtime_config_path.read_text(encoding="utf-8")
        )

        malformed_input = run_handler(guard, b"{ malformed", fixture)
        non_object_input = run_handler(guard, b"[]", fixture)
        write_text(fixture.runtime_config_path, "{ malformed")
        malformed_config = run_handler(
            guard,
            encoded(payload("PreToolUse")),
            fixture,
        )
        write_json(fixture.runtime_config_path, runtime_config)
        (fixture.agent_dir / "status-cache.json").unlink()
        ElydoraApiHandler.agent_status = "unknown"
        invalid_status = run_handler(
            guard,
            encoded(payload("PreToolUse")),
            fixture,
        )
    finally:
        server.shutdown()
        server.server_close()

    assert malformed_input.returncode == 0
    assert b"invalid JSON" in malformed_input.stderr
    assert b"fail-open" in malformed_input.stderr
    assert non_object_input.returncode == 0
    assert b"JSON object" in non_object_input.stderr
    assert b"fail-open" in non_object_input.stderr
    assert malformed_config.returncode == 0
    assert b"Failed to read agent config" in malformed_config.stderr
    assert invalid_status.returncode == 0
    assert b"invalid agent status" in invalid_status.stderr


def test_generated_hooks_report_an_unsafe_runtime_origin(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    config = json.loads(fixture.runtime_config_path.read_text(encoding="utf-8"))
    config["base_url"] = "https://api.elydora.com\\evil"
    write_json(fixture.runtime_config_path, config)
    (fixture.agent_dir / "status-cache.json").unlink(missing_ok=True)
    settings = fixture.settings()

    guard_result = run_handler(
        managed_handler(settings, "PreToolUse", GUARD_STATUS),
        encoded(payload("PreToolUse")),
        fixture,
    )
    audit_result = run_handler(
        managed_handler(settings, "PostToolUse", AUDIT_STATUS),
        encoded(payload("PostToolUse")),
        fixture,
    )

    assert guard_result.returncode == 0
    assert b"absolute HTTP or HTTPS URL" in guard_result.stderr
    assert audit_result.returncode == 0
    assert "absolute HTTP or HTTPS URL" in (fixture.agent_dir / "error.log").read_text(
        encoding="utf-8"
    )


@pytest.mark.parametrize(
    ("target", "source", "message"),
    [
        ("input", "{ malformed", "invalid JSON"),
        ("config.json", "{ malformed", "agent config"),
        ("private.key", "invalid", "Private key"),
        ("chain-state.json", "{ malformed", "Chain state"),
    ],
)
def test_fail_open_audit_records_runtime_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    target: str,
    source: str,
    message: str,
) -> None:
    server = start_api_server()
    try:
        fixture = prepare_fixture(
            monkeypatch,
            tmp_path,
            base_url=server_base_url(server),
        )
        fixture.install()
        audit = managed_handler(fixture.settings(), "PostToolUse", AUDIT_STATUS)
        if target != "input":
            write_text(fixture.agent_dir / target, source)
        runtime_input = (
            source.encode() if target == "input" else encoded(payload("PostToolUse"))
        )
        result = run_handler(audit, runtime_input, fixture)
    finally:
        server.shutdown()
        server.server_close()

    assert result.returncode == 0
    error_log = fixture.agent_dir / "error.log"
    assert error_log.is_file()
    assert message.lower() in error_log.read_text(encoding="utf-8").lower()


def test_fail_open_audit_records_api_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    server = start_api_server()
    ElydoraApiHandler.post_status = 500
    try:
        fixture = prepare_fixture(
            monkeypatch,
            tmp_path,
            base_url=server_base_url(server),
        )
        fixture.install()
        audit = managed_handler(fixture.settings(), "PostToolUse", AUDIT_STATUS)
        result = run_handler(audit, encoded(payload("PostToolUse")), fixture)
    finally:
        server.shutdown()
        server.server_close()

    assert result.returncode == 0
    assert "HTTP 500" in (fixture.agent_dir / "error.log").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "target", ["status-cache.json", "chain-state.json", "error.log"]
)
def test_runtimes_reject_linked_cache_chain_and_error_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    target: str,
) -> None:
    server = start_api_server()
    try:
        fixture = prepare_fixture(
            monkeypatch,
            tmp_path,
            base_url=server_base_url(server),
        )
        fixture.install()
        target_path = tmp_path / f"{target}.target"
        source = {
            "status-cache.json": json.dumps(
                {"status": "active", "cached_at": time.time()}
            ),
            "chain-state.json": json.dumps({"prev_chain_hash": "A" * 43}),
            "error.log": "preserve\n",
        }[target]
        write_text(target_path, source)
        link = fixture.agent_dir / target
        symlink_or_skip(target_path, link)
        if target == "status-cache.json":
            handler = managed_handler(fixture.settings(), "PreToolUse", GUARD_STATUS)
            runtime_input = encoded(payload("PreToolUse"))
        else:
            handler = managed_handler(fixture.settings(), "PostToolUse", AUDIT_STATUS)
            runtime_input = (
                b"{ malformed"
                if target == "error.log"
                else encoded(payload("PostToolUse"))
            )
        result = run_handler(handler, runtime_input, fixture)
    finally:
        server.shutdown()
        server.server_close()

    assert result.returncode == 0
    assert target_path.read_text(encoding="utf-8") == source
    if target == "error.log":
        assert b"Failed to write error log" in result.stderr
    else:
        assert (
            b"physical file" in result.stderr
            or (fixture.agent_dir / "error.log").is_file()
        )
