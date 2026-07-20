from __future__ import annotations

import json
from pathlib import Path
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from cursor_support import (
    ElydoraApiHandler,
    VALID_PRIVATE_KEY,
    managed_handler,
    prepare_fixture,
    run_handler,
    server_base_url,
    start_api_server,
    write_json,
    write_text,
)
from elydora.crypto import (
    compute_chain_hash,
    compute_payload_hash,
    jcs_canonicalize,
)
from elydora.utils import base64url_decode


SUCCESS_EVENT = {
    "conversation_id": "conversation-1",
    "generation_id": "generation-1",
    "hook_event_name": "postToolUse",
    "tool_name": "Shell",
    "tool_input": {"command": "Get-ChildItem"},
    "tool_output": '{"exitCode":0,"stdout":"ok"}',
    "tool_use_id": "call-1",
    "cwd": "project",
    "duration": 42,
}
FAILURE_EVENT = {
    "conversation_id": "conversation-1",
    "generation_id": "generation-1",
    "hook_event_name": "postToolUseFailure",
    "tool_name": "Shell",
    "tool_input": {"command": "exit 1"},
    "tool_use_id": "call-2",
    "cwd": "project",
    "error_message": "command failed",
    "failure_type": "error",
    "duration": 21,
    "is_interrupt": False,
}


def _payload(value: object) -> bytes:
    return (json.dumps(value, separators=(",", ":")) + "\n").encode()


def _assert_signed_operation(operation: dict, event: dict) -> None:
    assert operation["payload"] == event
    assert operation["payload_hash"] == compute_payload_hash(event)
    assert operation["subject"] == {"session_id": event["conversation_id"]}
    assert operation["action"] == {"tool": event["tool_name"]}
    expected_chain = compute_chain_hash(
        operation["prev_chain_hash"],
        operation["payload_hash"],
        operation["operation_id"],
        operation["issued_at"],
    )
    assert operation["chain_hash"] == expected_chain
    unsigned = {
        key: value
        for key, value in operation.items()
        if key not in {"chain_hash", "signature"}
    }
    public_key = Ed25519PrivateKey.from_private_bytes(
        base64url_decode(VALID_PRIVATE_KEY)
    ).public_key()
    public_key.verify(
        base64url_decode(operation["signature"]),
        jcs_canonicalize(unsigned).encode(),
    )


def test_handlers_enforce_status_and_submit_both_native_events(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    server = start_api_server()
    try:
        fixture = prepare_fixture(monkeypatch, tmp_path)
        fixture.config["base_url"] = server_base_url(server)
        fixture.install()
        settings = fixture.settings()
        guard = managed_handler(settings, "preToolUse", "guard.py")
        success = managed_handler(settings, "postToolUse", "hook.py")
        failure = managed_handler(settings, "postToolUseFailure", "hook.py")

        guard_result = run_handler(
            guard,
            _payload({"hook_event_name": "preToolUse"}),
        )
        success_result = run_handler(success, _payload(SUCCESS_EVENT))
        failure_result = run_handler(failure, _payload(FAILURE_EVENT))
    finally:
        server.shutdown()
        server.server_close()

    assert guard_result.returncode == 0
    assert json.loads(guard_result.stdout) == {"permission": "allow"}
    assert success_result.returncode == 0
    assert json.loads(success_result.stdout) == {}
    assert failure_result.returncode == 0
    assert json.loads(failure_result.stdout) == {}
    assert ElydoraApiHandler.get_paths == ["/v1/agents/agent-1"]
    assert ElydoraApiHandler.authorizations == [
        "Bearer token-1",
        "Bearer token-1",
        "Bearer token-1",
    ]
    assert len(ElydoraApiHandler.operations) == 2
    _assert_signed_operation(ElydoraApiHandler.operations[0], SUCCESS_EVENT)
    _assert_signed_operation(ElydoraApiHandler.operations[1], FAILURE_EVENT)
    assert (
        ElydoraApiHandler.operations[1]["prev_chain_hash"]
        == ElydoraApiHandler.operations[0]["chain_hash"]
    )


@pytest.mark.parametrize("status", ["frozen", "revoked"])
def test_guard_returns_native_denial_and_exit_two_from_cache(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    status: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    write_json(
        fixture.agent_dir / "status-cache.json",
        {"status": status, "cached_at": time.time()},
    )
    guard = managed_handler(fixture.settings(), "preToolUse", "guard.py")

    result = run_handler(guard, _payload({"hook_event_name": "preToolUse"}))

    denial = json.loads(result.stdout)
    assert result.returncode == 2
    assert denial["permission"] == "deny"
    assert status in denial["userMessage"]
    assert b"Tool execution blocked" in result.stderr


@pytest.mark.parametrize(
    ("target", "source", "event"),
    [
        ("config.json", "{ malformed", "preToolUse"),
        ("config.json", "{ malformed", "postToolUse"),
        ("private.key", "invalid", "postToolUse"),
        ("chain-state.json", "{ malformed", "postToolUse"),
        (
            "status-cache.json",
            json.dumps({"status": "active", "cached_at": 4_102_444_800}),
            "preToolUse",
        ),
    ],
)
def test_runtime_integrity_failures_exit_one_and_are_observable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    target: str,
    source: str,
    event: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    write_text(fixture.agent_dir / target, source)
    script = "guard.py" if event == "preToolUse" else "hook.py"
    handler = managed_handler(fixture.settings(), event, script)
    payload = {"hook_event_name": event}

    result = run_handler(handler, _payload(payload))

    assert result.returncode == 1
    assert result.stdout == b""
    assert b"Elydora" in result.stderr
    if event != "preToolUse":
        error_log = fixture.agent_dir / "error.log"
        assert error_log.is_file()
        assert error_log.read_text(encoding="utf-8")


@pytest.mark.parametrize("event", ["preToolUse", "postToolUse"])
def test_malformed_hook_input_exits_one(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    event: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    script = "guard.py" if event == "preToolUse" else "hook.py"
    handler = managed_handler(fixture.settings(), event, script)

    result = run_handler(handler, b"{ malformed")

    assert result.returncode == 1
    assert result.stdout == b""
    assert b"invalid JSON" in result.stderr


@pytest.mark.parametrize("event", ["preToolUse", "postToolUse"])
def test_api_failures_exit_one_and_audit_failure_is_logged(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    event: str,
) -> None:
    server = start_api_server()
    ElydoraApiHandler.get_status = 500
    ElydoraApiHandler.post_status = 500
    try:
        fixture = prepare_fixture(monkeypatch, tmp_path)
        fixture.config["base_url"] = server_base_url(server)
        fixture.install()
        script = "guard.py" if event == "preToolUse" else "hook.py"
        handler = managed_handler(fixture.settings(), event, script)
        payload = {"hook_event_name": event}
        result = run_handler(handler, _payload(payload))
    finally:
        server.shutdown()
        server.server_close()

    assert result.returncode == 1
    assert result.stdout == b""
    assert b"HTTP 500" in result.stderr
    if event == "postToolUse":
        log = fixture.agent_dir / "error.log"
        assert "HTTP 500" in log.read_text(encoding="utf-8")
