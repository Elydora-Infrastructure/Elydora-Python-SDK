from __future__ import annotations

import json
import os
from pathlib import Path
import stat

import pytest

from qwen_support import (
    ElydoraApiHandler,
    assert_managed_triple,
    official_input,
    prepare_fixture,
    run_handler,
    server_base_url,
    start_api_server,
)


def _close_server(server: object) -> None:
    server.shutdown()  # type: ignore[attr-defined]
    server.server_close()  # type: ignore[attr-defined]


def test_qwen_guard_accepts_active_agents_with_native_exit_semantics(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server = start_api_server(status="active")
    fixture = prepare_fixture(
        monkeypatch, tmp_path, base_url=server_base_url(server)
    )
    try:
        fixture.install()
        guard = assert_managed_triple(fixture.settings())["guard"]
        payload = json.dumps(
            official_input(fixture, "PreToolUse")
        ).encode()
        result = run_handler(guard, payload, fixture)
        assert result.returncode == 0, result.stderr.decode()
        assert result.stdout == b""
        assert len([
            request
            for request in ElydoraApiHandler.requests
            if request["method"] == "GET"
        ]) == 1
    finally:
        _close_server(server)


@pytest.mark.parametrize("status", ["frozen", "revoked"])
def test_qwen_guard_propagates_blocking_states_through_exit_code_two(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, status: str
) -> None:
    server = start_api_server(status=status)
    fixture = prepare_fixture(
        monkeypatch, tmp_path, base_url=server_base_url(server)
    )
    try:
        fixture.install()
        guard = assert_managed_triple(fixture.settings())["guard"]
        result = run_handler(
            guard,
            json.dumps(official_input(fixture, "PreToolUse")).encode(),
            fixture,
        )
        assert result.returncode == 2
        assert result.stdout == b""
        assert status.encode() in result.stderr.lower()
    finally:
        _close_server(server)


def test_qwen_audit_forwards_complete_success_and_failure_payloads(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server = start_api_server()
    fixture = prepare_fixture(
        monkeypatch, tmp_path, base_url=server_base_url(server)
    )
    try:
        fixture.install()
        handlers = assert_managed_triple(fixture.settings())
        expected = []
        for handler_name, event in (
            ("audit", "PostToolUse"),
            ("failure", "PostToolUseFailure"),
        ):
            payload = official_input(fixture, event)
            payload["future_provider_field"] = {"preserved": True}
            expected.append(payload)
            result = run_handler(
                handlers[handler_name], json.dumps(payload).encode(), fixture
            )
            assert result.returncode == 0, result.stderr.decode()
            assert result.stdout == b""
        posts = [
            request
            for request in ElydoraApiHandler.requests
            if request["method"] == "POST"
        ]
        assert len(posts) == 2
        assert posts[0]["json"]["payload"] == expected[0]
        assert posts[1]["json"]["payload"] == expected[1]
    finally:
        _close_server(server)


def test_qwen_audit_keeps_delivery_failures_observable_and_fail_open(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    audit = assert_managed_triple(fixture.settings())["audit"]
    result = run_handler(
        audit,
        json.dumps(official_input(fixture, "PostToolUse")).encode(),
        fixture,
    )
    assert result.returncode == 0, result.stderr.decode()
    assert result.stdout == b""
    error_log = (fixture.agent_dir / "error.log").read_text(encoding="utf-8").lower()
    assert "elydora-hook" in error_log and "urlerror" in error_log


@pytest.mark.skipif(
    os.name == "nt", reason="POSIX mode bits are not authoritative on Windows"
)
def test_qwen_runtime_artifacts_use_private_modes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    for file_path, expected in (
        (fixture.runtime_config_path, 0o600),
        (fixture.private_key_path, 0o600),
        (fixture.guard_path, 0o700),
        (fixture.audit_path, 0o700),
        (fixture.config_path, 0o600),
    ):
        assert stat.S_IMODE(file_path.stat().st_mode) == expected
