from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from letta_support import (
    ElydoraApiHandler,
    assert_managed_triple,
    official_input,
    prepare_fixture,
    run_handler,
    server_base_url,
    start_api_server,
)


def _payload(value: object) -> bytes:
    return json.dumps(value).encode()


def test_guard_accepts_active_agents_with_native_exit_semantics(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server = start_api_server(status="active")
    fixture = prepare_fixture(
        monkeypatch, tmp_path, base_url=server_base_url(server)
    )
    try:
        fixture.install()
        guard = assert_managed_triple(fixture.settings())["guard"]
        result = run_handler(
            guard,
            _payload(official_input(fixture, "PreToolUse")),
            fixture,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout == b""
        assert len([
            request for request in ElydoraApiHandler.requests
            if request["method"] == "GET"
        ]) == 1
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("status", ["frozen", "revoked"])
def test_guard_propagates_blocking_states_through_exit_code_two(
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
            _payload(official_input(fixture, "PreToolUse")),
            fixture,
        )
        assert result.returncode == 2, result.stderr
        assert result.stdout == b""
        assert status.encode() in result.stderr.lower()
    finally:
        server.shutdown()
        server.server_close()


def test_audit_forwards_complete_success_and_failure_payloads(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server = start_api_server()
    fixture = prepare_fixture(
        monkeypatch, tmp_path, base_url=server_base_url(server)
    )
    try:
        fixture.install()
        handlers = assert_managed_triple(fixture.settings())
        for handler_name, event in (
            ("audit", "PostToolUse"),
            ("failure", "PostToolUseFailure"),
        ):
            payload = {
                **official_input(fixture, event),
                "future_provider_field": {"preserved": True},
            }
            result = run_handler(
                handlers[handler_name], _payload(payload), fixture
            )
            assert result.returncode == 0, result.stderr
            assert result.stdout == b""
        posts = [
            request for request in ElydoraApiHandler.requests
            if request["method"] == "POST"
        ]
        assert len(posts) == 2
        assert posts[0]["json"]["payload"] == {
            **official_input(fixture, "PostToolUse"),
            "future_provider_field": {"preserved": True},
        }
        assert posts[1]["json"]["payload"] == {
            **official_input(fixture, "PostToolUseFailure"),
            "future_provider_field": {"preserved": True},
        }
    finally:
        server.shutdown()
        server.server_close()


def test_audit_failure_is_observable_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    audit = assert_managed_triple(fixture.settings())["audit"]
    result = run_handler(
        audit,
        _payload(official_input(fixture, "PostToolUse")),
        fixture,
    )
    assert result.returncode == 1
    assert b"Elydora audit" in result.stderr
    error_log = fixture.agent_dir / "error.log"
    source = error_log.read_text(encoding="utf-8")
    assert "[elydora-hook]" in source
    assert "URLError" in source


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits apply on Unix")
def test_runtime_artifacts_use_private_modes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    for file_path, expected in (
        (fixture.runtime_config_path, 0o600),
        (fixture.private_key_path, 0o600),
        (fixture.guard_path, 0o700),
        (fixture.audit_path, 0o700),
        (fixture.global_path, 0o600),
    ):
        assert file_path.stat().st_mode & 0o777 == expected
