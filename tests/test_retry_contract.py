import json
import logging
import threading
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Tuple, cast

import pytest

from elydora import AsyncElydoraClient, ElydoraClient, ElydoraError
from elydora._retry import (
    can_retry,
    retry_delay_seconds,
    should_retry_response,
)

ScriptedResponse = Tuple[int, Dict[str, str], object]


class ScriptedServer(ThreadingHTTPServer):
    responses: List[ScriptedResponse]
    methods: List[str]


class ScriptedHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self._respond()

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length:
            self.rfile.read(content_length)
        self._respond()

    def _respond(self) -> None:
        server = cast(ScriptedServer, self.server)
        server.methods.append(self.command)
        status, headers, body = server.responses.pop(0)
        encoded = json.dumps(body).encode()
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, _format: str, *args: object) -> None:
        pass


@pytest.fixture
def scripted_server():
    server = ScriptedServer(("127.0.0.1", 0), ScriptedHandler)
    server.responses = []
    server.methods = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def base_url(server: ScriptedServer) -> str:
    host, port = server.server_address
    return f"http://{host}:{port}"


def error_response(status: int, retry_after: str = "") -> ScriptedResponse:
    headers = {"Retry-After": retry_after} if retry_after else {}
    return (
        status,
        headers,
        {"error": {"code": "INTERNAL_ERROR", "message": "temporary failure"}},
    )


def test_retry_policy_matches_http_semantics() -> None:
    assert should_retry_response("GET", 503, 0, 1)
    assert should_retry_response("delete", 429, 0, 1)
    assert not should_retry_response("POST", 503, 0, 1)
    assert not should_retry_response("GET", 501, 0, 1)
    assert not should_retry_response("GET", 503, 1, 1)
    assert can_retry("POST", 0, 1, request_known_unprocessed=True)


def test_retry_after_supports_seconds_and_http_dates() -> None:
    now = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)
    retry_at = format_datetime(now + timedelta(seconds=30), usegmt=True)

    assert retry_delay_seconds(0, "15", now=now) == 15
    assert retry_delay_seconds(0, retry_at, now=now) == 30
    assert retry_delay_seconds(2, "invalid", now=now) == 4
    assert retry_delay_seconds(4, None, now=now) == 8


@pytest.mark.parametrize("value", [-1, True, 1.5, "2"])
def test_clients_reject_invalid_retry_configuration(value: object) -> None:
    with pytest.raises(ValueError, match="non-negative integer"):
        ElydoraClient("org", "agent", "key", max_retries=value)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="non-negative integer"):
        AsyncElydoraClient("org", "agent", "key", max_retries=value)  # type: ignore[arg-type]


def test_zero_retries_still_performs_one_sync_request(
    scripted_server: ScriptedServer,
) -> None:
    scripted_server.responses = [(200, {}, {"user_id": "user-1"})]
    client = ElydoraClient(
        "org", "agent", "key", base_url=base_url(scripted_server), max_retries=0
    )

    assert client.get_me()["user_id"] == "user-1"
    assert scripted_server.methods == ["GET"]


@pytest.mark.asyncio
async def test_zero_retries_still_performs_one_async_request(
    scripted_server: ScriptedServer,
) -> None:
    scripted_server.responses = [(200, {}, {"user_id": "user-1"})]
    client = AsyncElydoraClient(
        "org", "agent", "key", base_url=base_url(scripted_server), max_retries=0
    )
    try:
        response = await client.get_me()
        assert response["user_id"] == "user-1"
        assert scripted_server.methods == ["GET"]
    finally:
        await client.close()


def test_sync_client_retries_idempotent_responses(
    scripted_server: ScriptedServer,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    scripted_server.responses = [
        error_response(503, "0"),
        error_response(500),
        (200, {}, {"user_id": "user-1"}),
    ]
    delays: List[float] = []
    monkeypatch.setattr("elydora._sync_http.time.sleep", delays.append)
    caplog.set_level(logging.WARNING, logger="elydora._sync_http")
    client = ElydoraClient(
        "org", "agent", "key", base_url=base_url(scripted_server), max_retries=2
    )

    assert client.get_me()["user_id"] == "user-1"
    assert scripted_server.methods == ["GET", "GET", "GET"]
    assert delays == [0.0, 2.0]
    retry_logs = [
        record.getMessage()
        for record in caplog.records
        if record.name == "elydora._sync_http"
    ]
    assert "retry=1/2 delay_seconds=0.0 reason=http_503" in retry_logs[0]
    assert "retry=2/2 delay_seconds=2.0 reason=http_500" in retry_logs[1]


@pytest.mark.asyncio
async def test_async_client_retries_idempotent_responses(
    scripted_server: ScriptedServer,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    scripted_server.responses = [
        error_response(429, "0"),
        error_response(502),
        (200, {}, {"user_id": "user-1"}),
    ]
    delays: List[float] = []

    async def record_sleep(delay: float) -> None:
        delays.append(delay)

    monkeypatch.setattr("elydora._async_http.asyncio.sleep", record_sleep)
    caplog.set_level(logging.WARNING, logger="elydora._async_http")
    client = AsyncElydoraClient(
        "org", "agent", "key", base_url=base_url(scripted_server), max_retries=2
    )
    try:
        response = await client.get_me()
        assert response["user_id"] == "user-1"
        assert scripted_server.methods == ["GET", "GET", "GET"]
        assert delays == [0.0, 2.0]
        retry_logs = [
            record.getMessage()
            for record in caplog.records
            if record.name == "elydora._async_http"
        ]
        assert "retry=1/2 delay_seconds=0.0 reason=http_429" in retry_logs[0]
        assert "retry=2/2 delay_seconds=2.0 reason=http_502" in retry_logs[1]
    finally:
        await client.close()


def test_sync_client_does_not_replay_non_idempotent_requests(
    scripted_server: ScriptedServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scripted_server.responses = [
        error_response(503),
        (200, {}, {"token": "duplicate"}),
    ]
    delays: List[float] = []
    monkeypatch.setattr("elydora._sync_http.time.sleep", delays.append)
    client = ElydoraClient(
        "org", "agent", "key", base_url=base_url(scripted_server), max_retries=3
    )

    with pytest.raises(ElydoraError) as error:
        client.issue_token()
    assert error.value.status_code == 503
    assert scripted_server.methods == ["POST"]
    assert delays == []


@pytest.mark.asyncio
async def test_async_client_does_not_replay_non_idempotent_requests(
    scripted_server: ScriptedServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scripted_server.responses = [
        error_response(503),
        (200, {}, {"token": "duplicate"}),
    ]
    delays: List[float] = []

    async def record_sleep(delay: float) -> None:
        delays.append(delay)

    monkeypatch.setattr("elydora._async_http.asyncio.sleep", record_sleep)
    client = AsyncElydoraClient(
        "org", "agent", "key", base_url=base_url(scripted_server), max_retries=3
    )
    try:
        with pytest.raises(ElydoraError) as error:
            await client.issue_token()
        assert error.value.status_code == 503
        assert scripted_server.methods == ["POST"]
        assert delays == []
    finally:
        await client.close()
