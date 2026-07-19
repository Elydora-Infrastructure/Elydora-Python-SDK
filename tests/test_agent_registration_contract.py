import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import get_args

import pytest

from elydora import (
    AsyncElydoraClient,
    ElydoraClient,
    INTEGRATION_TYPES,
    IntegrationType,
    RegisterAgentRequest,
)

EXPECTED_INTEGRATION_TYPES = (
    "augment", "claudecode", "cline", "codex", "copilot", "cursor", "droid",
    "gemini", "grok", "kimi", "kirocli", "kiroide", "letta", "opencode", "qwen",
    "enterprise", "gui", "sdk", "other",
)


class RegistrationHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        content_length = int(self.headers["Content-Length"])
        body = json.loads(self.rfile.read(content_length))
        self.server.requests.append({
            "method": self.command,
            "path": self.path,
            "authorization": self.headers.get("Authorization"),
            "body": body,
        })
        response = json.dumps({
            "agent": {
                "agent_id": body["agent_id"],
                "org_id": "org-1",
                "display_name": body.get("display_name", ""),
                "responsible_entity": body.get("responsible_entity", ""),
                "integration_type": body["integration_type"],
                "status": "active",
                "created_at": 1,
                "updated_at": 1,
            },
            "keys": [],
        }).encode()
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, _format: str, *args: object) -> None:
        pass


@pytest.fixture
def registration_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), RegistrationHandler)
    server.requests = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def registration_request():
    return {
        "agent_id": "agent-1",
        "integration_type": "grok",
        "display_name": "Grok Agent",
        "responsible_entity": "platform@example.com",
        "keys": [{"kid": "key-v1", "public_key": "public-key", "algorithm": "ed25519"}],
    }


def expected_http_request():
    return {
        "method": "POST",
        "path": "/v1/agents/register",
        "authorization": "Bearer api-token",
        "body": registration_request(),
    }


def test_integration_types_match_public_api_contract() -> None:
    assert INTEGRATION_TYPES == EXPECTED_INTEGRATION_TYPES
    assert get_args(IntegrationType) == EXPECTED_INTEGRATION_TYPES
    assert RegisterAgentRequest.__required_keys__ == frozenset({
        "agent_id", "integration_type", "keys",
    })
    assert RegisterAgentRequest.__optional_keys__ == frozenset({
        "display_name", "responsible_entity",
    })


def test_sync_registration_requires_and_sends_integration_type(registration_server) -> None:
    host, port = registration_server.server_address
    client = ElydoraClient(
        "org-1", "admin-agent", "unused",
        base_url=f"http://{host}:{port}", max_retries=0, token="api-token",
    )
    with pytest.raises(ValueError, match="Invalid integration_type None"):
        client.register_agent({"agent_id": "agent-1", "keys": []})
    with pytest.raises(ValueError, match="Invalid integration_type 'future-cli'"):
        client.register_agent({
            "agent_id": "agent-1", "integration_type": "future-cli", "keys": [],
        })
    with pytest.raises(ValueError, match="Invalid integration_type 'future-cli'"):
        client.update_agent("agent-1", "future-cli")
    assert registration_server.requests == []

    response = client.register_agent(registration_request())

    assert response["agent"]["integration_type"] == "grok"
    assert registration_server.requests == [expected_http_request()]


@pytest.mark.asyncio
async def test_async_registration_requires_and_sends_integration_type(registration_server) -> None:
    host, port = registration_server.server_address
    client = AsyncElydoraClient(
        "org-1", "admin-agent", "unused",
        base_url=f"http://{host}:{port}", max_retries=0, token="api-token",
    )
    try:
        with pytest.raises(ValueError, match="Invalid integration_type None"):
            await client.register_agent({"agent_id": "agent-1", "keys": []})
        with pytest.raises(ValueError, match="Invalid integration_type 'future-cli'"):
            await client.update_agent("agent-1", "future-cli")
        assert registration_server.requests == []

        response = await client.register_agent(registration_request())

        assert response["agent"]["integration_type"] == "grok"
        assert registration_server.requests == [expected_http_request()]
    finally:
        await client.close()
