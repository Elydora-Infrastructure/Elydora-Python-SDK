from __future__ import annotations

from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess  # nosec B404
import sys
from threading import Thread
from typing import Any, Mapping

import pytest

from elydora.plugins.cursor import CursorPlugin
from elydora.utils import base64url_encode


AGENT_ID = "agent-1"
VALID_PRIVATE_KEY = base64url_encode(bytes(range(32)))


@dataclass
class CursorFixture:
    home_dir: Path
    config_path: Path
    agent_dir: Path
    guard_path: Path
    hook_path: Path
    runtime_config_path: Path
    private_key_path: Path
    plugin: CursorPlugin
    config: dict[str, str]

    def install(self) -> None:
        self.plugin.install(self.config)

    def settings(self) -> dict[str, Any]:
        return json.loads(self.config_path.read_text(encoding="utf-8"))


class ElydoraApiHandler(BaseHTTPRequestHandler):
    agent_status = "active"
    get_status = 200
    post_status = 201
    get_paths: list[str] = []
    operations: list[dict[str, Any]] = []
    authorizations: list[str | None] = []

    @classmethod
    def reset(cls) -> None:
        cls.agent_status = "active"
        cls.get_status = 200
        cls.post_status = 201
        cls.get_paths = []
        cls.operations = []
        cls.authorizations = []

    def _respond(self, status: int, value: object) -> None:
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        type(self).get_paths.append(self.path)
        type(self).authorizations.append(self.headers.get("Authorization"))
        self._respond(
            type(self).get_status,
            {"agent": {"status": type(self).agent_status}},
        )

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        value = json.loads(self.rfile.read(length))
        assert isinstance(value, dict)
        type(self).operations.append(value)
        type(self).authorizations.append(self.headers.get("Authorization"))
        self._respond(type(self).post_status, {"ok": True})

    def log_message(self, _format: str, *_args: object) -> None:
        return


def start_api_server() -> ThreadingHTTPServer:
    ElydoraApiHandler.reset()
    server = ThreadingHTTPServer(("127.0.0.1", 0), ElydoraApiHandler)
    Thread(target=server.serve_forever, daemon=True).start()
    return server


def server_base_url(server: ThreadingHTTPServer) -> str:
    return f"http://127.0.0.1:{server.server_port}"


def write_text(path: Path, source: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    os.chmod(path, mode)


def write_json(path: Path, value: object, mode: int = 0o600) -> None:
    source = value if isinstance(value, str) else json.dumps(value, indent=2) + "\n"
    write_text(path, source, mode)


def prepare_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    existing_config: object | None = None,
) -> CursorFixture:
    home_dir = tmp_path / "home with spaces and 'quote"
    config_path = home_dir / ".cursor" / "hooks.json"
    agent_dir = home_dir / ".elydora" / AGENT_ID
    guard_path = agent_dir / "guard.py"
    hook_path = agent_dir / "hook.py"
    runtime_config_path = agent_dir / "config.json"
    private_key_path = agent_dir / "private.key"
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("USERPROFILE", str(home_dir))
    agent_dir.mkdir(parents=True)
    if existing_config is not None:
        write_json(config_path, existing_config)
    return CursorFixture(
        home_dir=home_dir,
        config_path=config_path,
        agent_dir=agent_dir,
        guard_path=guard_path,
        hook_path=hook_path,
        runtime_config_path=runtime_config_path,
        private_key_path=private_key_path,
        plugin=CursorPlugin(),
        config={
            "org_id": "org-1",
            "agent_id": AGENT_ID,
            "agent_name": "cursor",
            "private_key": VALID_PRIVATE_KEY,
            "kid": "key-1",
            "token": "token-1",
            "base_url": "https://api.elydora.com",
            "guard_script_path": str(guard_path),
        },
    )


def managed_handler(
    settings: Mapping[str, Any],
    event: str,
    script: str,
) -> dict[str, Any]:
    handlers = settings["hooks"][event]
    return next(handler for handler in handlers if script in handler.get("command", ""))


def assert_native_handler(handler: dict[str, Any]) -> None:
    assert set(handler) == {"command", "timeout", "failClosed"}
    assert handler["timeout"] == 10
    assert handler["failClosed"] is True
    assert sys.executable.lower() in handler["command"].lower()
    if os.name == "nt":
        assert handler["command"].startswith("& '")
        assert handler["command"].endswith("; exit $LASTEXITCODE")
    else:
        assert handler["command"].startswith("'")


def run_handler(
    handler: Mapping[str, Any],
    payload: bytes,
    environment: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    if os.name == "nt":
        arguments = [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            handler["command"],
        ]
    else:
        arguments = ["/bin/sh", "-c", handler["command"]]
    return subprocess.run(
        arguments,
        input=payload,
        capture_output=True,
        check=False,
        env={**os.environ, **(environment or {})},
    )


def symlink_or_skip(target: Path, link: Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as error:
        pytest.skip(f"Symbolic links unavailable: {error}")
