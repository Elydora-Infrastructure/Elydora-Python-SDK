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

from elydora.plugins.codex import CodexPlugin
from elydora.utils import base64url_encode


AGENT_ID = "agent-1"
MISSING = object()
VALID_PRIVATE_KEY = base64url_encode(bytes(range(32)))


@dataclass
class CodexFixture:
    root_dir: Path
    home_dir: Path
    project_dir: Path
    config_path: Path
    agent_dir: Path
    guard_path: Path
    hook_path: Path
    runtime_config_path: Path
    private_key_path: Path
    plugin: CodexPlugin
    config: dict[str, str]

    def install(self) -> None:
        self.plugin.install(self.config)

    def settings(self, path: Path | None = None) -> dict[str, Any]:
        return json.loads((path or self.config_path).read_text(encoding="utf-8"))


class ElydoraApiHandler(BaseHTTPRequestHandler):
    agent_status: Any = "active"
    get_status = 200
    post_status = 201
    requests: list[dict[str, Any]] = []

    @classmethod
    def reset(cls) -> None:
        cls.agent_status = "active"
        cls.get_status = 200
        cls.post_status = 201
        cls.requests = []

    def _respond(self, status: int, value: object) -> None:
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        type(self).requests.append(
            {
                "method": "GET",
                "path": self.path,
                "authorization": self.headers.get("Authorization"),
            }
        )
        self._respond(
            type(self).get_status,
            {"agent": {"status": type(self).agent_status}},
        )

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        type(self).requests.append(
            {
                "method": "POST",
                "path": self.path,
                "authorization": self.headers.get("Authorization"),
                "raw": raw,
                "json": json.loads(raw),
            }
        )
        self._respond(type(self).post_status, {"operation": {"accepted": True}})

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
    existing_config: object = MISSING,
    base_url: str = "http://127.0.0.1:9",
) -> CodexFixture:
    home_dir = tmp_path / "home with spaces and 'quote %ELYDORA_HOOK_PATH%"
    project_dir = tmp_path / "project with spaces"
    config_path = home_dir / ".codex" / "hooks.json"
    agent_dir = home_dir / ".elydora" / AGENT_ID
    guard_path = agent_dir / "guard.py"
    hook_path = agent_dir / "hook.py"
    runtime_config_path = agent_dir / "config.json"
    private_key_path = agent_dir / "private.key"
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("USERPROFILE", str(home_dir))
    monkeypatch.setenv("CODEX_HOME", "")
    monkeypatch.setenv("ELYDORA_HOOK_PATH", str(tmp_path / "expanded"))
    project_dir.mkdir(parents=True)
    agent_dir.mkdir(parents=True)
    if existing_config is not MISSING:
        write_json(config_path, existing_config)
    return CodexFixture(
        root_dir=tmp_path,
        home_dir=home_dir,
        project_dir=project_dir,
        config_path=config_path,
        agent_dir=agent_dir,
        guard_path=guard_path,
        hook_path=hook_path,
        runtime_config_path=runtime_config_path,
        private_key_path=private_key_path,
        plugin=CodexPlugin(),
        config={
            "org_id": "org-1",
            "agent_id": AGENT_ID,
            "agent_name": "codex",
            "private_key": VALID_PRIVATE_KEY,
            "kid": "key-1",
            "token": "token-1",
            "base_url": base_url,
            "guard_script_path": str(guard_path),
        },
    )


def managed_handler(
    settings: Mapping[str, Any],
    event: str,
    status_message: str,
) -> dict[str, Any]:
    for group in settings["hooks"][event]:
        for handler in group["hooks"]:
            if handler.get("statusMessage") == status_message:
                return handler
    raise AssertionError(f"handler {status_message!r} not found")


def assert_native_handler(handler: Mapping[str, Any], status_message: str) -> None:
    assert set(handler) == {
        "type",
        "command",
        "commandWindows",
        "timeout",
        "statusMessage",
    }
    assert handler["type"] == "command"
    assert handler["timeout"] == 10
    assert handler["statusMessage"] == status_message
    assert str(handler["command"]).startswith("'")
    assert str(handler["commandWindows"]).startswith('"')
    assert " -EncodedCommand " in str(handler["commandWindows"])


def run_handler(
    handler: Mapping[str, Any],
    payload: bytes,
    fixture: CodexFixture,
) -> subprocess.CompletedProcess[bytes]:
    command_key = "commandWindows" if os.name == "nt" else "command"
    return subprocess.run(
        str(handler[command_key]),
        shell=True,
        input=payload,
        capture_output=True,
        check=False,
        cwd=fixture.project_dir,
        env={
            **os.environ,
            "HOME": str(fixture.home_dir),
            "USERPROFILE": str(fixture.home_dir),
            "CODEX_HOME": "",
        },
    )


def legacy_handler(script_path: Path, status_message: str) -> dict[str, Any]:
    import shlex

    arguments = [sys.executable, str(script_path)]
    return {
        "type": "command",
        "command": f"{shlex.quote(arguments[0])} {shlex.quote(arguments[1])}",
        "commandWindows": subprocess.list2cmdline(arguments),
        "timeout": 10,
        "statusMessage": status_message,
    }


def symlink_or_skip(target: Path, link: Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as error:
        pytest.skip(f"Symbolic links unavailable: {error}")
