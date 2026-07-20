from __future__ import annotations

from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shlex
import subprocess  # nosec B404
import sys
from threading import Thread
from typing import Any, Mapping

import pytest

from elydora.plugins.grok import GrokPlugin
from elydora.utils import base64url_encode


AGENT_ID = "agent-1"
MISSING = object()
VALID_PRIVATE_KEY = base64url_encode(bytes(range(32)))


@dataclass
class GrokFixture:
    root_dir: Path
    home_dir: Path
    project_dir: Path
    grok_home: Path
    config_path: Path
    agent_dir: Path
    guard_path: Path
    hook_path: Path
    runtime_config_path: Path
    private_key_path: Path
    plugin: GrokPlugin
    config: dict[str, str]

    def install(self) -> None:
        self.plugin.install(self.config)

    def settings(self) -> dict[str, Any]:
        return json.loads(self.config_path.read_text(encoding="utf-8"))


class GrokApiHandler(BaseHTTPRequestHandler):
    agent_status: Any = "active"
    operation_status = 201
    requests: list[dict[str, Any]] = []

    @classmethod
    def reset(cls) -> None:
        cls.agent_status = "active"
        cls.operation_status = 201
        cls.requests = []

    def _respond(self, status: int, value: object) -> None:
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        type(self).requests.append({
            "method": "GET",
            "path": self.path,
            "authorization": self.headers.get("Authorization"),
        })
        self._respond(200, {"agent": {"status": type(self).agent_status}})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        type(self).requests.append({
            "method": "POST",
            "path": self.path,
            "authorization": self.headers.get("Authorization"),
            "raw": raw,
            "json": json.loads(raw),
        })
        status = type(self).operation_status
        response: object = (
            {"operation": {"accepted": True}}
            if 200 <= status < 300
            else {"error": {"code": "UPSTREAM_FAILURE", "message": "failed"}}
        )
        self._respond(status, response)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def start_api_server(
    *, status: str = "active", operation_status: int = 201
) -> ThreadingHTTPServer:
    GrokApiHandler.reset()
    GrokApiHandler.agent_status = status
    GrokApiHandler.operation_status = operation_status
    server = ThreadingHTTPServer(("127.0.0.1", 0), GrokApiHandler)
    Thread(target=server.serve_forever, daemon=True).start()
    return server


def server_base_url(server: ThreadingHTTPServer) -> str:
    return f"http://127.0.0.1:{server.server_port}"


def write_text(path: Path, source: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    os.chmod(path, mode)


def prepare_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    existing_config: object = MISSING,
    explicit_grok_home: bool = True,
    base_url: str = "http://127.0.0.1:9",
) -> GrokFixture:
    home_dir = tmp_path / "home with spaces and 'quote %GROK_HOOK_EVENT%"
    project_dir = tmp_path / "project with spaces"
    grok_home = (
        home_dir / "custom grok"
        if explicit_grok_home
        else home_dir / ".grok"
    )
    config_path = grok_home / "hooks" / "elydora-audit.json"
    agent_dir = home_dir / ".elydora" / AGENT_ID
    guard_path = agent_dir / "guard.py"
    hook_path = agent_dir / "hook.py"
    project_dir.mkdir(parents=True)
    if existing_config is not MISSING:
        source = (
            str(existing_config)
            if isinstance(existing_config, str)
            else json.dumps(existing_config, indent=2) + "\n"
        )
        write_text(config_path, source)

    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("USERPROFILE", str(home_dir))
    monkeypatch.setenv("GROK_HOOK_EVENT", "injected-command-fragment")
    if explicit_grok_home:
        monkeypatch.setenv("GROK_HOME", str(grok_home))
    else:
        monkeypatch.delenv("GROK_HOME", raising=False)

    return GrokFixture(
        root_dir=tmp_path,
        home_dir=home_dir,
        project_dir=project_dir,
        grok_home=grok_home,
        config_path=config_path,
        agent_dir=agent_dir,
        guard_path=guard_path,
        hook_path=hook_path,
        runtime_config_path=agent_dir / "config.json",
        private_key_path=agent_dir / "private.key",
        plugin=GrokPlugin(),
        config={
            "org_id": "org-1",
            "agent_id": AGENT_ID,
            "agent_name": "grok",
            "private_key": VALID_PRIVATE_KEY,
            "kid": "kid-1",
            "token": "token-1",
            "base_url": base_url,
            "guard_script_path": str(guard_path),
        },
    )


def managed_handler(settings: Mapping[str, Any], event: str) -> dict[str, Any]:
    for group in reversed(settings.get("hooks", {}).get(event, [])):
        if set(group) != {"hooks"} or not isinstance(group["hooks"], list):
            continue
        for handler in reversed(group["hooks"]):
            if (
                set(handler) == {"type", "command", "timeout"}
                and handler.get("type") == "command"
                and handler.get("timeout") == 10
            ):
                return handler
    raise AssertionError(f"managed {event} handler not found")


def assert_managed_handler(handler: Mapping[str, Any]) -> None:
    assert set(handler) == {"type", "command", "timeout"}
    assert handler["type"] == "command"
    assert handler["timeout"] == 10
    command = str(handler["command"])
    if os.name == "nt":
        assert "powershell.exe" in command.lower()
        assert " -EncodedCommand " in command
    else:
        assert command.startswith("'")


def assert_managed_triple(settings: Mapping[str, Any]) -> None:
    for event in ("PreToolUse", "PostToolUse", "PostToolUseFailure"):
        assert_managed_handler(managed_handler(settings, event))
    assert managed_handler(settings, "PostToolUse")["command"] == managed_handler(
        settings, "PostToolUseFailure"
    )["command"]


def run_hook(
    command: str,
    payload: str,
    fixture: GrokFixture,
    environment: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        shell=True,
        input=payload,
        capture_output=True,
        check=False,
        cwd=fixture.project_dir,
        env={
            **os.environ,
            "HOME": str(fixture.home_dir),
            "USERPROFILE": str(fixture.home_dir),
            **dict(environment or {}),
        },
        text=True,
    )


def legacy_command(script_path: Path) -> str:
    arguments = [sys.executable, str(script_path)]
    return (
        subprocess.list2cmdline(arguments)
        if os.name == "nt"
        else shlex.join(arguments)
    )


def assert_no_transaction_files(root: Path) -> None:
    assert not list(root.rglob("*.tmp"))
    assert not list(root.rglob("*.rollback"))
