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
from tomlkit import parse

from elydora.plugins.kimi import KimiPlugin
from elydora.utils import base64url_encode


AGENT_ID = "agent-1"
MISSING = object()
VALID_PRIVATE_KEY = base64url_encode(bytes(range(32)))


@dataclass
class KimiFixture:
    root_dir: Path
    home_dir: Path
    project_dir: Path
    kimi_home: Path
    stable_path: Path
    legacy_home: Path
    legacy_path: Path
    agent_dir: Path
    guard_path: Path
    hook_path: Path
    runtime_config_path: Path
    private_key_path: Path
    plugin: KimiPlugin
    config: dict[str, str]

    def install(self) -> None:
        self.plugin.install(self.config)


class KimiApiHandler(BaseHTTPRequestHandler):
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
        type(self).requests.append(
            {
                "method": "GET",
                "path": self.path,
                "authorization": self.headers.get("Authorization"),
            }
        )
        self._respond(200, {"agent": {"status": type(self).agent_status}})

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
        status = type(self).operation_status
        value: object = (
            {"operation": {"accepted": True}}
            if 200 <= status < 300
            else {"error": {"code": "UPSTREAM_FAILURE", "message": "failed"}}
        )
        self._respond(status, value)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def start_api_server(
    *, status: str = "active", operation_status: int = 201
) -> ThreadingHTTPServer:
    KimiApiHandler.reset()
    KimiApiHandler.agent_status = status
    KimiApiHandler.operation_status = operation_status
    server = ThreadingHTTPServer(("127.0.0.1", 0), KimiApiHandler)
    Thread(target=server.serve_forever, daemon=True).start()
    return server


def server_base_url(server: ThreadingHTTPServer) -> str:
    return f"http://127.0.0.1:{server.server_port}"


def write_text(path: Path, source: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    os.chmod(path, mode)


def write_optional(path: Path, value: object) -> None:
    if value is MISSING:
        return
    write_text(path, str(value))


def prepare_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    stable_config: object = MISSING,
    legacy_config: object = MISSING,
    stable_detected: bool = True,
    legacy_detected: bool = True,
    explicit_kimi_home: bool = True,
    base_url: str = "http://127.0.0.1:9",
) -> KimiFixture:
    home_dir = tmp_path / "home with spaces and 'quote %ELYDORA_HOOK_PATH%"
    project_dir = tmp_path / "project with spaces"
    kimi_home = (
        home_dir / "custom kimi-code"
        if explicit_kimi_home
        else home_dir / ".kimi-code"
    )
    stable_path = kimi_home / "config.toml"
    legacy_home = home_dir / ".kimi"
    legacy_path = legacy_home / "config.toml"
    agent_dir = home_dir / ".elydora" / AGENT_ID
    guard_path = agent_dir / "guard.py"
    hook_path = agent_dir / "hook.py"
    project_dir.mkdir(parents=True)
    if stable_detected and not explicit_kimi_home:
        kimi_home.mkdir(parents=True)
    if legacy_detected:
        legacy_home.mkdir(parents=True)
    write_optional(stable_path, stable_config)
    write_optional(legacy_path, legacy_config)

    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("USERPROFILE", str(home_dir))
    monkeypatch.setenv("ELYDORA_HOOK_PATH", str(tmp_path / "expanded"))
    if explicit_kimi_home:
        monkeypatch.setenv("KIMI_CODE_HOME", str(kimi_home))
    else:
        monkeypatch.delenv("KIMI_CODE_HOME", raising=False)

    config = {
        "org_id": "org-1",
        "agent_id": AGENT_ID,
        "agent_name": "kimi",
        "private_key": VALID_PRIVATE_KEY,
        "kid": "kid-1",
        "token": "token-1",
        "base_url": base_url,
        "guard_script_path": str(guard_path),
    }
    return KimiFixture(
        root_dir=tmp_path,
        home_dir=home_dir,
        project_dir=project_dir,
        kimi_home=kimi_home,
        stable_path=stable_path,
        legacy_home=legacy_home,
        legacy_path=legacy_path,
        agent_dir=agent_dir,
        guard_path=guard_path,
        hook_path=hook_path,
        runtime_config_path=agent_dir / "config.json",
        private_key_path=agent_dir / "private.key",
        plugin=KimiPlugin(),
        config=config,
    )


def parsed_hooks(path: Path) -> list[dict[str, Any]]:
    value = parse(path.read_text(encoding="utf-8"))["hooks"].unwrap()
    assert isinstance(value, list)
    return value


def managed_hook(
    hooks: list[dict[str, Any]], event: str
) -> dict[str, Any]:
    return next(
        hook
        for hook in reversed(hooks)
        if hook.get("event") == event and hook.get("timeout") == 10
    )


def assert_managed_hook(hook: Mapping[str, Any], event: str) -> None:
    assert set(hook) == {"event", "command", "timeout"}
    assert hook["event"] == event
    assert hook["timeout"] == 10
    command = str(hook["command"])
    if os.name == "nt":
        assert "powershell.exe" in command.lower()
        assert " -EncodedCommand " in command
    else:
        assert command.startswith("'")


def assert_managed_triple(hooks: list[dict[str, Any]]) -> None:
    for event in ("PreToolUse", "PostToolUse", "PostToolUseFailure"):
        assert_managed_hook(managed_hook(hooks, event), event)
    assert managed_hook(hooks, "PostToolUse")["command"] == managed_hook(
        hooks, "PostToolUseFailure"
    )["command"]


def run_hook(
    command: str,
    payload: str,
    fixture: KimiFixture,
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
