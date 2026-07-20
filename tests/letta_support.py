from __future__ import annotations

from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import ntpath
import os
from pathlib import Path
import subprocess  # nosec B404
import sys
from threading import Thread
from typing import Any, Mapping, Optional

import pytest

from elydora.plugins.letta import LettaPlugin
from elydora.utils import base64url_encode


AGENT_ID = "agent-1"
MISSING = object()
VALID_PRIVATE_KEY = base64url_encode(bytes(range(32)))


@dataclass
class LettaFixture:
    root_dir: Path
    home_dir: Path
    project_dir: Path
    global_path: Path
    project_path: Path
    local_path: Path
    agent_dir: Path
    guard_path: Path
    audit_path: Path
    runtime_config_path: Path
    private_key_path: Path
    plugin: LettaPlugin
    config: dict[str, str]

    def install(self) -> None:
        self.plugin.install(self.config)

    def source(self, file_path: Optional[Path] = None) -> str:
        path = file_path or self.global_path
        with path.open("r", encoding="utf-8", newline="") as file:
            return file.read()

    def settings(self, file_path: Optional[Path] = None) -> dict[str, Any]:
        return json.loads(self.source(file_path))


class ElydoraApiHandler(BaseHTTPRequestHandler):
    agent_status: Any = "active"
    operation_status = 201
    requests: list[dict[str, Any]] = []

    @classmethod
    def reset(cls, status: Any, operation_status: int) -> None:
        cls.agent_status = status
        cls.operation_status = operation_status
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
        self._respond(
            type(self).operation_status,
            {"operation": {"accepted": True}},
        )

    def log_message(self, _format: str, *_args: object) -> None:
        return


def start_api_server(
    *, status: Any = "active", operation_status: int = 201
) -> ThreadingHTTPServer:
    ElydoraApiHandler.reset(status, operation_status)
    server = ThreadingHTTPServer(("127.0.0.1", 0), ElydoraApiHandler)
    Thread(target=server.serve_forever, daemon=True).start()
    return server


def server_base_url(server: ThreadingHTTPServer) -> str:
    return f"http://127.0.0.1:{server.server_port}"


def write_text(path: Path, source: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8", newline="")
    os.chmod(path, mode)


def write_json(path: Path, value: object, mode: int = 0o600) -> None:
    source = value if isinstance(value, str) else json.dumps(value, indent=2) + "\n"
    write_text(path, source, mode)


def prepare_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    global_settings: object = MISSING,
    project_settings: object = MISSING,
    local_settings: object = MISSING,
    base_url: str = "http://127.0.0.1:9",
) -> LettaFixture:
    home_dir = tmp_path / "home with spaces and 'quote $HOME %HOME%"
    project_dir = tmp_path / "project with spaces"
    project_dir.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("USERPROFILE", str(home_dir))
    monkeypatch.chdir(project_dir)
    global_path = home_dir / ".letta" / "settings.json"
    project_path = project_dir / ".letta" / "settings.json"
    local_path = project_dir / ".letta" / "settings.local.json"
    agent_dir = home_dir / ".elydora" / AGENT_ID
    guard_path = agent_dir / "guard.py"
    audit_path = agent_dir / "hook.py"
    runtime_config_path = agent_dir / "config.json"
    private_key_path = agent_dir / "private.key"
    for path, value in (
        (global_path, global_settings),
        (project_path, project_settings),
        (local_path, local_settings),
    ):
        if value is not MISSING:
            write_json(path, value)
    return LettaFixture(
        root_dir=tmp_path,
        home_dir=home_dir,
        project_dir=project_dir,
        global_path=global_path,
        project_path=project_path,
        local_path=local_path,
        agent_dir=agent_dir,
        guard_path=guard_path,
        audit_path=audit_path,
        runtime_config_path=runtime_config_path,
        private_key_path=private_key_path,
        plugin=LettaPlugin(),
        config={
            "org_id": "org-1",
            "agent_id": AGENT_ID,
            "agent_name": "letta",
            "private_key": VALID_PRIVATE_KEY,
            "kid": "kid-1",
            "token": "token-1",
            "base_url": base_url,
            "guard_script_path": str(guard_path),
        },
    )


def managed_handler(
    settings: Mapping[str, Any], event: str
) -> dict[str, Any]:
    for group in settings.get("hooks", {}).get(event, []):
        if set(group) != {"matcher", "hooks"} or group.get("matcher") != "*":
            continue
        for handler in group["hooks"]:
            if (
                set(handler) == {"type", "command", "timeout"}
                and handler.get("type") == "command"
                and handler.get("timeout") == 10_000
            ):
                return handler
    raise AssertionError(f"managed handler for {event!r} not found")


def assert_managed_triple(settings: Mapping[str, Any]) -> dict[str, Any]:
    guard = managed_handler(settings, "PreToolUse")
    audit = managed_handler(settings, "PostToolUse")
    failure = managed_handler(settings, "PostToolUseFailure")
    assert audit["command"] == failure["command"]
    return {"guard": guard, "audit": audit, "failure": failure}


def legacy_group(script_path: Path, event: str) -> dict[str, Any]:
    command = (
        f'"{sys.executable}" {script_path}'
        if event == "PreToolUse"
        else str(script_path)
    )
    return {
        "matcher": "*",
        "hooks": [{"type": "command", "command": command}],
    }


def run_handler(
    handler: Mapping[str, Any], payload: bytes, fixture: LettaFixture
) -> subprocess.CompletedProcess[bytes]:
    environment = {
        **os.environ,
        "HOME": str(fixture.home_dir),
        "USERPROFILE": str(fixture.home_dir),
    }
    if os.name == "nt":
        powershell = ntpath.join(
            os.environ.get("SystemRoot", r"C:\Windows"),
            "System32",
            "WindowsPowerShell",
            "v1.0",
            "powershell.exe",
        )
        command = [
            powershell,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            str(handler["command"]),
        ]
    else:
        command = ["/bin/bash", "-c", str(handler["command"])]
    return subprocess.run(  # nosec B603
        command,
        input=payload,
        capture_output=True,
        check=False,
        cwd=fixture.project_dir,
        env=environment,
        timeout=15,
    )


def official_input(fixture: LettaFixture, event: str) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "event_type": event,
        "working_directory": str(fixture.project_dir),
        "session_id": "session-1",
        "tool_name": "Bash",
        "tool_input": {"command": "echo test"},
        "tool_call_id": "call-1",
        "agent_id": "letta-agent-1",
    }
    if event == "PostToolUse":
        payload["tool_result"] = {"status": "success", "output": "test"}
    if event == "PostToolUseFailure":
        payload.update({
            "error_message": "Command failed",
            "error_type": "ProcessError",
        })
    return payload


def run_cli(
    fixture: LettaFixture, arguments: list[str]
) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    repository = str(Path(__file__).resolve().parents[1])
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        repository + os.pathsep + existing if existing else repository
    )
    return subprocess.run(  # nosec B603
        [sys.executable, "-m", "elydora.cli", *arguments],
        text=True,
        capture_output=True,
        check=False,
        cwd=fixture.project_dir,
        env=environment,
        timeout=30,
    )
