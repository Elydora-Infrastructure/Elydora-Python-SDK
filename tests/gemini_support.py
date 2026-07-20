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
from typing import Any, Mapping

import pytest

from elydora.plugins._jsonc import parse_jsonc
from elydora.plugins.gemini import GeminiPlugin
from elydora.utils import base64url_encode


AGENT_ID = "agent-1"
MISSING = object()
VALID_PRIVATE_KEY = base64url_encode(bytes(range(32)))


@dataclass
class GeminiFixture:
    root_dir: Path
    home_dir: Path
    project_dir: Path
    config_path: Path
    agent_dir: Path
    guard_path: Path
    hook_path: Path
    runtime_config_path: Path
    private_key_path: Path
    plugin: GeminiPlugin
    config: dict[str, str]

    def install(self) -> None:
        self.plugin.install(self.config)

    def source(self) -> str:
        with self.config_path.open("r", encoding="utf-8", newline="") as file:
            return file.read()

    def settings(self) -> dict[str, Any]:
        value = parse_jsonc(
            self.source(),
            f"Gemini CLI test settings at {self.config_path}",
            allow_trailing_commas=False,
        )
        assert isinstance(value, dict)
        return value


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


def _settings_root(
    home_dir: Path, project_dir: Path, override: object
) -> Path:
    if override is MISSING or override == "":
        return home_dir
    configured = str(home_dir) if override is None else str(override)
    value = Path(configured)
    return value if value.is_absolute() else project_dir / value


def prepare_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    existing_settings: object = MISSING,
    base_url: str = "http://127.0.0.1:9",
    gemini_home_override: object = None,
) -> GeminiFixture:
    home_dir = tmp_path / "home with spaces and 'quote $GEMINI_CWD %GEMINI_CWD%"
    project_dir = tmp_path / "project with spaces"
    project_dir.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("USERPROFILE", str(home_dir))
    monkeypatch.chdir(project_dir)
    if gemini_home_override is MISSING:
        monkeypatch.delenv("GEMINI_CLI_HOME", raising=False)
    else:
        configured = (
            str(home_dir)
            if gemini_home_override is None
            else str(gemini_home_override)
        )
        monkeypatch.setenv("GEMINI_CLI_HOME", configured)
    config_path = (
        _settings_root(home_dir, project_dir, gemini_home_override)
        / ".gemini"
        / "settings.json"
    )
    agent_dir = home_dir / ".elydora" / AGENT_ID
    guard_path = agent_dir / "guard.py"
    hook_path = agent_dir / "hook.py"
    runtime_config_path = agent_dir / "config.json"
    private_key_path = agent_dir / "private.key"
    if existing_settings is not MISSING:
        write_json(config_path, existing_settings)
    return GeminiFixture(
        root_dir=tmp_path,
        home_dir=home_dir,
        project_dir=project_dir,
        config_path=config_path,
        agent_dir=agent_dir,
        guard_path=guard_path,
        hook_path=hook_path,
        runtime_config_path=runtime_config_path,
        private_key_path=private_key_path,
        plugin=GeminiPlugin(),
        config={
            "org_id": "org-1",
            "agent_id": AGENT_ID,
            "agent_name": "gemini",
            "private_key": VALID_PRIVATE_KEY,
            "kid": "key-1",
            "token": "token-1",
            "base_url": base_url,
            "guard_script_path": str(guard_path),
        },
    )


def managed_handler(
    settings: Mapping[str, Any], event: str, name: str
) -> dict[str, Any]:
    for group in settings["hooks"][event]:
        if set(group) != {"hooks"}:
            continue
        for handler in group["hooks"]:
            if (
                set(handler) == {"type", "name", "command", "timeout"}
                and handler.get("type") == "command"
                and handler.get("name") == name
                and handler.get("timeout") == 10_000
            ):
                return handler
    raise AssertionError(f"managed handler for {event!r} not found")


def assert_managed_handler(
    handler: Mapping[str, Any], name: str
) -> None:
    assert set(handler) == {"type", "name", "command", "timeout"}
    assert handler["type"] == "command"
    assert handler["name"] == name
    assert handler["timeout"] == 10_000
    assert isinstance(handler["command"], str)


def run_handler(
    handler: Mapping[str, Any], payload: bytes, fixture: GeminiFixture
) -> subprocess.CompletedProcess[bytes]:
    environment = {
        **os.environ,
        "HOME": str(fixture.home_dir),
        "USERPROFILE": str(fixture.home_dir),
        "GEMINI_CLI_HOME": str(fixture.home_dir),
    }
    if os.name == "nt":
        powershell = ntpath.join(
            os.environ.get("SystemRoot", r"C:\Windows"),
            "System32",
            "WindowsPowerShell",
            "v1.0",
            "powershell.exe",
        )
        source = (
            f'{handler["command"]}; '
            "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"
        )
        command = [
            powershell,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            source,
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
    )


def legacy_handler(script_path: Path) -> dict[str, str]:
    command = (
        f'"{sys.executable}" {script_path}'
        if script_path.name == "guard.py"
        else str(script_path)
    )
    return {"type": "command", "command": command}


def symlink_or_skip(
    target: Path, link: Path, *, directory: bool = False
) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as error:
        pytest.skip(f"Symbolic links unavailable: {error}")
