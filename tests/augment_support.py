from __future__ import annotations

from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess  # nosec B404
from threading import Thread
from typing import Any, Mapping

import pytest

from elydora.plugins import augment_contract as contract
from elydora.plugins.augment import AugmentPlugin
from elydora.plugins.base import InstallConfig
from elydora.utils import base64url_encode


AGENT_ID = "agent-1"
MISSING = object()
VALID_PRIVATE_KEY = base64url_encode(bytes(range(32)))


@dataclass
class AugmentFixture:
    root_dir: Path
    home_dir: Path
    project_dir: Path
    config_path: Path
    agent_dir: Path
    guard_path: Path
    hook_path: Path
    guard_wrapper_path: Path
    audit_wrapper_path: Path
    runtime_config_path: Path
    private_key_path: Path
    plugin: AugmentPlugin
    config: InstallConfig

    def install(self) -> None:
        self.plugin.install(self.config)

    def settings(self) -> dict[str, Any]:
        return json.loads(self.config_path.read_text(encoding="utf-8"))


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
    path.write_text(source, encoding="utf-8")
    os.chmod(path, mode)


def write_json(path: Path, value: object, mode: int = 0o600) -> None:
    source = value if isinstance(value, str) else json.dumps(value, indent=2) + "\n"
    write_text(path, source, mode)


def prepare_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    existing_settings: object = MISSING,
    base_url: str = "http://127.0.0.1:9",
) -> AugmentFixture:
    home_dir = tmp_path / "home with spaces and 'quote %AUGGIE%"
    project_dir = tmp_path / "project with spaces"
    project_dir.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("USERPROFILE", str(home_dir))
    monkeypatch.chdir(project_dir)
    monkeypatch.setattr(contract, "home_dir", lambda: str(home_dir))
    config_path = home_dir / ".augment" / "settings.json"
    agent_dir = home_dir / ".elydora" / AGENT_ID
    guard_path = agent_dir / contract.GUARD_SCRIPT
    hook_path = agent_dir / contract.AUDIT_SCRIPT
    if existing_settings is not MISSING:
        write_json(config_path, existing_settings)
    return AugmentFixture(
        root_dir=tmp_path,
        home_dir=home_dir,
        project_dir=project_dir,
        config_path=config_path,
        agent_dir=agent_dir,
        guard_path=guard_path,
        hook_path=hook_path,
        guard_wrapper_path=agent_dir / contract.GUARD_WRAPPER,
        audit_wrapper_path=agent_dir / contract.AUDIT_WRAPPER,
        runtime_config_path=agent_dir / "config.json",
        private_key_path=agent_dir / "private.key",
        plugin=AugmentPlugin(),
        config={
            "org_id": "org-1",
            "agent_id": AGENT_ID,
            "agent_name": "augment",
            "private_key": VALID_PRIVATE_KEY,
            "kid": "key-1",
            "token": "token-1",
            "base_url": base_url,
            "guard_script_path": str(guard_path),
        },
    )


def managed_handler(
    settings: Mapping[str, Any], event: str, wrapper_path: Path
) -> dict[str, Any]:
    command = contract.build_command(str(wrapper_path))
    for group in settings["hooks"][event]:
        for handler in group["hooks"]:
            if handler.get("command") == command:
                return handler
    raise AssertionError(f"managed handler for {event!r} not found")


def run_handler(
    handler: Mapping[str, Any], payload: bytes, fixture: AugmentFixture
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # nosec B602
        str(handler["command"]),
        shell=True,
        input=payload,
        capture_output=True,
        check=False,
        cwd=fixture.project_dir,
        env={
            **os.environ,
            "HOME": str(fixture.home_dir),
            "USERPROFILE": str(fixture.home_dir),
        },
    )


def symlink_or_skip(target: Path, link: Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as error:
        pytest.skip(f"Symbolic links unavailable: {error}")
