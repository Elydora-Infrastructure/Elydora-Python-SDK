from __future__ import annotations

import base64
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess  # nosec B404
import sys
from threading import Thread
from typing import Any, Mapping

import pytest

from elydora.plugins import cline_contract as contract
from elydora.plugins.base import InstallConfig
from elydora.plugins.cline import ClinePlugin


AGENT_ID = "agent-1"
MISSING = object()
VALID_PRIVATE_KEY = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode()


@dataclass
class ClineFixture:
    root_dir: Path
    home_dir: Path
    project_dir: Path
    cline_dir: Path
    hooks_dir: Path
    agent_dir: Path
    guard_path: Path
    audit_path: Path
    guard_wrapper: Path
    audit_wrapper: Path
    runtime_config: Path
    private_key: Path
    plugin: ClinePlugin
    config: InstallConfig

    def install(self) -> None:
        self.plugin.install(self.config)

    def environment(self) -> dict[str, str]:
        return {
            **os.environ,
            "HOME": str(self.home_dir),
            "USERPROFILE": str(self.home_dir),
            "CLINE_DIR": str(self.cline_dir),
        }

    def managed_paths(self) -> tuple[Path, ...]:
        return (
            self.guard_path,
            self.runtime_config,
            self.private_key,
            self.audit_path,
            self.guard_wrapper,
            self.audit_wrapper,
        )


class ElydoraApiHandler(BaseHTTPRequestHandler):
    agent_status: Any = "active"
    requests: list[dict[str, Any]] = []

    @classmethod
    def reset(cls, status: Any) -> None:
        cls.agent_status = status
        cls.requests = []

    def _respond(self, status: int, value: object) -> None:
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        type(self).requests.append(
            {
                "method": "GET",
                "path": self.path,
                "authorization": self.headers.get("Authorization"),
            }
        )
        self._respond(200, {"agent": {"status": type(self).agent_status}})

    def do_POST(self) -> None:  # noqa: N802
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
        self._respond(201, {"operation": {"accepted": True}})

    def log_message(self, _format: str, *_args: object) -> None:
        return


def start_api_server(*, status: Any = "active") -> ThreadingHTTPServer:
    ElydoraApiHandler.reset(status)
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


def python_script(body: str) -> str:
    return f"#!{sys.executable}\n{body}"


def prepare_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    existing_guard: object = MISSING,
    existing_audit: object = MISSING,
    base_url: str = "http://127.0.0.1:9",
) -> ClineFixture:
    home_dir = tmp_path / "home with spaces and 'quote %CLINE%"
    project_dir = tmp_path / "project with spaces"
    cline_dir = tmp_path / "custom-cline-home"
    hooks_dir = cline_dir / "hooks"
    agent_dir = home_dir / ".elydora" / AGENT_ID
    project_dir.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("USERPROFILE", str(home_dir))
    monkeypatch.setenv("CLINE_DIR", str(cline_dir))
    monkeypatch.chdir(project_dir)
    guard_wrapper = hooks_dir / contract.GUARD_FILE_NAME
    audit_wrapper = hooks_dir / contract.AUDIT_FILE_NAME
    if existing_guard is not MISSING:
        write_text(guard_wrapper, str(existing_guard), 0o700)
    if existing_audit is not MISSING:
        write_text(audit_wrapper, str(existing_audit), 0o700)
    guard_path = agent_dir / contract.GUARD_SCRIPT
    audit_path = agent_dir / contract.AUDIT_SCRIPT
    return ClineFixture(
        root_dir=tmp_path,
        home_dir=home_dir,
        project_dir=project_dir,
        cline_dir=cline_dir,
        hooks_dir=hooks_dir,
        agent_dir=agent_dir,
        guard_path=guard_path,
        audit_path=audit_path,
        guard_wrapper=guard_wrapper,
        audit_wrapper=audit_wrapper,
        runtime_config=agent_dir / "config.json",
        private_key=agent_dir / "private.key",
        plugin=ClinePlugin(),
        config={
            "org_id": "org-1",
            "agent_id": AGENT_ID,
            "agent_name": "cline",
            "private_key": VALID_PRIVATE_KEY,
            "kid": "key-1",
            "token": "token-1",
            "base_url": base_url,
            "guard_script_path": str(guard_path),
        },
    )


def run_wrapper(
    wrapper: Path,
    fixture: ClineFixture,
    payload: bytes,
) -> subprocess.CompletedProcess[bytes]:
    node = shutil.which("node")
    assert node is not None
    return subprocess.run(  # nosec B603
        [node, str(wrapper)],
        cwd=fixture.project_dir,
        env=fixture.environment(),
        input=payload,
        capture_output=True,
        check=False,
        timeout=10,
    )


def assert_no_transaction_files(root: Path) -> None:
    assert not list(root.rglob("*.tmp"))
    assert not list(root.rglob("*.rollback"))


def snapshot_installation(fixture: ClineFixture) -> Mapping[Path, bytes]:
    return {path: path.read_bytes() for path in fixture.managed_paths()}


def assert_snapshot(snapshot: Mapping[Path, bytes]) -> None:
    for path, source in snapshot.items():
        assert path.read_bytes() == source


def symlink_or_skip(target: Path, link: Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as error:
        pytest.skip(f"Symbolic links unavailable: {error}")
