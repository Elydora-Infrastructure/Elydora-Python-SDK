from __future__ import annotations

import base64
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from typing import Any

import pytest

from elydora.plugins import kiroide
from elydora.plugins import (
    kiroide_contract,
    kiroide_installation,
    kiroide_io,
)
from elydora.plugins.base import InstallConfig



AGENT_ID = "agent-1"
PRIVATE_KEY = base64.urlsafe_b64encode(bytes([11]) * 32).rstrip(b"=").decode()
ROTATED_PRIVATE_KEY = (
    base64.urlsafe_b64encode(bytes([12]) * 32).rstrip(b"=").decode()
)


@dataclass(frozen=True)
class KiroIdeFixture:
    home: Path
    workspace: Path
    config_path: Path
    legacy_path: Path
    agent_directory: Path
    guard_path: Path
    audit_path: Path
    plugin: kiroide.KiroIdePlugin
    config: InstallConfig


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def install_config(home: Path) -> InstallConfig:
    return {
        "org_id": "org-1",
        "agent_id": AGENT_ID,
        "agent_name": "kiroide",
        "private_key": PRIVATE_KEY,
        "kid": "kid-1",
        "token": "token-1",
        "base_url": "https://api.elydora.test",
        "guard_script_path": str(home / ".elydora" / AGENT_ID / "guard.py"),
    }


def prepare_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    current: Any = None,
    legacy: Any = None,
    base_url: str = "https://api.elydora.test",
) -> KiroIdeFixture:
    home = tmp_path / "home with spaces and 'quote %KIRO%"
    workspace = tmp_path / "workspace with spaces"
    home.mkdir(parents=True)
    workspace.mkdir(parents=True)
    config_path = workspace / ".kiro" / "hooks" / "elydora-audit.json"
    legacy_path = home / ".kiro" / "hooks" / "elydora-audit.kiro.hook"
    if current is not None:
        if isinstance(current, str):
            config_path.parent.mkdir(parents=True)
            config_path.write_text(current, encoding="utf-8")
        else:
            write_json(config_path, current)
    if legacy is not None:
        if isinstance(legacy, str):
            legacy_path.parent.mkdir(parents=True)
            legacy_path.write_text(legacy, encoding="utf-8")
        else:
            write_json(legacy_path, legacy)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.chdir(workspace)
    agent_directory = home / ".elydora" / AGENT_ID
    config = install_config(home)
    config["base_url"] = base_url
    return KiroIdeFixture(
        home,
        workspace,
        config_path,
        legacy_path,
        agent_directory,
        agent_directory / "guard.py",
        agent_directory / "hook.py",
        kiroide.KiroIdePlugin(),
        config,
    )


def find_hook(document: dict[str, Any], name: str) -> dict[str, Any]:
    return next(hook for hook in document["hooks"] if hook.get("name") == name)


def managed_document(guard_command: str, audit_command: str) -> dict[str, Any]:
    return {
        "version": "v1",
        "hooks": [
            {
                "name": "elydora-guard",
                "description": "Block tool use when the Elydora agent is frozen",
                "trigger": "PreToolUse",
                "matcher": ".*",
                "action": {"type": "command", "command": guard_command},
                "timeout": 10,
                "enabled": True,
            },
            {
                "name": "elydora-audit",
                "description": "Record tool use in the Elydora audit trail",
                "trigger": "PostToolUse",
                "matcher": ".*",
                "action": {"type": "command", "command": audit_command},
                "timeout": 10,
                "enabled": True,
            },
        ],
    }


def legacy_document(fixture: KiroIdeFixture, agent_id: str = AGENT_ID) -> dict:
    agent_directory = fixture.home / ".elydora" / agent_id
    return {
        "name": "Elydora Audit",
        "description": (
            "Sends tool-use events to the Elydora tamper-evident audit platform"
        ),
        "version": "1.0.0",
        "hooks": {
            "pre_tool_use": {
                "command": f'"{sys.executable}" {agent_directory / "guard.py"}',
                "timeout_ms": 5000,
            },
            "post_tool_use": {
                "command": str(agent_directory / "hook.py"),
                "timeout_ms": 5000,
            },
        },
    }


def legacy_runtime_config(
    fixture: KiroIdeFixture, agent_id: str = AGENT_ID
) -> dict[str, str]:
    return {
        "org_id": "org-1",
        "agent_id": agent_id,
        "kid": "kid-1",
        "base_url": "https://api.elydora.test",
        "token": "",
        "agent_name": "kiroide",
    }


def write_legacy_runtime(fixture: KiroIdeFixture, agent_id: str) -> Path:
    agent_directory = fixture.home / ".elydora" / agent_id
    write_json(
        agent_directory / "config.json",
        legacy_runtime_config(fixture, agent_id),
    )
    (agent_directory / "private.key").write_text(PRIVATE_KEY, encoding="utf-8")
    (agent_directory / "guard.py").write_text("guard\n", encoding="utf-8")
    (agent_directory / "hook.py").write_text("audit\n", encoding="utf-8")
    return agent_directory


def write_large_error_log(agent_directory: Path, marker: bytes) -> Path:
    error_log = agent_directory / "error.log"
    with error_log.open("wb") as file:
        for _index in range(48):
            file.write(marker * 4096)
    if os.name != "nt":
        error_log.chmod(0o600)
    assert error_log.stat().st_size > 2 * 1024 * 1024
    return error_log


def run_command(
    command: str, fixture: KiroIdeFixture, payload: dict[str, Any]
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        shell=True,
        cwd=fixture.workspace,
        env={
            **os.environ,
            "HOME": str(fixture.home),
            "USERPROFILE": str(fixture.home),
        },
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
    )


class AuditHandler(BaseHTTPRequestHandler):
    operations: list[dict[str, Any]] = []

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8")
        self.operations.append(json.loads(raw))
        self.send_response(201)
        self.end_headers()

    def log_message(self, _format: str, *_args: object) -> None:
        return


@dataclass(frozen=True)
class AuditServer:
    server: ThreadingHTTPServer
    thread: threading.Thread

    @property
    def base_url(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


def start_audit_server() -> AuditServer:
    AuditHandler.operations = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), AuditHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return AuditServer(server, thread)


def prepare_installation(
    fixture: KiroIdeFixture,
    config: InstallConfig | None = None,
) -> tuple[
    kiroide_io.KiroIdeSources,
    kiroide_installation.KiroIdeRuntimePaths,
    kiroide_installation.PreparedKiroIdeInstallation,
    kiroide_contract.RenderedKiroIdeDocument,
]:
    selected = fixture.config if config is None else config
    sources = kiroide_io.read_kiroide_sources()
    kiroide_contract.require_available_kiroide_hooks(sources.document.hooks)
    paths = kiroide_installation.preflight_kiroide_installation(
        selected, sources
    )
    hooks = kiroide_contract.without_managed_kiroide_hooks(
        sources.document.hooks
    )
    rendered = kiroide_contract.render_kiroide_document(
        sources.document,
        [
            *hooks,
            kiroide_contract.build_kiroide_hook(
                kiroide_contract.GUARD_NAME, paths.guard_path
            ),
            kiroide_contract.build_kiroide_hook(
                kiroide_contract.AUDIT_NAME, paths.audit_path
            ),
        ],
    )
    prepared = kiroide_installation.prepare_kiroide_installation(
        selected, paths, sources, rendered
    )
    return sources, paths, prepared, rendered
