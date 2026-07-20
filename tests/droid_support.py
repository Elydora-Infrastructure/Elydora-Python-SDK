from __future__ import annotations

import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess  # nosec B404
import threading
from typing import Any, Dict, Iterable, Optional

import pytest

from elydora.plugins import _jsonc, droid, droid_policy
from elydora.plugins.base import InstallConfig


AGENT_ID = "agent-1"
VALID_PRIVATE_KEY = base64.urlsafe_b64encode(bytes([13]) * 32).rstrip(b"=").decode()
JsonObject = Dict[str, Any]


class DroidFixture:
    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        *,
        root_config: Any = None,
        legacy_config: Any = None,
        settings: Any = None,
        local_settings: Any = None,
        project_settings: Any = None,
        project_local_settings: Any = None,
        base_url: str = "http://127.0.0.1:9",
        agent_id: str = AGENT_ID,
    ) -> None:
        self.root_dir = tmp_path
        self.home_dir = tmp_path / "home with spaces and 'quote %DROID%"
        self.workspace_dir = tmp_path / "workspace with spaces"
        self.factory_dir = self.home_dir / ".factory"
        self.root_path = self.factory_dir / "hooks.json"
        self.legacy_path = self.factory_dir / "hooks" / "hooks.json"
        self.settings_path = self.factory_dir / "settings.json"
        self.local_settings_path = self.factory_dir / "settings.local.json"
        self.project_factory_dir = self.workspace_dir / ".factory"
        self.project_settings_path = self.project_factory_dir / "settings.json"
        self.project_local_settings_path = (
            self.project_factory_dir / "settings.local.json"
        )
        self.system_settings_path = (
            tmp_path / "managed factory" / "settings.json"
        )
        self.agent_id = agent_id
        self.agent_dir = self.home_dir / ".elydora" / agent_id
        self.guard_path = self.agent_dir / "guard.py"
        self.audit_path = self.agent_dir / "hook.py"
        self.runtime_config = self.agent_dir / "config.json"
        self.private_key_path = self.agent_dir / "private.key"
        self.workspace_dir.mkdir(parents=True)
        (self.workspace_dir / ".git").mkdir()
        self._write(self.root_path, root_config)
        self._write(self.legacy_path, legacy_config)
        self._write(self.settings_path, settings)
        self._write(self.local_settings_path, local_settings)
        self._write(self.project_settings_path, project_settings)
        self._write(self.project_local_settings_path, project_local_settings)
        monkeypatch.setenv("HOME", str(self.home_dir))
        monkeypatch.setenv("USERPROFILE", str(self.home_dir))
        monkeypatch.chdir(self.workspace_dir)
        monkeypatch.setattr(
            droid_policy,
            "_managed_settings_path",
            lambda: str(self.system_settings_path),
        )
        self.config: InstallConfig = {
            "agent_id": agent_id,
            "agent_name": "droid",
            "org_id": "org-1",
            "private_key": VALID_PRIVATE_KEY,
            "kid": "kid-1",
            "token": "token-1",
            "base_url": base_url,
            "guard_script_path": str(self.guard_path),
        }
        self.plugin = droid.DroidPlugin()

    @staticmethod
    def _write(path: Path, value: Any) -> None:
        if value is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = value if isinstance(value, str) else json.dumps(value, indent=2) + "\n"
        with open(path, "w", encoding="utf-8", newline="") as file:
            file.write(raw)

    def install(self, **overrides: str) -> None:
        config = InstallConfig(**self.config)
        config.update(overrides)
        self.plugin.install(config)

    def write_system_settings(self, value: Any) -> None:
        self._write(self.system_settings_path, value)


def load_jsonc(path: Path) -> JsonObject:
    value = _jsonc.parse_jsonc(path.read_text(encoding="utf-8"), str(path))
    assert isinstance(value, dict)
    return value


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    source = value if isinstance(value, str) else json.dumps(value, indent=2) + "\n"
    with open(path, "w", encoding="utf-8", newline="") as file:
        file.write(source)


def read_raw(path: Path) -> str:
    with open(path, "r", encoding="utf-8", newline="") as file:
        return file.read()


def managed_group(
    hooks: JsonObject,
    event: str,
    script_name: str,
) -> Optional[JsonObject]:
    for group in hooks.get(event, []):
        if any(
            script_name in handler.get("command", "")
            for handler in group.get("hooks", [])
        ):
            return group
    return None


def managed_handler(
    hooks: JsonObject,
    event: str,
    script_name: str,
) -> Optional[JsonObject]:
    group = managed_group(hooks, event, script_name)
    if group is None:
        return None
    return next(
        handler
        for handler in group["hooks"]
        if script_name in handler.get("command", "")
    )


def assert_native_group(group: Optional[JsonObject]) -> None:
    assert group is not None
    assert sorted(group) == ["hooks", "matcher"]
    assert group["matcher"] == "*"
    assert len(group["hooks"]) == 1
    handler = group["hooks"][0]
    assert sorted(handler) == ["command", "timeout", "type"]
    assert handler["type"] == "command"
    assert handler["timeout"] == 10


def run_hook(
    command: str,
    payload: str,
) -> subprocess.CompletedProcess[str]:
    argv = (
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
        ]
        if os.name == "nt"
        else ["/bin/sh", "-c", command]
    )
    return subprocess.run(  # nosec B603
        argv,
        input=payload,
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )


def assert_no_transaction_files(root: Path) -> None:
    leaked = [
        path
        for path in root.rglob("*")
        if path.suffix in {".tmp", ".rollback"}
    ]
    assert leaked == []


def snapshot(paths: Iterable[Path]) -> Dict[Path, str]:
    return {
        path: read_raw(path)
        for path in paths
    }


def assert_snapshot(expected: Dict[Path, str]) -> None:
    for path, source in expected.items():
        assert read_raw(path) == source


class _ApiHandler(BaseHTTPRequestHandler):
    def _respond(self, status: int, payload: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload.encode("utf-8"))

    def do_GET(self) -> None:
        self.server.requests.append(("GET", self.path, b""))  # type: ignore[attr-defined]
        self._respond(200, '{"agent":{"status":"active"}}')

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.server.requests.append(  # type: ignore[attr-defined]
            ("POST", self.path, body)
        )
        self._respond(201, '{"operation":{"accepted":true}}')

    def log_message(self, _format: str, *args: object) -> None:
        del args


class ApiServer:
    def __init__(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _ApiHandler)
        self.server.requests = []  # type: ignore[attr-defined]
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
        )
        self.thread.start()
        host, port = self.server.server_address
        self.base_url = f"http://{host}:{port}"

    @property
    def requests(self) -> list[tuple[str, str, bytes]]:
        return self.server.requests  # type: ignore[attr-defined,no-any-return]

    def close(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()
