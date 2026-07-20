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

from elydora.plugins._jsonc import parse_jsonc
from elydora.plugins.qwen import QwenPlugin
from elydora.plugins.qwen_command import build_qwen_command
from elydora.utils import base64url_encode


AGENT_ID = "agent-1"
MISSING = object()
VALID_PRIVATE_KEY = base64url_encode(bytes(range(32)))
GUARD_NAME = "elydora-guard"
AUDIT_NAME = "elydora-audit"


@dataclass
class QwenFixture:
    root_dir: Path
    home_dir: Path
    project_dir: Path
    config_path: Path
    system_defaults_path: Path
    system_path: Path
    trusted_folders_path: Path
    agent_dir: Path
    guard_path: Path
    audit_path: Path
    runtime_config_path: Path
    private_key_path: Path
    plugin: QwenPlugin
    config: dict[str, str]

    def install(self) -> None:
        self.plugin.install(self.config)

    def source(self, file_path: Optional[Path] = None) -> str:
        path = file_path or self.config_path
        with path.open("r", encoding="utf-8", newline="") as file:
            return file.read()

    def settings(self, file_path: Optional[Path] = None) -> dict[str, Any]:
        path = file_path or self.config_path
        value = parse_jsonc(
            self.source(path),
            f"Qwen Code test settings at {path}",
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


def prepare_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    existing_settings: object = MISSING,
    base_url: str = "http://127.0.0.1:9",
) -> QwenFixture:
    home_dir = tmp_path / "home with spaces and 'quote $QWEN_CWD %QWEN_CWD%"
    project_dir = tmp_path / "project with spaces"
    project_dir.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("USERPROFILE", str(home_dir))
    monkeypatch.delenv("QWEN_HOME", raising=False)
    monkeypatch.delenv("QWEN_RUNTIME_DIR", raising=False)
    monkeypatch.chdir(project_dir)
    config_path = home_dir / ".qwen" / "settings.json"
    system_defaults_path = tmp_path / "system-defaults.json"
    system_path = tmp_path / "system-settings.json"
    trusted_folders_path = tmp_path / "trusted-folders.json"
    monkeypatch.setenv(
        "QWEN_CODE_SYSTEM_DEFAULTS_PATH", str(system_defaults_path)
    )
    monkeypatch.setenv("QWEN_CODE_SYSTEM_SETTINGS_PATH", str(system_path))
    monkeypatch.setenv(
        "QWEN_CODE_TRUSTED_FOLDERS_PATH", str(trusted_folders_path)
    )
    agent_dir = home_dir / ".elydora" / AGENT_ID
    guard_path = agent_dir / "guard.py"
    audit_path = agent_dir / "hook.py"
    runtime_config_path = agent_dir / "config.json"
    private_key_path = agent_dir / "private.key"
    if existing_settings is not MISSING:
        write_json(config_path, existing_settings)
    return QwenFixture(
        root_dir=tmp_path,
        home_dir=home_dir,
        project_dir=project_dir,
        config_path=config_path,
        system_defaults_path=system_defaults_path,
        system_path=system_path,
        trusted_folders_path=trusted_folders_path,
        agent_dir=agent_dir,
        guard_path=guard_path,
        audit_path=audit_path,
        runtime_config_path=runtime_config_path,
        private_key_path=private_key_path,
        plugin=QwenPlugin(),
        config={
            "org_id": "org-1",
            "agent_id": AGENT_ID,
            "agent_name": "qwen",
            "private_key": VALID_PRIVATE_KEY,
            "kid": "kid-1",
            "token": "token-1",
            "base_url": base_url,
            "guard_script_path": str(guard_path),
        },
    )


def managed_handler(
    settings: Mapping[str, Any], event: str, name: str
) -> dict[str, Any]:
    for group in settings.get("hooks", {}).get(event, []):
        if set(group) != {"hooks"}:
            continue
        for handler in group["hooks"]:
            if (
                set(handler)
                == {"type", "name", "command", "shell", "timeout"}
                and handler.get("type") == "command"
                and handler.get("name") == name
                and handler.get("shell")
                == ("powershell" if os.name == "nt" else "bash")
                and handler.get("timeout") == 10_000
            ):
                return handler
    raise AssertionError(f"managed handler for {event!r} not found")


def assert_managed_triple(settings: Mapping[str, Any]) -> dict[str, Any]:
    guard = managed_handler(settings, "PreToolUse", GUARD_NAME)
    audit = managed_handler(settings, "PostToolUse", AUDIT_NAME)
    failure = managed_handler(settings, "PostToolUseFailure", AUDIT_NAME)
    assert audit["command"] == failure["command"]
    return {"guard": guard, "audit": audit, "failure": failure}


def legacy_group(script_path: Path) -> dict[str, Any]:
    return {
        "matcher": "*",
        "hooks": [{
            "type": "command",
            "command": build_qwen_command(str(script_path)),
            "shell": "powershell" if os.name == "nt" else "bash",
            "timeout": 10_000,
        }],
    }


def run_handler(
    handler: Mapping[str, Any], payload: bytes, fixture: QwenFixture
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


def official_input(fixture: QwenFixture, event: str) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "session_id": "session-1",
        "transcript_path": str(fixture.project_dir / "transcript.jsonl"),
        "cwd": str(fixture.project_dir),
        "hook_event_name": event,
        "timestamp": "2026-07-19T00:00:00.000Z",
        "permission_mode": "default",
        "tool_name": "run_shell_command",
        "tool_input": {"command": "echo test"},
        "tool_use_id": "toolu_1",
        "tool_call_id": "call_1",
    }
    if event == "PostToolUse":
        payload["tool_response"] = {"output": "test", "error": None}
    if event == "PostToolUseFailure":
        payload.update({"error": "command failed", "is_interrupt": False})
    return payload


def run_cli(
    fixture: QwenFixture, arguments: list[str]
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
