from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import sys
from threading import Thread
import time

from elydora.plugins.hook_template import generate_guard_script


AGENT_ID = "agent 1"


class StatusHandler(BaseHTTPRequestHandler):
    status = "active"
    request_path = ""

    def do_GET(self) -> None:
        type(self).request_path = self.path
        body = json.dumps({"agent": {"status": type(self).status}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def create_guard(tmp_path: Path, status: str) -> tuple[Path, ThreadingHTTPServer]:
    StatusHandler.status = status
    StatusHandler.request_path = ""
    server = ThreadingHTTPServer(("127.0.0.1", 0), StatusHandler)
    Thread(target=server.serve_forever, daemon=True).start()

    agent_dir = tmp_path / ".elydora" / AGENT_ID
    agent_dir.mkdir(parents=True)
    config = {
        "agent_id": AGENT_ID,
        "base_url": f"http://127.0.0.1:{server.server_port}",
    }
    (agent_dir / "config.json").write_text(json.dumps(config), encoding="utf-8")

    script_path = tmp_path / "guard.py"
    script_path.write_text(
        generate_guard_script("claudecode", AGENT_ID),
        encoding="utf-8",
    )
    return script_path, server


def run_guard(script_path: Path, home_dir: Path) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "HOME": str(home_dir),
        "USERPROFILE": str(home_dir),
    }
    return subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        check=False,
        env=env,
        input="",
        text=True,
    )


def test_remote_frozen_status_blocks_tool_execution(tmp_path: Path) -> None:
    script_path, server = create_guard(tmp_path, "frozen")
    try:
        result = run_guard(script_path, tmp_path)
    finally:
        server.shutdown()
        server.server_close()

    assert result.returncode == 2
    assert "Tool execution blocked" in result.stderr
    assert StatusHandler.request_path == "/v1/agents/agent%201"


def test_active_status_allows_tool_execution(tmp_path: Path) -> None:
    script_path, server = create_guard(tmp_path, "active")
    try:
        result = run_guard(script_path, tmp_path)
    finally:
        server.shutdown()
        server.server_close()

    assert result.returncode == 0
    assert result.stderr == ""


def test_cached_frozen_status_uses_blocking_exit_code(tmp_path: Path) -> None:
    script_path, server = create_guard(tmp_path, "active")
    cache_path = tmp_path / ".elydora" / AGENT_ID / "status-cache.json"
    cache_path.write_text(
        json.dumps({"status": "frozen", "cached_at": time.time()}),
        encoding="utf-8",
    )
    try:
        result = run_guard(script_path, tmp_path)
    finally:
        server.shutdown()
        server.server_close()

    assert result.returncode == 2
    assert "Tool execution blocked" in result.stderr
