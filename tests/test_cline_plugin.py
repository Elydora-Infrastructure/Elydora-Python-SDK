from __future__ import annotations

import base64
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
from queue import Queue
import shutil
import subprocess  # nosec B404
import sys
from threading import Thread
from typing import Any, Optional

import pytest

from elydora import cli
from elydora.plugins import cline
from elydora.plugins import cline_contract, cline_io
from elydora.plugins.base import InstallConfig
from elydora.plugins.registry import SUPPORTED_AGENTS


AGENT_ID = "agent-1"
MISSING = object()


@dataclass(frozen=True)
class ClineFixture:
    plugin: cline.ClinePlugin
    config: InstallConfig
    home_dir: Path
    workspace_dir: Path
    cline_dir: Path
    hooks_dir: Path
    agent_dir: Path
    guard_path: Path
    audit_path: Path
    guard_wrapper: Path
    audit_wrapper: Path
    runtime_config: Path


def _python_script(body: str) -> str:
    return f"#!{sys.executable}\n{body}"


def prepare_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    auto_install: bool = True,
    create_guard: bool = True,
    existing_audit: Any = MISSING,
    existing_guard: Any = MISSING,
    guard_source: Optional[str] = None,
) -> ClineFixture:
    home_dir = tmp_path / "home with spaces"
    workspace_dir = tmp_path / "workspace"
    cline_dir = tmp_path / "custom-cline-home"
    hooks_dir = cline_dir / "hooks"
    agent_dir = home_dir / ".elydora" / AGENT_ID
    guard_path = agent_dir / "guard.py"
    audit_path = agent_dir / "hook.py"
    guard_wrapper = hooks_dir / "PreToolUse.mjs"
    audit_wrapper = hooks_dir / "PostToolUse.mjs"
    workspace_dir.mkdir(parents=True)
    agent_dir.mkdir(parents=True)
    if create_guard:
        guard_path.write_text(
            guard_source
            or _python_script(
                "import sys\n"
                "sys.stdin.read()\n"
                "sys.stderr.write('Agent is frozen by Elydora.\\n')\n"
                "raise SystemExit(2)\n"
            ),
            encoding="utf-8",
        )
    if existing_guard is not MISSING:
        hooks_dir.mkdir(parents=True, exist_ok=True)
        guard_wrapper.write_text(str(existing_guard), encoding="utf-8")
    if existing_audit is not MISSING:
        hooks_dir.mkdir(parents=True, exist_ok=True)
        audit_wrapper.write_text(str(existing_audit), encoding="utf-8")

    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("USERPROFILE", str(home_dir))
    monkeypatch.setenv("CLINE_DIR", str(cline_dir))
    private_key = base64.urlsafe_b64encode(bytes([1]) * 32).rstrip(b"=").decode()
    config: InstallConfig = {
        "agent_id": AGENT_ID,
        "agent_name": "cline",
        "org_id": "org-1",
        "private_key": private_key,
        "kid": "kid-1",
        "base_url": "https://api.elydora.test",
        "guard_script_path": str(guard_path),
    }
    fixture = ClineFixture(
        plugin=cline.ClinePlugin(),
        config=config,
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        cline_dir=cline_dir,
        hooks_dir=hooks_dir,
        agent_dir=agent_dir,
        guard_path=guard_path,
        audit_path=audit_path,
        guard_wrapper=guard_wrapper,
        audit_wrapper=audit_wrapper,
        runtime_config=agent_dir / "config.json",
    )
    if auto_install:
        fixture.plugin.install(config)
    return fixture


def run_wrapper(
    wrapper: Path,
    fixture: ClineFixture,
    payload: dict[str, Any],
) -> subprocess.CompletedProcess[str]:
    node = shutil.which("node")
    assert node is not None
    return subprocess.run(  # nosec B603
        [node, str(wrapper)],
        cwd=fixture.workspace_dir,
        env={
            **os.environ,
            "HOME": str(fixture.home_dir),
            "USERPROFILE": str(fixture.home_dir),
        },
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )


def test_cline_is_registered_in_the_sdk_and_cli() -> None:
    assert SUPPORTED_AGENTS["cline"] == {
        "name": "Cline",
        "hook_event": "PreToolUse/PostToolUse",
        "config_path": "~/.cline/hooks/PreToolUse.mjs",
    }
    assert cli.PLUGIN_MAP["cline"] is cline.ClinePlugin


def test_install_writes_only_native_global_hooks_and_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    guard_source = fixture.guard_wrapper.read_text(encoding="utf-8")
    audit_source = fixture.audit_wrapper.read_text(encoding="utf-8")

    fixture.plugin.install(fixture.config)

    assert fixture.guard_wrapper.read_text(encoding="utf-8") == guard_source
    assert fixture.audit_wrapper.read_text(encoding="utf-8") == audit_source
    assert guard_source.startswith("#!/usr/bin/env node\n// @elydora-cline-hook ")
    assert list(fixture.hooks_dir.glob("*.tmp")) == []
    assert not (fixture.home_dir / "Documents" / "Cline" / "Hooks").exists()
    assert not (fixture.workspace_dir / ".cline" / "hooks").exists()
    assert not (fixture.workspace_dir / ".clinerules" / "hooks").exists()


def test_install_uses_official_default_without_cline_dir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, auto_install=False)
    monkeypatch.delenv("CLINE_DIR")

    fixture.plugin.install(fixture.config)

    default_hooks = fixture.home_dir / ".cline" / "hooks"
    assert (default_hooks / "PreToolUse.mjs").is_file()
    assert (default_hooks / "PostToolUse.mjs").is_file()
    assert not fixture.guard_wrapper.exists()


def test_wrappers_translate_freezes_and_forward_payload_byte_for_byte(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    capture_path = tmp_path / "captured-event.json"
    fixture.audit_path.write_text(
        _python_script(
            "from pathlib import Path\n"
            "import os, sys\n"
            f"Path({str(capture_path)!r}).write_text("
            "json.dumps({'cwd': os.getcwd(), 'input': sys.stdin.read()}), "
            "encoding='utf-8')\n"
        ).replace("import os, sys", "import json, os, sys"),
        encoding="utf-8",
    )
    pre_payload = {
        "clineVersion": "3.0.46",
        "hookName": "tool_call",
        "taskId": "task-1",
        "tool_call": {"name": "read_file", "input": {"path": "README.md"}},
    }
    guard = run_wrapper(fixture.guard_wrapper, fixture, pre_payload)
    assert guard.returncode == 0
    assert "Agent is frozen by Elydora" in guard.stderr
    marker, control = guard.stdout.strip().split("\t", 1)
    assert marker == "HOOK_CONTROL"
    assert json.loads(control) == {
        "cancel": True,
        "errorMessage": "Agent is frozen by Elydora.",
    }

    post_payload = {
        "clineVersion": "3.0.46",
        "hookName": "tool_result",
        "taskId": "task-1",
        "tool_result": {"name": "read_file", "input": {"path": "README.md"}},
    }
    audit = run_wrapper(fixture.audit_wrapper, fixture, post_payload)
    assert audit.returncode == 0
    captured = json.loads(capture_path.read_text(encoding="utf-8"))
    assert captured == {"cwd": str(fixture.workspace_dir), "input": json.dumps(post_payload)}


def test_wrappers_keep_passes_quiet_and_surface_runtime_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    passing = prepare_fixture(
        monkeypatch,
        tmp_path / "passing",
        guard_source=_python_script("import sys\nsys.stdin.read()\n"),
    )
    result = run_wrapper(passing.guard_wrapper, passing, {})
    assert result.returncode == 0
    assert result.stdout == ""

    failing = prepare_fixture(monkeypatch, tmp_path / "failing")
    failing.audit_path.write_text(
        _python_script(
            "import sys\n"
            "sys.stderr.write('audit failed\\n')\n"
            "raise SystemExit(7)\n"
        ),
        encoding="utf-8",
    )
    result = run_wrapper(failing.audit_wrapper, failing, {})
    assert result.returncode == 1
    assert "audit failed" in result.stderr
    assert "exited with code 7" in result.stderr


def test_wrapper_rejects_a_non_absolute_runtime_shebang(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        guard_source="#!python.exe\nimport sys\nsys.stdin.read()\n",
    )

    result = run_wrapper(fixture.guard_wrapper, fixture, {})

    assert result.returncode == 1
    assert result.stdout == ""
    assert "runtime shebang executable must be absolute" in result.stderr


class _OperationHandler(BaseHTTPRequestHandler):
    operations: Queue[dict[str, Any]]

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers["Content-Length"])
        body = json.loads(self.rfile.read(length).decode("utf-8"))
        self.operations.put(body)
        self.send_response(201)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, format: str, *args: Any) -> None:
        return


def test_audit_runtime_maps_official_nested_fields_into_the_operation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    operations: Queue[dict[str, Any]] = Queue()
    _OperationHandler.operations = operations
    server = ThreadingHTTPServer(("127.0.0.1", 0), _OperationHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    fixture = prepare_fixture(monkeypatch, tmp_path, auto_install=False)
    fixture.config["base_url"] = f"http://127.0.0.1:{server.server_port}"
    try:
        fixture.plugin.install(fixture.config)
        payload = {
            "hookName": "tool_result",
            "taskId": "task-1",
            "tool_result": {
                "name": "read_file",
                "input": {"path": "README.md"},
                "output": "ok",
            },
        }
        result = run_wrapper(fixture.audit_wrapper, fixture, payload)
        assert result.returncode == 0
        operation = operations.get(timeout=3)
        assert operation["payload"] == {
            "tool_name": "read_file",
            "tool_input": {"path": "README.md"},
            "session_id": "task-1",
        }
        assert operation["action"] == {"tool": "read_file"}
        assert operation["subject"] == {"session_id": "task-1"}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_status_requires_intact_hooks_and_runtimes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    assert fixture.plugin.status() == {
        "installed": True,
        "agent": "cline",
        "details": f"Config: {fixture.hooks_dir}",
    }
    fixture.guard_path.unlink()
    assert fixture.plugin.status()["installed"] is False
    fixture.guard_path.write_text(_python_script("pass\n"), encoding="utf-8")
    fixture.audit_wrapper.unlink()
    assert fixture.plugin.status() == {
        "installed": False,
        "agent": "cline",
        "details": "Not installed",
    }


def test_status_surfaces_corrupt_hooks_and_runtime_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.guard_wrapper.write_text(
        fixture.guard_wrapper.read_text(encoding="utf-8") + "\n// tampered\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="managed template"):
        fixture.plugin.status()

    fixture.plugin.install(fixture.config)
    fixture.runtime_config.write_text("{ malformed", encoding="utf-8")
    with pytest.raises(ValueError, match="parse Elydora runtime config"):
        fixture.plugin.status()


@pytest.mark.parametrize("collision", ["guard", "audit"])
def test_install_rejects_user_filename_collisions_before_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    collision: str,
) -> None:
    existing_guard = "// user PreToolUse hook\n" if collision == "guard" else MISSING
    existing_audit = "// user PostToolUse hook\n" if collision == "audit" else MISSING
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        auto_install=False,
        existing_guard=existing_guard,
        existing_audit=existing_audit,
    )
    with pytest.raises(ValueError, match="owned by another integration"):
        fixture.plugin.install(fixture.config)
    assert fixture.audit_path.exists() is False
    assert fixture.runtime_config.exists() is False
    if collision == "guard":
        assert fixture.guard_wrapper.read_text(encoding="utf-8") == existing_guard
        assert fixture.audit_wrapper.exists() is False
    else:
        assert fixture.audit_wrapper.read_text(encoding="utf-8") == existing_audit
        assert fixture.guard_wrapper.exists() is False


def test_install_preserves_corrupt_metadata_for_recovery(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    corrupt = "#!/usr/bin/env node\n// @elydora-cline-hook invalid\n"
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        auto_install=False,
        existing_guard=corrupt,
    )
    with pytest.raises(ValueError, match="parse Elydora Cline hook metadata"):
        fixture.plugin.install(fixture.config)
    assert fixture.guard_wrapper.read_text(encoding="utf-8") == corrupt
    assert fixture.audit_wrapper.exists() is False
    assert fixture.audit_path.exists() is False


def test_install_rejects_missing_guard_before_creating_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        auto_install=False,
        create_guard=False,
    )
    with pytest.raises(FileNotFoundError, match="guard runtime is missing"):
        fixture.plugin.install(fixture.config)
    assert fixture.guard_wrapper.exists() is False
    assert fixture.audit_wrapper.exists() is False
    assert fixture.audit_path.exists() is False
    assert fixture.runtime_config.exists() is False


def test_uninstall_removes_exact_ownership_and_preserves_other_hooks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    user_hook = fixture.hooks_dir / "PreToolUse.py"
    user_hook.write_text("# user hook\n", encoding="utf-8")

    fixture.plugin.uninstall("agent-10")
    assert fixture.guard_wrapper.is_file()
    assert fixture.audit_wrapper.is_file()
    fixture.plugin.uninstall(AGENT_ID)
    assert fixture.guard_wrapper.exists() is False
    assert fixture.audit_wrapper.exists() is False
    assert user_hook.read_text(encoding="utf-8") == "# user hook\n"


def test_hook_pair_restores_the_first_hook_when_the_second_commit_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    original_guard = fixture.guard_wrapper.read_text(encoding="utf-8")
    original_audit = fixture.audit_wrapper.read_text(encoding="utf-8")
    guard_state = cline_io.read_hook_file(str(fixture.guard_wrapper))
    audit_state = cline_io.read_hook_file(str(fixture.audit_wrapper))
    replacement_guard = cline_contract.build_wrapper(
        cline_contract.build_metadata("guard", "agent-2", str(fixture.guard_path))
    )
    replacement_audit = cline_contract.build_wrapper(
        cline_contract.build_metadata("audit", "agent-2", str(fixture.audit_path))
    )
    real_replace = os.replace
    failure_injected = False

    def fail_audit_commit(source: Any, destination: Any) -> None:
        nonlocal failure_injected
        if not failure_injected and Path(destination) == fixture.audit_wrapper:
            failure_injected = True
            raise OSError("simulated audit commit failure")
        real_replace(source, destination)

    monkeypatch.setattr(os, "replace", fail_audit_commit)

    with pytest.raises(OSError, match="Write Cline hook pair"):
        cline_io.write_hook_pair(
            cline_io.PendingWrite(guard_state, replacement_guard),
            cline_io.PendingWrite(audit_state, replacement_audit),
        )

    assert failure_injected is True
    assert fixture.guard_wrapper.read_text(encoding="utf-8") == original_guard
    assert fixture.audit_wrapper.read_text(encoding="utf-8") == original_audit
    assert list(fixture.hooks_dir.glob("*.tmp")) == []
