from __future__ import annotations

import base64
import copy
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import stat
import sys
import threading
import time
from typing import Any

import pytest

from elydora import cli
from elydora.plugins import kiroide
from elydora.plugins._shell_command import is_python_executable, windows_powershell_path
from elydora.plugins import (
    _transaction,
    kiroide_command,
    kiroide_contract,
    kiroide_installation,
    kiroide_io,
)
from elydora.plugins.base import InstallConfig
from elydora.plugins.registry import SUPPORTED_AGENTS


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


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _install_config(home: Path) -> InstallConfig:
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


def _prepare_fixture(
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
            _write_json(config_path, current)
    if legacy is not None:
        if isinstance(legacy, str):
            legacy_path.parent.mkdir(parents=True)
            legacy_path.write_text(legacy, encoding="utf-8")
        else:
            _write_json(legacy_path, legacy)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.chdir(workspace)
    agent_directory = home / ".elydora" / AGENT_ID
    config = _install_config(home)
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


def _find_hook(document: dict[str, Any], name: str) -> dict[str, Any]:
    return next(hook for hook in document["hooks"] if hook.get("name") == name)


def _managed_document(guard_command: str, audit_command: str) -> dict[str, Any]:
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


def _legacy_document(fixture: KiroIdeFixture, agent_id: str = AGENT_ID) -> dict:
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


def _legacy_runtime_config(
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


def _write_legacy_runtime(fixture: KiroIdeFixture, agent_id: str) -> Path:
    agent_directory = fixture.home / ".elydora" / agent_id
    _write_json(
        agent_directory / "config.json",
        _legacy_runtime_config(fixture, agent_id),
    )
    (agent_directory / "private.key").write_text(PRIVATE_KEY, encoding="utf-8")
    (agent_directory / "guard.py").write_text("guard\n", encoding="utf-8")
    (agent_directory / "hook.py").write_text("audit\n", encoding="utf-8")
    return agent_directory


def _write_large_error_log(agent_directory: Path, marker: bytes) -> Path:
    error_log = agent_directory / "error.log"
    with error_log.open("wb") as file:
        for _index in range(48):
            file.write(marker * 4096)
    if os.name != "nt":
        error_log.chmod(0o600)
    assert error_log.stat().st_size > 2 * 1024 * 1024
    return error_log


def _run_command(
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


class _AuditHandler(BaseHTTPRequestHandler):
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
class _AuditServer:
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


def _start_audit_server() -> _AuditServer:
    _AuditHandler.operations = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AuditHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return _AuditServer(server, thread)


def _prepare_installation(
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


def test_kiroide_uses_current_workspace_v1_hook_contract(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    home = tmp_path / "home with spaces"
    workspace = tmp_path / "workspace with spaces"
    home.mkdir()
    workspace.mkdir()
    config_path = workspace / ".kiro" / "hooks" / "elydora-audit.json"
    existing_hook = {
        "name": "workspace-context",
        "trigger": "SessionStart",
        "action": {"type": "agent", "prompt": "Read AGENTS.md"},
        "enabled": True,
    }
    _write_json(
        config_path,
        {"version": "v1", "owner": "workspace", "hooks": [existing_hook]},
    )
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.chdir(workspace)

    plugin = kiroide.KiroIdePlugin()
    plugin.install(_install_config(home))
    first_source = config_path.read_text(encoding="utf-8")
    plugin.install(_install_config(home))

    assert SUPPORTED_AGENTS["kiroide"] == {
        "name": "Kiro IDE",
        "hook_event": "PreToolUse/PostToolUse",
        "config_path": ".kiro/hooks/elydora-audit.json",
    }
    assert config_path.read_text(encoding="utf-8") == first_source
    document = json.loads(first_source)
    assert document["version"] == "v1"
    assert document["owner"] == "workspace"
    assert document["hooks"][0] == existing_hook
    assert document["hooks"][1]["trigger"] == "PreToolUse"
    assert document["hooks"][2]["trigger"] == "PostToolUse"
    assert all(hook["matcher"] == ".*" for hook in document["hooks"][1:])
    assert all(hook["timeout"] == 10 for hook in document["hooks"][1:])
    assert all(hook["enabled"] is True for hook in document["hooks"][1:])
    assert not (home / ".kiro" / "hooks" / "elydora-audit.json").exists()
    private_key_path = home / ".elydora" / AGENT_ID / "private.key"
    audit_path = home / ".elydora" / AGENT_ID / "hook.py"
    assert private_key_path.read_text(encoding="utf-8") == PRIVATE_KEY
    assert PRIVATE_KEY not in audit_path.read_text(encoding="utf-8")
    if os.name != "nt":
        assert private_key_path.stat().st_mode & 0o777 == 0o600
        assert audit_path.stat().st_mode & 0o777 == 0o700


def test_kiroide_commands_block_frozen_agents_and_forward_native_events(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    api = _start_audit_server()
    try:
        fixture = _prepare_fixture(
            monkeypatch, tmp_path, base_url=api.base_url
        )
        fixture.plugin.install(fixture.config)
        document = json.loads(fixture.config_path.read_text(encoding="utf-8"))
        payload = {
            "hook_event_name": "preToolUse",
            "cwd": str(fixture.workspace),
            "session_id": "session-1",
            "tool_name": "execute_bash",
            "tool_input": {"command": "pytest -q"},
            "future_field": {"retained": True},
        }
        status_cache_path = fixture.agent_directory / "status-cache.json"
        _write_json(
            status_cache_path,
            {"status": "frozen", "cached_at": time.time()},
        )
        if os.name != "nt":
            status_cache_path.chmod(0o600)

        blocked = _run_command(
            _find_hook(document, "elydora-guard")["action"]["command"],
            fixture,
            payload,
        )
        assert blocked.returncode == 2
        assert "Tool execution blocked" in blocked.stderr

        payload["hook_event_name"] = "postToolUse"
        payload["tool_response"] = {"success": True, "result": "12 passed"}
        audited = _run_command(
            _find_hook(document, "elydora-audit")["action"]["command"],
            fixture,
            payload,
        )
        assert audited.returncode == 0, audited.stderr
        assert _AuditHandler.operations[-1]["payload"] == payload
        assert _AuditHandler.operations[-1]["action"] == {
            "tool": "execute_bash"
        }
        assert _AuditHandler.operations[-1]["subject"] == {
            "session_id": "session-1"
        }
    finally:
        api.close()


def test_kiroide_status_requires_exact_enabled_hooks_and_runtime_sources(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    assert fixture.plugin.status() == {
        "installed": True,
        "agent": "kiroide",
        "details": f"Config: {fixture.config_path}",
    }

    document = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    _find_hook(document, "elydora-guard")["enabled"] = False
    _write_json(fixture.config_path, document)
    assert fixture.plugin.status() == {
        "installed": False,
        "agent": "kiroide",
        "details": (
            "Managed hooks are incomplete or invalid: "
            f"{fixture.config_path}"
        ),
    }

    fixture.plugin.install(fixture.config)
    fixture.guard_path.write_text("tampered\n", encoding="utf-8")
    status = fixture.plugin.status()
    assert status["installed"] is False
    assert "runtime files are missing or invalid" in status["details"]


def test_kiroide_status_surfaces_malformed_runtime_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    (fixture.agent_directory / "config.json").write_text(
        "{ malformed", encoding="utf-8"
    )

    with pytest.raises(ValueError, match="parse Elydora runtime config"):
        fixture.plugin.status()


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("{ malformed", "parse Kiro IDE hooks"),
        (
            '{"version":"v1","version":"v1","hooks":[]}',
            'duplicate field "version"',
        ),
        ({"version": "v0", "hooks": []}, 'version must be "v1"'),
        ({"version": "v1", "hooks": None}, 'field "hooks" must be an array'),
        (
            {
                "version": "v1",
                "hooks": [
                    {
                        "name": "bad",
                        "trigger": "FutureEvent",
                        "action": {"type": "command", "command": "echo bad"},
                    }
                ],
            },
            "unsupported trigger",
        ),
    ],
)
def test_kiroide_rejects_invalid_workspace_hooks_before_runtime_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    source: Any,
    message: str,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path, current=source)
    original = fixture.config_path.read_text(encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        fixture.plugin.install(fixture.config)

    assert fixture.config_path.read_text(encoding="utf-8") == original
    assert not fixture.agent_directory.exists()


def test_kiroide_cli_preflight_rejects_workspace_before_runtime_creation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path, current="{ malformed")
    private_key_file = tmp_path / "private.key"
    token_file = tmp_path / "token"
    private_key_file.write_text(PRIVATE_KEY, encoding="utf-8")
    token_file.write_text("token-1", encoding="utf-8")
    if os.name != "nt":
        private_key_file.chmod(0o600)
        token_file.chmod(0o600)
    args = cli.build_parser().parse_args(
        [
            "install",
            "--agent",
            "kiroide",
            "--org_id",
            "org-1",
            "--agent_id",
            AGENT_ID,
            "--private_key_file",
            str(private_key_file),
            "--token_file",
            str(token_file),
            "--kid",
            "kid-1",
        ]
    )

    with pytest.raises(ValueError, match="parse Kiro IDE hooks"):
        cli.cmd_install(args)

    assert fixture.config_path.read_text(encoding="utf-8") == "{ malformed"
    assert not fixture.agent_directory.exists()


def test_kiroide_rejects_noncanonical_private_keys_before_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    fixture.config["private_key"] = PRIVATE_KEY + "="

    with pytest.raises(ValueError, match="canonical 32-byte base64url"):
        fixture.plugin.install(fixture.config)

    assert not fixture.config_path.exists()
    assert not fixture.agent_directory.exists()


def test_kiroide_rejects_managed_name_collisions(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    current = {
        "version": "v1",
        "hooks": [
            {
                "name": "elydora-guard",
                "trigger": "PreToolUse",
                "action": {"type": "command", "command": "user-command"},
            }
        ],
    }
    fixture = _prepare_fixture(monkeypatch, tmp_path, current=current)

    with pytest.raises(ValueError, match="conflicts with the Elydora contract"):
        fixture.plugin.install(fixture.config)

    assert json.loads(fixture.config_path.read_text(encoding="utf-8")) == current
    assert not fixture.agent_directory.exists()


def test_kiroide_rejects_linked_workspace_configuration_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    external = tmp_path / "external-kiro"
    external.mkdir()
    try:
        (fixture.workspace / ".kiro").symlink_to(external, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"Directory symbolic links are unavailable: {error}")

    with pytest.raises(OSError, match="not a physical directory"):
        fixture.plugin.install(fixture.config)

    assert not (external / "hooks" / "elydora-audit.json").exists()
    assert not fixture.agent_directory.exists()


def test_kiroide_migrates_only_the_matching_legacy_python_hook(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    _write_json(fixture.legacy_path, _legacy_document(fixture))

    fixture.plugin.install(fixture.config)
    assert not fixture.legacy_path.exists()

    _write_json(fixture.legacy_path, _legacy_document(fixture, "agent-2"))
    fixture.plugin.install(fixture.config)
    assert fixture.legacy_path.exists()


def test_kiroide_preserves_unrelated_legacy_hook_and_rejects_malformed_legacy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    unrelated = {
        "name": "User Hook",
        "version": "1.0.0",
        "hooks": {"post_tool_use": {"command": "user-command"}},
    }
    fixture = _prepare_fixture(monkeypatch, tmp_path, legacy=unrelated)
    fixture.plugin.install(fixture.config)
    assert json.loads(fixture.legacy_path.read_text(encoding="utf-8")) == unrelated

    fixture.plugin.uninstall(AGENT_ID)
    fixture.legacy_path.write_text("{ malformed", encoding="utf-8")
    with pytest.raises(ValueError, match="parse legacy Kiro IDE hook"):
        fixture.plugin.install(fixture.config)
    assert fixture.legacy_path.read_text(encoding="utf-8") == "{ malformed"


def test_kiroide_uninstall_removes_exact_ownership_and_preserves_user_hooks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    user_hook = {
        "name": "workspace-context",
        "trigger": "SessionStart",
        "action": {"type": "agent", "prompt": "Read AGENTS.md"},
    }
    fixture = _prepare_fixture(
        monkeypatch,
        tmp_path,
        current={"version": "v1", "owner": "workspace", "hooks": [user_hook]},
    )
    fixture.plugin.install(fixture.config)

    fixture.plugin.uninstall("agent-2")
    assert len(json.loads(fixture.config_path.read_text())["hooks"]) == 3
    assert fixture.agent_directory.exists()
    assert (fixture.agent_directory / "private.key").read_text(
        encoding="utf-8"
    ) == PRIVATE_KEY
    fixture.plugin.uninstall(AGENT_ID)
    assert json.loads(fixture.config_path.read_text(encoding="utf-8")) == {
        "version": "v1",
        "owner": "workspace",
        "hooks": [user_hook],
    }

    owned = _prepare_fixture(monkeypatch, tmp_path / "owned")
    owned.plugin.install(owned.config)
    owned.plugin.uninstall(AGENT_ID)
    assert not owned.config_path.exists()


def test_kiroide_uninstall_without_agent_id_removes_owned_runtime(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)

    fixture.plugin.uninstall()

    assert not fixture.config_path.exists()
    assert not fixture.agent_directory.exists()
    assert not (fixture.agent_directory / "private.key").exists()


def test_kiroide_uninstall_without_agent_id_removes_current_and_legacy_runtimes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    legacy_agent_id = "agent-2"
    legacy_directory = _write_legacy_runtime(fixture, legacy_agent_id)
    _write_json(fixture.legacy_path, _legacy_document(fixture, legacy_agent_id))

    fixture.plugin.uninstall()

    assert not fixture.config_path.exists()
    assert not fixture.legacy_path.exists()
    assert not fixture.agent_directory.exists()
    assert not legacy_directory.exists()
    assert not (legacy_directory / "private.key").exists()


def test_kiroide_no_id_uninstall_streams_all_oversized_error_logs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    current_error = _write_large_error_log(
        fixture.agent_directory,
        b"current runtime error\n",
    )
    legacy_agent_id = "agent-2"
    legacy_directory = _write_legacy_runtime(fixture, legacy_agent_id)
    legacy_error = _write_large_error_log(
        legacy_directory,
        b"legacy runtime error\n",
    )
    _write_json(fixture.legacy_path, _legacy_document(fixture, legacy_agent_id))

    fixture.plugin.uninstall()

    assert not current_error.exists()
    assert not legacy_error.exists()
    assert not fixture.agent_directory.exists()
    assert not legacy_directory.exists()


def test_kiroide_uninstall_without_agent_id_deduplicates_current_and_legacy_owner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    _write_json(fixture.legacy_path, _legacy_document(fixture))

    fixture.plugin.uninstall()

    assert not fixture.config_path.exists()
    assert not fixture.legacy_path.exists()
    assert not fixture.agent_directory.exists()


def test_kiroide_uninstall_without_agent_id_rejects_unknown_runtime_before_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    legacy_agent_id = "agent-2"
    legacy_directory = _write_legacy_runtime(fixture, legacy_agent_id)
    _write_json(fixture.legacy_path, _legacy_document(fixture, legacy_agent_id))
    unknown = legacy_directory / "user-data.txt"
    unknown.write_text("preserve\n", encoding="utf-8")
    original_provider = fixture.config_path.read_bytes()
    original_legacy = fixture.legacy_path.read_bytes()
    original_key = (fixture.agent_directory / "private.key").read_bytes()
    original_legacy_key = (legacy_directory / "private.key").read_bytes()

    with pytest.raises(OSError, match="contains unmanaged entries"):
        fixture.plugin.uninstall()

    assert fixture.config_path.read_bytes() == original_provider
    assert fixture.legacy_path.read_bytes() == original_legacy
    assert (fixture.agent_directory / "private.key").read_bytes() == original_key
    assert (legacy_directory / "private.key").read_bytes() == original_legacy_key
    assert unknown.read_text(encoding="utf-8") == "preserve\n"


def test_kiroide_uninstall_without_agent_id_rolls_back_provider_and_runtime(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    runtime_paths = [
        fixture.guard_path,
        fixture.audit_path,
        fixture.agent_directory / "private.key",
        fixture.agent_directory / "config.json",
    ]
    original_provider = fixture.config_path.read_bytes()
    original_runtime = {path: path.read_bytes() for path in runtime_paths}
    original_capture = _transaction._capture_physical

    def fail_private_key_removal(
        source: str,
        destination: str,
        directory: _transaction.PinnedDirectory,
    ) -> None:
        if Path(source) == fixture.agent_directory / "private.key" and (
            destination.endswith(".rollback")
        ):
            raise OSError("injected private key removal failure")
        original_capture(source, destination, directory)

    monkeypatch.setattr(_transaction, "_capture_physical", fail_private_key_removal)

    with pytest.raises(OSError, match="injected private key removal failure"):
        fixture.plugin.uninstall()

    assert fixture.config_path.read_bytes() == original_provider
    assert {path: path.read_bytes() for path in runtime_paths} == original_runtime


def test_kiroide_transaction_rolls_back_when_legacy_cleanup_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    original = {"version": "v1", "owner": "workspace", "hooks": []}
    fixture = _prepare_fixture(monkeypatch, tmp_path, current=original)
    _write_json(fixture.legacy_path, _legacy_document(fixture))
    original_capture = _transaction._capture_physical

    def fail_legacy_removal(
        source: str,
        destination: str,
        directory: _transaction.PinnedDirectory,
    ) -> None:
        if Path(source) == fixture.legacy_path and destination.endswith(".rollback"):
            raise OSError("injected legacy cleanup failure")
        original_capture(source, destination, directory)

    monkeypatch.setattr(_transaction, "_capture_physical", fail_legacy_removal)

    with pytest.raises(OSError, match="injected legacy cleanup failure"):
        fixture.plugin.install(fixture.config)

    assert json.loads(fixture.config_path.read_text(encoding="utf-8")) == original
    assert fixture.legacy_path.exists()
    for path in (
        fixture.guard_path,
        fixture.audit_path,
        fixture.agent_directory / "config.json",
        fixture.agent_directory / "private.key",
    ):
        assert not path.exists()
    leftovers = list(fixture.config_path.parent.glob(".*.tmp"))
    leftovers += list(fixture.config_path.parent.glob(".*.rollback"))
    assert leftovers == []


@pytest.mark.parametrize("swapped", ["workspace", "kiro", "hooks"])
def test_kiroide_transaction_rejects_provider_directory_identity_swaps(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    swapped: str,
) -> None:
    fixture = _prepare_fixture(
        monkeypatch,
        tmp_path,
        current={"version": "v1", "hooks": []},
    )
    sources, paths, prepared, _rendered = _prepare_installation(fixture)
    monkeypatch.chdir(tmp_path)
    original_paths = {
        "workspace": fixture.workspace,
        "kiro": fixture.workspace / ".kiro",
        "hooks": fixture.workspace / ".kiro" / "hooks",
    }
    original = original_paths[swapped]
    backup = original.with_name(original.name + "-original")
    replacement = tmp_path / f"redirected-{swapped}"
    if swapped == "workspace":
        (replacement / ".kiro" / "hooks").mkdir(parents=True)
        redirected_config = replacement / ".kiro" / "hooks" / "elydora-audit.json"
    elif swapped == "kiro":
        (replacement / "hooks").mkdir(parents=True)
        redirected_config = replacement / "hooks" / "elydora-audit.json"
    else:
        replacement.mkdir()
        redirected_config = replacement / "elydora-audit.json"
    original.rename(backup)
    try:
        original.symlink_to(replacement, target_is_directory=True)
    except OSError as error:
        backup.rename(original)
        pytest.skip(f"Directory symbolic links are unavailable: {error}")

    with pytest.raises(OSError, match="not a physical directory|changed during"):
        kiroide_installation.commit_kiroide_installation(
            prepared, sources, paths
        )

    assert not redirected_config.exists()
    assert not fixture.agent_directory.exists()


def test_kiroide_key_rotation_pins_unchanged_provider_sources(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    original_key = (fixture.agent_directory / "private.key").read_text(
        encoding="utf-8"
    )
    rotated = InstallConfig(**fixture.config)
    rotated["private_key"] = ROTATED_PRIVATE_KEY
    sources, paths, prepared, rendered = _prepare_installation(fixture, rotated)
    assert rendered.changed is False
    document = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    document["concurrent_change"] = True
    _write_json(fixture.config_path, document)

    with pytest.raises(OSError, match="Kiro IDE hooks changed during"):
        kiroide_installation.commit_kiroide_installation(
            prepared, sources, paths
        )

    assert (fixture.agent_directory / "private.key").read_text(
        encoding="utf-8"
    ) == original_key
    assert json.loads(fixture.config_path.read_text(encoding="utf-8"))[
        "concurrent_change"
    ] is True


def test_kiroide_noop_install_rejects_concurrent_provider_changes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    sources, paths, prepared, rendered = _prepare_installation(fixture)
    assert prepared.changes == []
    assert rendered.changed is False
    document = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    _find_hook(document, "elydora-guard")["enabled"] = False
    _write_json(fixture.config_path, document)

    with pytest.raises(OSError, match="Kiro IDE hooks changed during"):
        kiroide_installation.commit_kiroide_installation(
            prepared, sources, paths
        )

    assert _find_hook(
        json.loads(fixture.config_path.read_text(encoding="utf-8")),
        "elydora-guard",
    )["enabled"] is False


@pytest.mark.parametrize(
    "relative_path",
    ["private.key", "config.json", "guard.py", "hook.py"],
)
def test_kiroide_noop_install_pins_every_runtime_source(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    relative_path: str,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    sources, paths, prepared, _rendered = _prepare_installation(fixture)
    assert prepared.changes == []
    assert len(prepared.runtime_preconditions) == 4
    target = fixture.agent_directory / relative_path
    concurrent = target.read_text(encoding="utf-8") + "\nconcurrent-change"
    target.write_text(concurrent, encoding="utf-8")

    with pytest.raises(OSError, match="changed during Install Kiro IDE hooks"):
        kiroide_installation.commit_kiroide_installation(
            prepared, sources, paths
        )

    assert target.read_text(encoding="utf-8") == concurrent


def test_kiroide_runtime_config_binds_agent_to_absolute_workspace(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)

    runtime_config = json.loads(
        (fixture.agent_directory / "config.json").read_text(encoding="utf-8")
    )
    assert runtime_config["workspace_root"] == str(fixture.workspace.resolve())
    assert Path(runtime_config["workspace_root"]).is_absolute()


def test_kiroide_rejects_same_agent_install_from_another_workspace(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    original_hook = fixture.config_path.read_bytes()
    runtime_config_path = fixture.agent_directory / "config.json"
    original_runtime = runtime_config_path.read_bytes()
    second_workspace = tmp_path / "second workspace"
    second_workspace.mkdir()
    monkeypatch.chdir(second_workspace)

    with pytest.raises(ValueError, match="bound to another workspace"):
        fixture.plugin.install(fixture.config)

    assert fixture.config_path.read_bytes() == original_hook
    assert runtime_config_path.read_bytes() == original_runtime
    assert not (second_workspace / ".kiro").exists()


def test_kiroide_cli_uninstall_requires_bound_workspace(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    original_hook = fixture.config_path.read_bytes()
    second_workspace = tmp_path / "second workspace"
    second_workspace.mkdir()
    args = cli.build_parser().parse_args(
        [
            "uninstall",
            "--agent",
            "kiroide",
            "--agent_id",
            AGENT_ID,
        ]
    )
    monkeypatch.chdir(second_workspace)

    with pytest.raises(ValueError, match="bound to another workspace"):
        cli.cmd_uninstall(args)

    assert fixture.config_path.read_bytes() == original_hook
    assert fixture.agent_directory.exists()
    assert not (second_workspace / ".kiro").exists()

    monkeypatch.chdir(fixture.workspace)
    cli.cmd_uninstall(args)
    assert not fixture.config_path.exists()
    assert not fixture.agent_directory.exists()


def test_kiroide_install_claims_legacy_runtime_owner_from_matching_hooks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    runtime_config_path = fixture.agent_directory / "config.json"
    runtime_config = json.loads(runtime_config_path.read_text(encoding="utf-8"))
    runtime_config.pop("workspace_root")
    _write_json(runtime_config_path, runtime_config)

    fixture.plugin.install(fixture.config)

    claimed = json.loads(runtime_config_path.read_text(encoding="utf-8"))
    assert claimed["workspace_root"] == str(fixture.workspace.resolve())


def test_kiroide_install_migrates_exact_global_legacy_runtime_owner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    _write_json(fixture.legacy_path, _legacy_document(fixture))
    runtime_config_path = fixture.agent_directory / "config.json"
    _write_json(runtime_config_path, _legacy_runtime_config(fixture))
    config = dict(fixture.config)
    config.pop("token")

    fixture.plugin.install(config)

    migrated = json.loads(runtime_config_path.read_text(encoding="utf-8"))
    assert migrated["workspace_root"] == str(fixture.workspace.resolve())
    assert "token" not in migrated
    assert fixture.config_path.exists()
    assert not fixture.legacy_path.exists()


def test_kiroide_legacy_owner_migration_rolls_back_runtime_claim(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    _write_json(fixture.legacy_path, _legacy_document(fixture))
    runtime_config_path = fixture.agent_directory / "config.json"
    original_runtime = _legacy_runtime_config(fixture)
    _write_json(runtime_config_path, original_runtime)
    original_capture = _transaction._capture_physical

    def fail_legacy_removal(
        source: str,
        destination: str,
        directory: _transaction.PinnedDirectory,
    ) -> None:
        if Path(source) == fixture.legacy_path and destination.endswith(
            ".rollback"
        ):
            raise OSError("injected legacy migration failure")
        original_capture(source, destination, directory)

    monkeypatch.setattr(_transaction, "_capture_physical", fail_legacy_removal)

    with pytest.raises(OSError, match="injected legacy migration failure"):
        fixture.plugin.install(fixture.config)

    assert json.loads(runtime_config_path.read_text(encoding="utf-8")) == (
        original_runtime
    )
    assert fixture.legacy_path.exists()
    assert not fixture.config_path.exists()


def test_kiroide_cli_uninstall_accepts_exact_global_legacy_ownership(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    _write_json(fixture.legacy_path, _legacy_document(fixture))
    _write_json(
        fixture.agent_directory / "config.json",
        _legacy_runtime_config(fixture),
    )
    args = cli.build_parser().parse_args(
        [
            "uninstall",
            "--agent",
            "kiroide",
            "--agent_id",
            AGENT_ID,
        ]
    )

    cli.cmd_uninstall(args)

    assert not fixture.legacy_path.exists()
    assert not fixture.agent_directory.exists()
    assert not fixture.config_path.exists()


def test_kiroide_rejects_unproved_legacy_runtime_owner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    _write_json(fixture.legacy_path, _legacy_document(fixture, "agent-2"))
    runtime_config_path = fixture.agent_directory / "config.json"
    original = _legacy_runtime_config(fixture)
    _write_json(runtime_config_path, original)

    with pytest.raises(ValueError, match="token is invalid"):
        fixture.plugin.install(fixture.config)

    assert json.loads(runtime_config_path.read_text(encoding="utf-8")) == original
    assert fixture.legacy_path.exists()
    assert not fixture.config_path.exists()


def test_kiroide_rejects_invalid_ownerless_legacy_runtime_config(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    _write_json(fixture.legacy_path, _legacy_document(fixture))
    runtime_config_path = fixture.agent_directory / "config.json"
    invalid = _legacy_runtime_config(fixture)
    invalid["token"] = " "
    _write_json(runtime_config_path, invalid)

    with pytest.raises(ValueError, match="token is invalid"):
        fixture.plugin.install(fixture.config)

    assert json.loads(runtime_config_path.read_text(encoding="utf-8")) == invalid
    assert fixture.legacy_path.exists()
    assert not fixture.config_path.exists()


@pytest.mark.parametrize(
    ("owner", "message"),
    [("relative", "must be absolute"), ("other", "bound to another workspace")],
)
def test_kiroide_status_rejects_invalid_runtime_workspace_owner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    owner: str,
    message: str,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    runtime_config_path = fixture.agent_directory / "config.json"
    runtime_config = json.loads(runtime_config_path.read_text(encoding="utf-8"))
    runtime_config["workspace_root"] = (
        "relative" if owner == "relative" else str((tmp_path / "other").resolve())
    )
    _write_json(runtime_config_path, runtime_config)

    with pytest.raises(ValueError, match=message):
        fixture.plugin.status()


def test_kiroide_failed_install_removes_created_workspace_and_runtime_directories(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)

    def fail_first_commit(
        _source: str,
        _destination: str,
        _directory: _transaction.PinnedDirectory,
    ) -> None:
        raise OSError("injected Kiro IDE commit failure")

    monkeypatch.setattr(_transaction, "_replace_physical", fail_first_commit)

    with pytest.raises(OSError, match="injected Kiro IDE commit failure"):
        fixture.plugin.install(fixture.config)

    assert not (fixture.workspace / ".kiro").exists()
    # The durable transaction state directory survives failures by design;
    # everything else under the runtime root must be rolled back.
    elydora_root = fixture.home / ".elydora"
    if elydora_root.exists():
        assert [entry.name for entry in elydora_root.iterdir()] == ["transactions"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission contract")
@pytest.mark.parametrize("relative_path", ["private.key", "config.json"])
def test_kiroide_noop_install_pins_runtime_secret_modes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    relative_path: str,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    sources, paths, prepared, _rendered = _prepare_installation(fixture)
    target = fixture.agent_directory / relative_path
    target.chmod(0o640)

    with pytest.raises(OSError, match="changed during Install Kiro IDE hooks"):
        kiroide_installation.commit_kiroide_installation(
            prepared, sources, paths
        )

    assert stat.S_IMODE(target.stat().st_mode) == 0o640


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission contract")
def test_kiroide_key_rotation_rejects_concurrent_mode_changes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    rotated = InstallConfig(**fixture.config)
    rotated["private_key"] = ROTATED_PRIVATE_KEY
    sources, paths, prepared, _rendered = _prepare_installation(
        fixture, rotated
    )
    key_path = fixture.agent_directory / "private.key"
    assert any(change.file_path == str(key_path) for change in prepared.changes)
    key_path.chmod(0o640)

    with pytest.raises(OSError, match="changed during installation"):
        kiroide_installation.commit_kiroide_installation(
            prepared, sources, paths
        )

    assert key_path.read_text(encoding="utf-8") == PRIVATE_KEY
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o640


def test_kiroide_install_rejects_runtime_root_link_created_after_prepare(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    sources, paths, prepared, _rendered = _prepare_installation(fixture)
    runtime_root = fixture.home / ".elydora"
    redirected_root = tmp_path / "redirected-runtime-root"
    redirected_root.mkdir()
    try:
        runtime_root.symlink_to(redirected_root, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"Directory symbolic links are unavailable: {error}")

    with pytest.raises(OSError, match="not a physical directory|changed during"):
        kiroide_installation.commit_kiroide_installation(
            prepared, sources, paths
        )

    assert not (redirected_root / AGENT_ID / "private.key").exists()
    assert not fixture.config_path.exists()


def test_kiroide_install_rejects_agent_directory_identity_swap(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    fixture.agent_directory.mkdir(parents=True)
    sources, paths, prepared, _rendered = _prepare_installation(fixture)
    original_directory = fixture.agent_directory.with_name("agent-original")
    fixture.agent_directory.rename(original_directory)
    fixture.agent_directory.mkdir()

    with pytest.raises(OSError, match="changed during"):
        kiroide_installation.commit_kiroide_installation(
            prepared, sources, paths
        )

    assert not (fixture.agent_directory / "private.key").exists()
    assert not fixture.config_path.exists()


def test_kiroide_exact_managed_commands_survive_python_relocation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    executable_name = "python.exe" if os.name == "nt" else "python3"
    fake_executable = tmp_path / "other-runtime" / executable_name
    with monkeypatch.context() as command_context:
        command_context.setattr(
            kiroide_command.sys, "executable", str(fake_executable)
        )
        guard_command = kiroide_command.build_kiroide_command(
            str(fixture.guard_path)
        )
        audit_command = kiroide_command.build_kiroide_command(
            str(fixture.audit_path)
        )
    stale_document = _managed_document(guard_command, audit_command)
    _write_json(fixture.config_path, stale_document)

    assert fixture.plugin.status() == {
        "installed": False,
        "agent": "kiroide",
        "details": (
            "Managed hooks are incomplete or invalid: "
            f"{fixture.config_path}"
        ),
    }

    fixture.plugin.install(fixture.config)
    repaired = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    assert kiroide_command.kiroide_runtime_reference(
        _find_hook(repaired, "elydora-guard")["action"]["command"],
        "guard.py",
    ) is not None
    assert kiroide_command.kiroide_runtime_reference(
        _find_hook(repaired, "elydora-audit")["action"]["command"],
        "hook.py",
    ) is not None

    _write_json(fixture.config_path, stale_document)
    fixture.plugin.uninstall(AGENT_ID)

    assert not fixture.config_path.exists()


@pytest.mark.parametrize("damage", ["field", "orphan"])
def test_kiroide_stale_command_ownership_survives_contract_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    damage: str,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    executable_name = "python.exe" if os.name == "nt" else "python3"
    fake_executable = tmp_path / "other-runtime" / executable_name
    with monkeypatch.context() as command_context:
        command_context.setattr(
            kiroide_command.sys, "executable", str(fake_executable)
        )
        document = _managed_document(
            kiroide_command.build_kiroide_command(str(fixture.guard_path)),
            kiroide_command.build_kiroide_command(str(fixture.audit_path)),
        )
    if damage == "field":
        _find_hook(document, "elydora-guard")["timeout"] = 9
    else:
        document["hooks"].remove(_find_hook(document, "elydora-audit"))
    _write_json(fixture.config_path, document)

    fixture.plugin.install(fixture.config)
    repaired = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    assert len(repaired["hooks"]) == 2
    assert all(hook["timeout"] == 10 for hook in repaired["hooks"])

    _write_json(fixture.config_path, document)
    fixture.plugin.uninstall(AGENT_ID)

    assert json.loads(fixture.config_path.read_text(encoding="utf-8"))[
        "hooks"
    ] == []


@pytest.mark.skipif(os.name != "nt", reason="Windows launcher contract")
def test_kiroide_current_commands_require_the_system_powershell_launcher(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    command = kiroide_command.build_kiroide_command(str(fixture.guard_path))
    expected = f'"{windows_powershell_path()}"'
    altered = command.replace(expected, r'"C:\Other\powershell.exe"', 1)

    assert kiroide_command.kiroide_runtime_reference(altered, "guard.py") is None


@pytest.mark.skipif(os.name != "nt", reason="Windows launcher contract")
def test_kiroide_windows_launcher_fails_when_python_is_missing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    missing_python = tmp_path / "missing-runtime" / "python.exe"
    script_path = tmp_path / "guard.py"
    with monkeypatch.context() as command_context:
        command_context.setattr(
            kiroide_command.sys, "executable", str(missing_python)
        )
        command = kiroide_command.build_kiroide_command(str(script_path))

    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 1
    assert result.stderr


@pytest.mark.parametrize(
    "executable_name",
    ["python3.13t", "python3.14t", "python3.13d.exe", "pypy3", "pypy3.10.exe"],
)
def test_kiroide_ownership_accepts_supported_python_runtime_names(
    executable_name: str,
) -> None:
    assert is_python_executable(executable_name)


def test_kiroide_builder_rejects_unrecoverable_executable_names(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    with monkeypatch.context() as command_context:
        command_context.setattr(
            kiroide_command.sys,
            "executable",
            str(tmp_path / "embedded-runtime"),
        )
        with pytest.raises(ValueError, match="absolute Python executable"):
            kiroide_command.build_kiroide_command(str(tmp_path / "guard.py"))


@pytest.mark.parametrize("damage", ["orphan", "duplicate", "altered"])
def test_kiroide_status_rejects_every_incomplete_managed_hook_set(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    damage: str,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    document = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    audit = _find_hook(document, "elydora-audit")
    if damage == "orphan":
        document["hooks"].remove(audit)
    elif damage == "duplicate":
        document["hooks"].append(copy.deepcopy(audit))
    else:
        _find_hook(document, "elydora-guard")["timeout"] = 9
    _write_json(fixture.config_path, document)

    status = fixture.plugin.status()
    assert status["installed"] is False
    assert status["details"] == (
        f"Managed hooks are incomplete or invalid: {fixture.config_path}"
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission contract")
@pytest.mark.parametrize(
    ("target", "message"),
    [
        ("key", "private key must be accessible only by its owner"),
        ("config", "Token-bearing Elydora runtime config must be accessible"),
    ],
)
def test_kiroide_repairs_and_enforces_owner_only_runtime_secrets(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    target: str,
    message: str,
) -> None:
    fixture = _prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    paths = {
        "key": fixture.agent_directory / "private.key",
        "config": fixture.agent_directory / "config.json",
    }
    paths[target].chmod(0o644)

    with pytest.raises(ValueError, match=message):
        fixture.plugin.status()

    fixture.plugin.install(fixture.config)
    assert stat.S_IMODE(paths[target].stat().st_mode) == 0o600
    assert fixture.plugin.status()["installed"] is True
