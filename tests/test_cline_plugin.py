from __future__ import annotations

import json
from pathlib import Path

import pytest

from cline_support import (
    AGENT_ID,
    ElydoraApiHandler,
    MISSING,
    assert_no_transaction_files,
    prepare_fixture,
    python_script,
    run_wrapper,
    server_base_url,
    start_api_server,
    write_text,
)
from elydora import cli
from elydora.plugins import cline
from elydora.plugins.registry import SUPPORTED_AGENTS


def encoded(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


def official_payload(event: str) -> dict[str, object]:
    nested = {
        "id": "tool-call-1",
        "name": "read_file",
        "input": {"path": "README.md", "nested": {"preserve": True}},
    }
    value: dict[str, object] = {
        "clineVersion": "3.0.46",
        "hookName": event,
        "timestamp": "2026-07-19T12:00:00.000Z",
        "taskId": "task-1",
        "workspaceRoots": ["/workspace"],
        "userId": "user-1",
        "futureField": {"survives": ["exactly", 2]},
    }
    if event == "tool_call":
        value["tool_call"] = nested
        value["preToolUse"] = {
            "toolName": nested["name"],
            "parameters": nested["input"],
        }
    else:
        value["tool_result"] = {
            **nested,
            "output": "ok",
            "durationMs": 12,
        }
        value["postToolUse"] = {
            "toolName": nested["name"],
            "parameters": nested["input"],
            "result": "ok",
            "success": True,
            "executionTimeMs": 12,
        }
    return value


def test_cline_is_registered_in_the_sdk_and_cli() -> None:
    assert SUPPORTED_AGENTS["cline"] == {
        "name": "Cline",
        "hook_event": "PreToolUse/PostToolUse",
        "config_path": "~/.cline/hooks/PreToolUse.mjs",
    }
    assert cli.PLUGIN_MAP["cline"] is cline.ClinePlugin
    assert cline.ClinePlugin.manages_guard_runtime is True


def test_install_commits_all_six_files_and_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    before = {path: path.read_bytes() for path in fixture.managed_paths()}

    fixture.install()

    assert {path: path.read_bytes() for path in fixture.managed_paths()} == before
    assert fixture.guard_wrapper.read_text(encoding="utf-8").startswith(
        "#!/usr/bin/env node\n// @elydora-cline-hook "
    )
    assert json.loads(fixture.runtime_config.read_text(encoding="utf-8")) == {
        "org_id": "org-1",
        "agent_id": AGENT_ID,
        "kid": "key-1",
        "base_url": "http://127.0.0.1:9",
        "agent_name": "cline",
        "token": "token-1",
    }
    assert not (fixture.home_dir / "Documents" / "Cline" / "Hooks").exists()
    assert not (fixture.project_dir / ".cline" / "hooks").exists()
    assert not (fixture.project_dir / ".clinerules" / "hooks").exists()
    assert_no_transaction_files(fixture.home_dir)
    assert_no_transaction_files(fixture.cline_dir)


def test_install_uses_official_default_without_cline_dir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    monkeypatch.delenv("CLINE_DIR")

    fixture.install()

    default_hooks = fixture.home_dir / ".cline" / "hooks"
    assert (default_hooks / "PreToolUse.mjs").is_file()
    assert (default_hooks / "PostToolUse.mjs").is_file()
    assert not fixture.guard_wrapper.exists()


def test_wrappers_preserve_bytes_and_emit_pure_json_control(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    guard_capture = tmp_path / "guard-input.json"
    audit_capture = tmp_path / "audit-input.json"
    write_text(
        fixture.guard_path,
        python_script(
            "from pathlib import Path\n"
            "import sys\n"
            f"Path({str(guard_capture)!r}).write_bytes(sys.stdin.buffer.read())\n"
            "sys.stderr.write('Agent is frozen by Elydora.\\n')\n"
            "raise SystemExit(2)\n"
        ),
        0o700,
    )
    write_text(
        fixture.audit_path,
        python_script(
            "from pathlib import Path\n"
            "import sys\n"
            f"Path({str(audit_capture)!r}).write_bytes(sys.stdin.buffer.read())\n"
        ),
        0o700,
    )
    pre_raw = encoded(official_payload("tool_call"))
    post_raw = encoded(official_payload("tool_result"))

    guard = run_wrapper(fixture.guard_wrapper, fixture, pre_raw)
    audit = run_wrapper(fixture.audit_wrapper, fixture, post_raw)

    assert guard.returncode == 0
    assert json.loads(guard.stdout) == {
        "cancel": True,
        "errorMessage": "Agent is frozen by Elydora.",
    }
    assert b"HOOK_CONTROL" not in guard.stdout
    assert guard_capture.read_bytes() == pre_raw
    assert audit.returncode == 0
    assert audit.stdout == b""
    assert audit_capture.read_bytes() == post_raw


@pytest.mark.parametrize("status", ["frozen", "revoked"])
def test_generated_guard_translates_blocking_status_to_cline_control(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    status: str,
) -> None:
    server = start_api_server(status=status)
    try:
        fixture = prepare_fixture(
            monkeypatch, tmp_path, base_url=server_base_url(server)
        )
        fixture.install()
        result = run_wrapper(
            fixture.guard_wrapper,
            fixture,
            encoded(official_payload("tool_call")),
        )
    finally:
        server.shutdown()
        server.server_close()

    assert result.returncode == 0
    assert json.loads(result.stdout)["cancel"] is True
    assert status.encode() in result.stderr.lower()


def test_wrappers_keep_passes_quiet_and_surface_runtime_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    write_text(
        fixture.guard_path,
        python_script("import sys\nsys.stdin.buffer.read()\n"),
        0o700,
    )
    passing = run_wrapper(fixture.guard_wrapper, fixture, b"{}")
    assert passing.returncode == 0
    assert passing.stdout == b""

    write_text(
        fixture.audit_path,
        python_script(
            "import sys\n"
            "sys.stderr.write('audit failed\\n')\n"
            "raise SystemExit(7)\n"
        ),
        0o700,
    )
    failing = run_wrapper(fixture.audit_wrapper, fixture, b"{}")
    assert failing.returncode == 1
    assert b"audit failed" in failing.stderr
    assert b"exited with code 7" in failing.stderr


def test_wrapper_rejects_a_non_absolute_runtime_shebang(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    write_text(
        fixture.guard_path,
        "#!python.exe\nimport sys\nsys.stdin.buffer.read()\n",
        0o700,
    )

    result = run_wrapper(fixture.guard_wrapper, fixture, b"{}")

    assert result.returncode == 1
    assert result.stdout == b""
    assert b"runtime shebang executable must be absolute" in result.stderr


def test_audit_submits_the_complete_native_event(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    server = start_api_server()
    payload = official_payload("tool_result")
    try:
        fixture = prepare_fixture(
            monkeypatch, tmp_path, base_url=server_base_url(server)
        )
        fixture.install()
        result = run_wrapper(fixture.audit_wrapper, fixture, encoded(payload))
    finally:
        server.shutdown()
        server.server_close()

    assert result.returncode == 0
    request = next(
        item for item in ElydoraApiHandler.requests if item["method"] == "POST"
    )
    operation = request["json"]
    assert operation["payload"] == payload
    assert operation["action"] == {"tool": "read_file"}
    assert operation["subject"] == {"session_id": "task-1"}
    assert request["authorization"] == "Bearer token-1"


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("guard", None),
        ("audit", None),
        ("config", "parse Elydora runtime config"),
        ("key", "private key.*canonical 32-byte"),
        ("wrapper", "managed template"),
    ],
)
def test_status_requires_exact_physical_runtime_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    target: str,
    expected: str | None,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    assert fixture.plugin.status()["installed"] is True
    if target == "guard":
        write_text(fixture.guard_path, "tampered\n", 0o700)
    elif target == "audit":
        write_text(fixture.audit_path, "tampered\n", 0o700)
    elif target == "config":
        write_text(fixture.runtime_config, "{ malformed")
    elif target == "key":
        write_text(fixture.private_key, "invalid")
    else:
        source = fixture.guard_wrapper.read_text(encoding="utf-8")
        write_text(fixture.guard_wrapper, source + "// tampered\n", 0o700)

    if expected is None:
        assert fixture.plugin.status()["installed"] is False
    else:
        with pytest.raises(ValueError, match=expected):
            fixture.plugin.status()


@pytest.mark.parametrize(
    ("source", "pattern"),
    [
        ('{"agent_name":"cline","agent_name":"cline"}', "duplicate field"),
        (
            json.dumps(
                {
                    "org_id": "org-1",
                    "agent_id": "other-agent",
                    "kid": "key-1",
                    "base_url": "https://api.elydora.com",
                    "agent_name": "cline",
                }
            ),
            "identity does not match",
        ),
        (
            json.dumps(
                {
                    "org_id": "org-1",
                    "agent_id": AGENT_ID,
                    "kid": "key-1",
                    "base_url": "https://api.elydora.com",
                    "agent_name": "cline",
                    "hidden": True,
                }
            ),
            "unsupported field",
        ),
    ],
)
def test_status_surfaces_invalid_runtime_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    source: str,
    pattern: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    write_text(fixture.runtime_config, source)

    with pytest.raises(ValueError, match=pattern):
        fixture.plugin.status()


@pytest.mark.parametrize("collision", ["guard", "audit"])
def test_install_rejects_user_filename_collisions_before_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    collision: str,
) -> None:
    guard = "// user PreToolUse hook\n" if collision == "guard" else MISSING
    audit = "// user PostToolUse hook\n" if collision == "audit" else MISSING
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        existing_guard=guard,
        existing_audit=audit,
    )

    with pytest.raises(ValueError, match="owned by another integration"):
        fixture.install()

    assert not fixture.agent_dir.exists()
    path = fixture.guard_wrapper if collision == "guard" else fixture.audit_wrapper
    assert path.read_text(encoding="utf-8").startswith("// user")


def test_install_preserves_corrupt_metadata_for_recovery(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    corrupt = "#!/usr/bin/env node\n// @elydora-cline-hook invalid\n"
    fixture = prepare_fixture(monkeypatch, tmp_path, existing_guard=corrupt)

    with pytest.raises(ValueError, match="parse Elydora Cline hook metadata"):
        fixture.install()

    assert fixture.guard_wrapper.read_text(encoding="utf-8") == corrupt
    assert not fixture.agent_dir.exists()


def test_uninstall_removes_exact_ownership_and_preserves_adjacent_hooks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    user_hook = fixture.hooks_dir / "PreToolUse.py"
    write_text(user_hook, "# user hook\n")

    fixture.plugin.uninstall("agent-10")
    assert fixture.guard_wrapper.is_file()
    assert fixture.audit_wrapper.is_file()
    fixture.plugin.uninstall(AGENT_ID)

    assert not fixture.guard_wrapper.exists()
    assert not fixture.audit_wrapper.exists()
    assert user_hook.read_text(encoding="utf-8") == "# user hook\n"


def test_runtime_failures_remain_observable_and_fail_open(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    guard = run_wrapper(
        fixture.guard_wrapper,
        fixture,
        encoded(official_payload("tool_call")),
    )
    audit = run_wrapper(fixture.audit_wrapper, fixture, b"{ malformed")

    assert guard.returncode == 0
    assert b"Failed to resolve agent status" in guard.stderr
    assert audit.returncode == 0
    assert b"invalid JSON" in (fixture.agent_dir / "error.log").read_bytes()
