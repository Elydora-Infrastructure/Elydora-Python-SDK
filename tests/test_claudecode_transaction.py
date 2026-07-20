from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess  # nosec B404
import sys

import pytest

from claudecode_support import (
    AGENT_ID,
    VALID_PRIVATE_KEY,
    prepare_fixture,
    symlink_or_skip,
    write_json,
    write_text,
)
from elydora.plugins import _transaction, claudecode_installation
from elydora.plugins.claudecode_contract import (
    AUDIT_STATUS,
    GUARD_STATUS,
    build_claude_group,
    remove_managed_claude_hooks,
    render_claude_document,
)
from elydora.plugins.claudecode_io import read_claude_document
from elydora.utils import base64url_encode


RUNTIME_NAMES = ("guard.py", "config.json", "private.key", "hook.py")


def prepare_installation(fixture: object) -> list[_transaction.FileChange]:
    document = read_claude_document()
    paths = claudecode_installation.preflight_claude_installation(
        fixture.config, document
    )
    cleaned = remove_managed_claude_hooks(document.hooks)
    hooks = {
        **cleaned,
        "PreToolUse": [
            *cleaned.get("PreToolUse", []),
            build_claude_group(paths.guard_path, GUARD_STATUS),
        ],
        "PostToolUse": [
            *cleaned.get("PostToolUse", []),
            build_claude_group(paths.audit_path, AUDIT_STATUS),
        ],
        "PostToolUseFailure": [
            *cleaned.get("PostToolUseFailure", []),
            build_claude_group(paths.audit_path, AUDIT_STATUS),
        ],
    }
    return claudecode_installation.prepare_claude_installation(
        fixture.config, paths, render_claude_document(document, hooks)
    )


def assert_no_transaction_files(root: Path) -> None:
    assert not list(root.rglob("*.tmp"))
    assert not list(root.rglob("*.rollback"))


def test_transaction_rolls_back_all_five_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    original = '{"model":"sonnet"}\n'
    fixture = prepare_fixture(
        monkeypatch, tmp_path, existing_settings=original
    )
    real_replace = _transaction.os.replace
    failed = False

    def fail_settings_once(source: str, destination: str) -> None:
        nonlocal failed
        if os.path.abspath(destination) == str(fixture.config_path) and not failed:
            failed = True
            raise OSError("injected Claude settings failure")
        real_replace(source, destination)

    monkeypatch.setattr(_transaction.os, "replace", fail_settings_once)

    with pytest.raises(OSError, match="injected Claude settings failure"):
        fixture.install()

    assert fixture.config_path.read_text(encoding="utf-8") == original
    for name in RUNTIME_NAMES:
        assert not (fixture.agent_dir / name).exists()
    assert_no_transaction_files(fixture.home_dir)


def test_concurrent_settings_change_is_detected_before_runtime_commits(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(
        monkeypatch, tmp_path, existing_settings={"model": "sonnet"}
    )
    changes = prepare_installation(fixture)
    concurrent = '{"model":"opus"}\n'
    fixture.config_path.write_text(concurrent, encoding="utf-8")

    with pytest.raises(OSError, match="changed during installation"):
        claudecode_installation.commit_claude_installation(changes)

    assert fixture.config_path.read_text(encoding="utf-8") == concurrent
    for name in RUNTIME_NAMES:
        assert not (fixture.agent_dir / name).exists()
    assert_no_transaction_files(fixture.home_dir)


def test_recovery_preserves_original_after_committed_runtime_changes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    original = fixture.runtime_config_path.read_text(encoding="utf-8")
    fixture.config["org_id"] = "org-updated"
    fixture.config["private_key"] = base64url_encode(bytes(range(31, -1, -1)))
    changes = prepare_installation(fixture)
    real_replace = _transaction.os.replace
    calls = 0

    def change_first_then_fail(source: str, destination: str) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            real_replace(source, destination)
            write_text(Path(destination), "external change\n")
            return
        raise OSError("injected later commit failure")

    monkeypatch.setattr(_transaction.os, "replace", change_first_then_fail)

    with pytest.raises(OSError, match="original content preserved at"):
        claudecode_installation.commit_claude_installation(changes)

    assert fixture.runtime_config_path.read_text(encoding="utf-8") == "external change\n"
    rollbacks = list(fixture.agent_dir.glob(".config.json.*.rollback"))
    assert len(rollbacks) == 1
    assert rollbacks[0].read_text(encoding="utf-8") == original


@pytest.mark.parametrize("runtime_name", [
    "private.key", "guard.py", "hook.py", "chain-state.json",
    "status-cache.json", "error.log",
])
def test_orphan_runtime_artifacts_fail_before_settings_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    runtime_name: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    artifact = fixture.agent_dir / runtime_name
    write_text(artifact, "orphan\n")

    with pytest.raises(ValueError, match="identity cannot be verified"):
        fixture.install()

    assert artifact.read_text(encoding="utf-8") == "orphan\n"
    assert not fixture.config_path.exists()


def test_mismatched_runtime_identity_fails_before_writes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    write_json(fixture.runtime_config_path, {
        "agent_id": "another-agent", "agent_name": "claudecode",
    })
    original = fixture.runtime_config_path.read_text(encoding="utf-8")

    with pytest.raises(ValueError, match="identity does not match"):
        fixture.install()

    assert fixture.runtime_config_path.read_text(encoding="utf-8") == original
    assert not fixture.config_path.exists()


@pytest.mark.parametrize("kind", ["configuration", "settings", "runtime"])
def test_linked_configuration_and_runtime_paths_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    kind: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    target = tmp_path / f"{kind}-target"
    if kind == "settings":
        write_text(target, "{}\n")
        fixture.config_path.parent.mkdir(parents=True)
        symlink_or_skip(target, fixture.config_path)
    else:
        target.mkdir()
        link = (
            fixture.config_path.parent
            if kind == "configuration"
            else fixture.agent_dir.parent
        )
        if kind == "runtime" and link.exists():
            shutil.rmtree(link)
        link.parent.mkdir(parents=True, exist_ok=True)
        symlink_or_skip(target, link, directory=True)

    with pytest.raises(OSError, match="physical (file|directory)"):
        fixture.install()


@pytest.mark.parametrize(
    ("field", "value", "pattern"),
    [
        ("agent_name", "codex", "requires agent_name claudecode"),
        ("agent_id", "../escape", "Invalid agent ID"),
        ("private_key", "invalid", "canonical 32-byte"),
        ("token", "", "non-empty string"),
        ("base_url", "https://api.elydora.com?q=1", "query parameters"),
        ("guard_script_path", "outside", "managed agent directory"),
    ],
)
def test_install_validates_runtime_inputs_before_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    field: str,
    value: str,
    pattern: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.config[field] = value

    with pytest.raises(ValueError, match=pattern):
        fixture.install()

    assert not fixture.config_path.exists()
    assert not fixture.agent_dir.exists()


def test_status_surfaces_malformed_runtime_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    fixture.runtime_config_path.write_text("{ malformed", encoding="utf-8")

    with pytest.raises(ValueError, match="parse Elydora runtime config"):
        fixture.plugin.status()


def test_installation_leaves_no_transaction_artifacts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    assert_no_transaction_files(fixture.home_dir)


def test_cli_preflight_preserves_malformed_settings(
    tmp_path: Path,
) -> None:
    home_dir = tmp_path / "cli-home"
    settings_path = home_dir / ".claude" / "settings.json"
    key_path = tmp_path / "private.key"
    write_text(settings_path, "{ malformed")
    write_text(key_path, VALID_PRIVATE_KEY)
    environment = {**os.environ, "HOME": str(home_dir), "USERPROFILE": str(home_dir)}
    environment.pop("CLAUDE_CONFIG_DIR", None)

    result = subprocess.run(
        [
            sys.executable, "-m", "elydora.cli", "install",
            "--agent", "claudecode", "--org_id", "org-1",
            "--agent_id", AGENT_ID, "--private_key_file", str(key_path),
            "--kid", "key-1", "--base_url", "https://api.elydora.com",
        ],
        capture_output=True,
        check=False,
        cwd=Path(__file__).parents[1],
        env=environment,
        text=True,
    )

    assert result.returncode == 1
    assert "parse Claude Code user settings" in result.stderr
    assert settings_path.read_text(encoding="utf-8") == "{ malformed"
    assert not (home_dir / ".elydora").exists()
