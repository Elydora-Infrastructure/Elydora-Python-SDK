from __future__ import annotations

import os
from pathlib import Path
import subprocess  # nosec B404
import sys

import pytest

from cline_support import (
    AGENT_ID,
    VALID_PRIVATE_KEY,
    assert_no_transaction_files,
    assert_snapshot,
    prepare_fixture,
    snapshot_installation,
    symlink_or_skip,
    write_json,
    write_text,
)
from elydora.plugins import _transaction, cline_installation
from elydora.plugins.cline_contract import resolve_hook_files
from elydora.plugins.cline_io import read_hook_file


def prepare_installation(fixture: object) -> list[_transaction.FileChange]:
    paths = resolve_hook_files()
    guard = read_hook_file(paths.guard_path)
    audit = read_hook_file(paths.audit_path)
    return cline_installation.prepare_cline_installation(
        fixture.config, guard, audit
    )


def test_transaction_rolls_back_all_six_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    real_replace = _transaction.os.replace
    failed = False

    def fail_audit_once(source: str, destination: str) -> None:
        nonlocal failed
        if os.path.abspath(destination) == str(fixture.audit_wrapper) and not failed:
            failed = True
            raise OSError("injected Cline audit hook failure")
        real_replace(source, destination)

    monkeypatch.setattr(_transaction.os, "replace", fail_audit_once)
    with pytest.raises(OSError, match="injected Cline audit hook failure"):
        fixture.install()

    assert failed is True
    assert all(not path.exists() for path in fixture.managed_paths())
    assert_no_transaction_files(fixture.home_dir)
    assert_no_transaction_files(fixture.cline_dir)


def test_concurrent_hook_replacement_is_detected_before_final_commit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    changes = prepare_installation(fixture)
    concurrent = "// concurrently replaced\n"
    real_replace = _transaction.os.replace
    injected = False

    def inject_replacement(source: str, destination: str) -> None:
        nonlocal injected
        if not injected:
            injected = True
            write_text(fixture.audit_wrapper, concurrent, 0o700)
        real_replace(source, destination)

    monkeypatch.setattr(_transaction.os, "replace", inject_replacement)
    with pytest.raises(OSError, match="changed during installation"):
        cline_installation.commit_cline_installation(changes)

    assert injected is True
    assert fixture.audit_wrapper.read_text(encoding="utf-8") == concurrent
    for path in fixture.managed_paths()[:-1]:
        assert not path.exists()
    assert_no_transaction_files(fixture.home_dir)
    assert_no_transaction_files(fixture.cline_dir)


def test_stale_hook_snapshot_is_rejected_before_staging(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    paths = resolve_hook_files()
    guard = read_hook_file(paths.guard_path)
    audit = read_hook_file(paths.audit_path)
    concurrent = "// stale snapshot replacement\n"
    write_text(fixture.audit_wrapper, concurrent, 0o700)

    with pytest.raises(OSError, match="changed before staging"):
        cline_installation.prepare_cline_installation(
            fixture.config, guard, audit
        )

    assert fixture.audit_wrapper.read_text(encoding="utf-8") == concurrent
    assert not fixture.agent_dir.exists()
    assert_no_transaction_files(fixture.root_dir)


@pytest.mark.parametrize(
    "runtime_name",
    [
        "private.key",
        "guard.py",
        "hook.py",
        "chain-state.json",
        "status-cache.json",
        "error.log",
    ],
)
def test_orphan_runtime_artifacts_fail_before_hook_writes(
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
    assert not fixture.guard_wrapper.exists()
    assert not fixture.audit_wrapper.exists()


def test_mismatched_runtime_identity_fails_before_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    write_json(
        fixture.runtime_config,
        {"agent_id": "another-agent", "agent_name": "cline"},
    )
    original = fixture.runtime_config.read_text(encoding="utf-8")

    with pytest.raises(ValueError, match="identity does not match"):
        fixture.install()

    assert fixture.runtime_config.read_text(encoding="utf-8") == original
    assert not fixture.guard_wrapper.exists()


@pytest.mark.parametrize(
    "kind", ["configuration", "hooks", "runtime", "hook"]
)
def test_linked_configuration_runtime_and_hook_paths_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    kind: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    target = tmp_path / f"{kind}-target"
    if kind == "configuration":
        target.mkdir()
        symlink_or_skip(target, fixture.cline_dir, directory=True)
    elif kind == "hooks":
        target.mkdir()
        fixture.cline_dir.mkdir()
        symlink_or_skip(target, fixture.hooks_dir, directory=True)
    elif kind == "runtime":
        target.mkdir()
        fixture.home_dir.mkdir()
        symlink_or_skip(
            target, fixture.home_dir / ".elydora", directory=True
        )
    else:
        fixture.install()
        write_text(target, "external hook\n")
        fixture.guard_wrapper.unlink()
        symlink_or_skip(target, fixture.guard_wrapper)

    with pytest.raises(OSError, match="physical (file|directory)"):
        fixture.install()


@pytest.mark.parametrize(
    ("field", "value", "pattern"),
    [
        ("agent_name", "codex", "requires agent_name cline"),
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

    assert not fixture.agent_dir.exists()
    assert not fixture.hooks_dir.exists()


def test_uninstall_restores_both_hooks_when_second_removal_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    before = snapshot_installation(fixture)
    paths = resolve_hook_files()
    changes = cline_installation.prepare_cline_uninstall(
        (
            read_hook_file(paths.guard_path),
            read_hook_file(paths.audit_path),
        ),
        AGENT_ID,
    )
    real_replace = _transaction.os.replace
    failed = False

    def fail_audit_removal(source: str, destination: str) -> None:
        nonlocal failed
        if os.path.abspath(source) == str(fixture.audit_wrapper) and not failed:
            failed = True
            raise OSError("injected Cline uninstall failure")
        real_replace(source, destination)

    monkeypatch.setattr(_transaction.os, "replace", fail_audit_removal)
    with pytest.raises(OSError, match="injected Cline uninstall failure"):
        cline_installation.commit_cline_uninstall(changes)

    assert failed is True
    assert_snapshot(before)
    assert_no_transaction_files(fixture.root_dir)


def test_installation_leaves_no_transaction_artifacts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    assert_no_transaction_files(fixture.root_dir)


def test_cli_preflight_preserves_a_hook_collision(tmp_path: Path) -> None:
    home_dir = tmp_path / "cli-home"
    hook_path = home_dir / ".cline" / "hooks" / "PreToolUse.mjs"
    key_path = tmp_path / "private.key"
    write_text(hook_path, "// user hook\n", 0o700)
    write_text(key_path, VALID_PRIVATE_KEY)
    environment = {
        key: value
        for key, value in {
            **os.environ,
            "HOME": str(home_dir),
            "USERPROFILE": str(home_dir),
        }.items()
        if key != "CLINE_DIR"
    }
    result = subprocess.run(  # nosec B603
        [
            sys.executable,
            "-m",
            "elydora.cli",
            "install",
            "--agent",
            "cline",
            "--org_id",
            "org-1",
            "--agent_id",
            AGENT_ID,
            "--private_key_file",
            str(key_path),
            "--kid",
            "key-1",
            "--base_url",
            "https://api.elydora.com",
        ],
        capture_output=True,
        check=False,
        cwd=Path(__file__).parents[1],
        env=environment,
        text=True,
    )

    assert result.returncode == 1
    assert "owned by another integration" in result.stderr
    assert hook_path.read_text(encoding="utf-8") == "// user hook\n"
    assert not (home_dir / ".elydora").exists()
