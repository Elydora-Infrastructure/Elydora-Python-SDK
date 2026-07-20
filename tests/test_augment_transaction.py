from __future__ import annotations

import os
from pathlib import Path
import subprocess  # nosec B404
import sys

import pytest

from augment_support import (
    AGENT_ID,
    VALID_PRIVATE_KEY,
    prepare_fixture,
    symlink_or_skip,
    write_json,
    write_text,
)
from elydora.plugins import _transaction, augment, augment_installation
from elydora.plugins.augment_contract import render_augment_document
from elydora.plugins.augment_io import read_augment_document


RUNTIME_NAMES = (
    "guard.py",
    "config.json",
    "private.key",
    "hook.py",
    "augment-guard.cmd" if os.name == "nt" else "augment-guard.sh",
    "augment-hook.cmd" if os.name == "nt" else "augment-hook.sh",
)


def prepare_installation(fixture: object) -> list[_transaction.FileChange]:
    document = read_augment_document()
    paths = augment_installation.preflight_augment_installation(
        fixture.config, document
    )
    rendered = render_augment_document(
        document, augment._installed_hooks(document.hooks, paths)
    )
    return augment_installation.prepare_augment_installation(
        fixture.config, paths, rendered
    )


def assert_no_transaction_files(root: Path) -> None:
    assert not list(root.rglob("*.tmp"))
    assert not list(root.rglob("*.rollback"))


def test_transaction_rolls_back_all_seven_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    original = '{"telemetryEnabled":true}\n'
    fixture = prepare_fixture(monkeypatch, tmp_path, existing_settings=original)
    real_replace = _transaction.os.replace
    failed = False

    def fail_settings_once(source: str, destination: str) -> None:
        nonlocal failed
        if os.path.abspath(destination) == str(fixture.config_path) and not failed:
            failed = True
            raise OSError("injected Auggie settings failure")
        real_replace(source, destination)

    monkeypatch.setattr(_transaction.os, "replace", fail_settings_once)
    with pytest.raises(OSError, match="injected Auggie settings failure"):
        fixture.install()

    assert fixture.config_path.read_text(encoding="utf-8") == original
    for name in RUNTIME_NAMES:
        assert not (fixture.agent_dir / name).exists()
    assert_no_transaction_files(fixture.home_dir)


def test_concurrent_settings_change_is_detected_before_runtime_commits(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(
        monkeypatch, tmp_path, existing_settings={"telemetryEnabled": True}
    )
    changes = prepare_installation(fixture)
    concurrent = '{"telemetryEnabled":false,"hooks":{"Notification":[]}}\n'
    fixture.config_path.write_text(concurrent, encoding="utf-8")

    with pytest.raises(OSError, match="changed during installation"):
        augment_installation.commit_augment_installation(changes)

    assert fixture.config_path.read_text(encoding="utf-8") == concurrent
    for name in RUNTIME_NAMES:
        assert not (fixture.agent_dir / name).exists()
    assert_no_transaction_files(fixture.home_dir)


def test_stale_settings_are_rejected_before_staging(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    document = read_augment_document()
    paths = augment_installation.preflight_augment_installation(
        fixture.config, document
    )
    rendered = render_augment_document(
        document, augment._installed_hooks(document.hooks, paths)
    )
    write_text(fixture.config_path, '{"hooks":{"Notification":[]}}\n')
    with pytest.raises(OSError, match="changed before staging"):
        augment_installation.prepare_augment_installation(
            fixture.config, paths, rendered
        )
    assert not fixture.agent_dir.exists()
    assert_no_transaction_files(fixture.home_dir)


@pytest.mark.parametrize(
    "runtime_name",
    [
        "private.key",
        "guard.py",
        "hook.py",
        "augment-guard.cmd" if os.name == "nt" else "augment-guard.sh",
        "augment-hook.cmd" if os.name == "nt" else "augment-hook.sh",
        "chain-state.json",
        "status-cache.json",
        "error.log",
    ],
)
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
    write_json(
        fixture.runtime_config_path,
        {
            "agent_id": "another-agent",
            "agent_name": "augment",
        },
    )
    original = fixture.runtime_config_path.read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="identity does not match"):
        fixture.install()
    assert fixture.runtime_config_path.read_text(encoding="utf-8") == original
    assert not fixture.config_path.exists()


@pytest.mark.parametrize("kind", ["configuration", "settings", "runtime", "wrapper"])
def test_linked_settings_runtime_and_wrapper_paths_are_rejected(
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
    elif kind == "configuration":
        target.mkdir()
        fixture.config_path.parent.parent.mkdir(parents=True)
        symlink_or_skip(target, fixture.config_path.parent, directory=True)
    elif kind == "runtime":
        target.mkdir()
        fixture.agent_dir.parent.parent.mkdir(parents=True)
        symlink_or_skip(target, fixture.agent_dir.parent, directory=True)
    else:
        fixture.install()
        write_text(target, "external wrapper\n")
        fixture.guard_wrapper_path.unlink()
        symlink_or_skip(target, fixture.guard_wrapper_path)

    with pytest.raises(OSError, match="physical (file|directory)"):
        fixture.install()


@pytest.mark.parametrize(
    ("field", "value", "pattern"),
    [
        ("agent_name", "codex", "requires agent_name augment"),
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


def test_installation_leaves_no_transaction_artifacts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    assert_no_transaction_files(fixture.home_dir)


def test_cli_preflight_preserves_malformed_settings(tmp_path: Path) -> None:
    home_dir = tmp_path / "cli-home"
    settings_path = home_dir / ".augment" / "settings.json"
    key_path = tmp_path / "private.key"
    write_text(settings_path, "{ malformed")
    write_text(key_path, VALID_PRIVATE_KEY)
    environment = {**os.environ, "HOME": str(home_dir), "USERPROFILE": str(home_dir)}
    result = subprocess.run(  # nosec B603
        [
            sys.executable,
            "-m",
            "elydora.cli",
            "install",
            "--agent",
            "augment",
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
    assert "parse Auggie user settings" in result.stderr
    assert settings_path.read_text(encoding="utf-8") == "{ malformed"
    assert not (home_dir / ".elydora").exists()
