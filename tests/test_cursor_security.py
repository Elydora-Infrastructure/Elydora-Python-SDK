from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from cursor_support import (
    AGENT_ID,
    prepare_fixture,
    symlink_or_skip,
    write_json,
    write_text,
)


@pytest.mark.parametrize(
    "runtime_name",
    [
        "guard.py",
        "hook.py",
        "private.key",
        "chain-state.json",
        "status-cache.json",
        "error.log",
    ],
)
def test_orphan_runtime_artifacts_are_rejected(
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
    assert fixture.config_path.exists() is False


def test_mismatched_runtime_identity_is_rejected_before_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    write_json(
        fixture.runtime_config_path,
        {"agent_id": "another-agent", "agent_name": "cursor"},
    )
    original = fixture.runtime_config_path.read_text(encoding="utf-8")

    with pytest.raises(ValueError, match="identity does not match"):
        fixture.install()

    assert fixture.runtime_config_path.read_text(encoding="utf-8") == original
    assert fixture.config_path.exists() is False


@pytest.mark.parametrize(
    "runtime_name",
    [
        "config.json",
        "private.key",
        "guard.py",
        "hook.py",
        "chain-state.json",
        "status-cache.json",
        "error.log",
    ],
)
def test_symbolic_link_runtime_is_rejected_before_config_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    runtime_name: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    target = fixture.home_dir / f"{runtime_name}.target"
    source = (
        json.dumps({"agent_id": AGENT_ID, "agent_name": "cursor"})
        if runtime_name == "config.json"
        else "target\n"
    )
    write_text(target, source)
    runtime_path = fixture.agent_dir / runtime_name
    symlink_or_skip(target, runtime_path)

    with pytest.raises(OSError, match="physical file"):
        fixture.install()

    assert target.read_text(encoding="utf-8") == source
    assert fixture.config_path.exists() is False


def test_symbolic_link_config_is_rejected_and_target_is_preserved(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    target = fixture.home_dir / "cursor-hooks.target.json"
    original = '{"version":1,"hooks":{}}\n'
    write_text(target, original)
    fixture.config_path.parent.mkdir(parents=True)
    symlink_or_skip(target, fixture.config_path)

    with pytest.raises(OSError, match="physical file"):
        fixture.install()

    assert target.read_text(encoding="utf-8") == original
    assert fixture.config_path.is_symlink()


def test_symbolic_link_config_directory_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    target = fixture.home_dir / "cursor-target"
    target.mkdir()
    symlink_or_skip(target, fixture.config_path.parent, directory=True)

    with pytest.raises(OSError, match="not a physical directory"):
        fixture.install()

    assert list(target.iterdir()) == []


def test_symbolic_link_agent_directory_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.agent_dir.rmdir()
    target = fixture.home_dir / "agent-target"
    target.mkdir()
    symlink_or_skip(target, fixture.agent_dir, directory=True)

    with pytest.raises(OSError, match="not a physical directory"):
        fixture.install()

    assert fixture.config_path.exists() is False
    assert list(target.iterdir()) == []


def test_symbolic_link_runtime_root_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.agent_dir.rmdir()
    fixture.agent_dir.parent.rmdir()
    target = fixture.home_dir / "runtime-target"
    (target / AGENT_ID).mkdir(parents=True)
    symlink_or_skip(target, fixture.agent_dir.parent, directory=True)

    with pytest.raises(OSError, match="not a physical directory"):
        fixture.install()

    assert fixture.config_path.exists() is False
    assert list((target / AGENT_ID).iterdir()) == []


@pytest.mark.parametrize(
    "runtime_name",
    ["config.json", "private.key", "guard.py", "hook.py"],
)
def test_status_rejects_symbolic_link_runtime_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    runtime_name: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    runtime_path = fixture.agent_dir / runtime_name
    target = fixture.home_dir / f"status-{runtime_name}.target"
    target.write_bytes(runtime_path.read_bytes())
    runtime_path.unlink()
    symlink_or_skip(target, runtime_path)

    with pytest.raises(OSError, match="physical file"):
        fixture.plugin.status()


def test_transaction_rolls_back_all_files_when_config_commit_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        existing_config={"version": 1, "hooks": {"sessionStart": []}},
    )
    original = fixture.config_path.read_text(encoding="utf-8")
    real_replace = os.replace
    failed = False

    def fail_config_once(source: str, destination: str) -> None:
        nonlocal failed
        if os.path.abspath(destination) == str(fixture.config_path) and not failed:
            failed = True
            raise OSError("injected config commit failure")
        real_replace(source, destination)

    monkeypatch.setattr(os, "replace", fail_config_once)

    with pytest.raises(OSError, match="injected config commit failure"):
        fixture.install()

    assert fixture.config_path.read_text(encoding="utf-8") == original
    for path in (
        fixture.guard_path,
        fixture.hook_path,
        fixture.runtime_config_path,
        fixture.private_key_path,
    ):
        assert path.exists() is False
    assert not list(fixture.home_dir.rglob("*.tmp"))
    assert not list(fixture.home_dir.rglob("*.rollback"))


def test_transaction_detects_concurrent_config_change(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from elydora.plugins._transaction import write_changes
    from elydora.plugins.cursor_contract import render_document
    from elydora.plugins.cursor_io import read_document, rendered_change

    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        existing_config={
            "version": 1,
            "hooks": {"sessionStart": [{"command": "original"}]},
        },
    )
    document = read_document()
    change = rendered_change(render_document(document, {}))
    assert change is not None
    concurrent = '{"version":1,"hooks":{"sessionStart":[]}}\n'
    fixture.config_path.write_text(concurrent, encoding="utf-8")

    with pytest.raises(OSError, match="changed during installation"):
        write_changes([change], "Update Cursor hooks")

    assert fixture.config_path.read_text(encoding="utf-8") == concurrent
    assert not list(fixture.config_path.parent.glob("*.tmp"))
