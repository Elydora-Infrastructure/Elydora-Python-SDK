from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from elydora.plugins import _transaction
from elydora.plugins.letta_config import render_letta_document
from elydora.plugins.letta_contract import build_letta_group
from elydora.plugins.letta_installation import (
    commit_letta_installation,
    preflight_letta_installation,
    prepare_letta_installation,
)
from elydora.plugins.letta_sources import read_letta_sources
from letta_support import prepare_fixture, write_json


def _groups(guard_path: str, audit_path: str) -> dict:
    return {
        "PreToolUse": build_letta_group(guard_path),
        "PostToolUse": build_letta_group(audit_path),
        "PostToolUseFailure": build_letta_group(audit_path),
    }


def test_transaction_aborts_when_read_only_source_changes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(
        monkeypatch, tmp_path, project_settings={"owner": "before"}
    )
    sources = read_letta_sources()
    paths = preflight_letta_installation(fixture.config, sources)
    rendered = render_letta_document(
        sources.global_settings,
        None,
        _groups(paths.guard_path, paths.audit_path),
    )
    changes = prepare_letta_installation(fixture.config, paths, rendered)
    write_json(fixture.project_path, {"owner": "after"})
    with pytest.raises(OSError, match="project settings changed"):
        commit_letta_installation(changes, sources)
    assert json.loads(fixture.project_path.read_text()) == {"owner": "after"}
    assert not fixture.global_path.exists()
    assert not fixture.agent_dir.exists()


def test_transaction_rolls_back_every_runtime_and_settings_change(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(
        monkeypatch, tmp_path, global_settings={"owner": "user"}
    )
    original = fixture.source()
    real_replace = _transaction.os.replace
    failed = False

    def fail_settings_commit(source: Any, destination: Any) -> None:
        nonlocal failed
        if not failed and Path(destination) == fixture.global_path:
            failed = True
            raise OSError("simulated Letta settings commit failure")
        real_replace(source, destination)

    monkeypatch.setattr(_transaction.os, "replace", fail_settings_commit)
    with pytest.raises(OSError, match="Install Letta Code hooks"):
        fixture.install()
    assert failed
    assert fixture.source() == original
    for file_path in (
        fixture.guard_path,
        fixture.audit_path,
        fixture.runtime_config_path,
        fixture.private_key_path,
    ):
        assert not file_path.exists()
    assert [
        path
        for path in fixture.home_dir.rglob("*")
        if path.suffix in {".tmp", ".rollback"}
    ] == []


def test_install_rejects_linked_configuration_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    redirected = tmp_path / "redirected-letta"
    redirected.mkdir()
    fixture.home_dir.mkdir(parents=True)
    try:
        os.symlink(redirected, fixture.global_path.parent, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("directory links require platform privileges")
    with pytest.raises(OSError, match="global configuration directory"):
        fixture.install()
    assert not fixture.agent_dir.exists()


def test_install_rejects_directory_at_settings_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.global_path.mkdir(parents=True)
    with pytest.raises(OSError, match="global settings path"):
        fixture.install()
    assert not fixture.agent_dir.exists()
