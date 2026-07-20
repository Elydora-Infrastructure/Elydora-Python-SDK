from __future__ import annotations

import os
from pathlib import Path
import subprocess  # nosec B404
import sys
from typing import Any, Dict

import pytest

from elydora.plugins import _transaction, droid
from elydora.plugins.droid_config import render_document, source_documents
from elydora.plugins.droid_installation import (
    commit_droid_installation,
    commit_droid_uninstall,
    preflight_droid_installation,
    prepare_droid_installation,
    prepare_droid_uninstall,
)
from elydora.plugins.droid_io import read_sources

from droid_support import (
    AGENT_ID,
    VALID_PRIVATE_KEY,
    DroidFixture,
    assert_no_transaction_files,
    assert_snapshot,
    load_jsonc,
    snapshot,
    write_json,
)


def _prepare_installation(
    fixture: DroidFixture,
    **overrides: str,
):
    config: Dict[str, Any] = dict(fixture.config)
    config.update(overrides)
    sources = read_sources()
    paths = preflight_droid_installation(config, sources)
    rendered = droid._render_installation(  # noqa: SLF001
        sources,
        paths.guard_path,
        paths.audit_path,
    )
    return prepare_droid_installation(config, sources, rendered)


def _managed_paths(fixture: DroidFixture) -> tuple[Path, ...]:
    return (
        fixture.guard_path,
        fixture.runtime_config,
        fixture.private_key_path,
        fixture.audit_path,
        fixture.root_path,
    )


def test_install_rolls_back_runtime_after_late_hook_commit_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = DroidFixture(monkeypatch, tmp_path)
    prepared = _prepare_installation(fixture)
    real_replace = _transaction.os.replace
    failed = False

    def fail_hook_commit(source: Any, destination: Any) -> None:
        nonlocal failed
        if not failed and Path(destination) == fixture.root_path:
            failed = True
            raise OSError("injected Droid hook commit failure")
        real_replace(source, destination)

    monkeypatch.setattr(_transaction.os, "replace", fail_hook_commit)
    with pytest.raises(OSError, match="injected Droid hook commit failure"):
        commit_droid_installation(prepared)
    assert failed is True
    for path in _managed_paths(fixture):
        assert not path.exists()
    assert_no_transaction_files(tmp_path)


def test_concurrent_active_hook_replacement_prevents_runtime_commit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = DroidFixture(monkeypatch, tmp_path)
    fixture.install()
    before = snapshot(_managed_paths(fixture))
    prepared = _prepare_installation(fixture, org_id="org-updated")
    concurrent = '{"hooks":{"PreToolUse":[]},"owner":"concurrent"}\n'
    fixture.root_path.write_text(concurrent, encoding="utf-8")
    with pytest.raises(OSError, match="hooks changed during Install Factory Droid"):
        commit_droid_installation(prepared)
    for path, source in before.items():
        if path != fixture.root_path:
            assert path.read_text(encoding="utf-8") == source
    assert fixture.root_path.read_text(encoding="utf-8") == concurrent
    assert_no_transaction_files(tmp_path)


def test_concurrent_inactive_local_source_creation_is_detected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = DroidFixture(monkeypatch, tmp_path)
    fixture.install()
    before = snapshot(_managed_paths(fixture))
    prepared = _prepare_installation(fixture, org_id="org-updated")
    concurrent = '{"hooksDisabled":true}\n'
    fixture.local_settings_path.write_text(concurrent, encoding="utf-8")
    with pytest.raises(OSError, match="local settings changed during Install"):
        commit_droid_installation(prepared)
    assert_snapshot(before)
    assert fixture.local_settings_path.read_text(encoding="utf-8") == concurrent
    assert_no_transaction_files(tmp_path)


def test_concurrent_project_policy_change_is_detected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = DroidFixture(
        monkeypatch,
        tmp_path,
        project_settings={"hooksDisabled": False},
    )
    fixture.install()
    before = snapshot(_managed_paths(fixture))
    prepared = _prepare_installation(fixture, org_id="org-updated")
    concurrent = '{"hooksDisabled":true}\n'
    fixture.project_settings_path.write_text(concurrent, encoding="utf-8")
    with pytest.raises(OSError, match="project settings changed during Install"):
        commit_droid_installation(prepared)
    assert_snapshot(before)
    assert fixture.project_settings_path.read_text(encoding="utf-8") == concurrent
    assert_no_transaction_files(tmp_path)


def test_same_content_replacement_is_rejected_by_physical_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = DroidFixture(monkeypatch, tmp_path)
    fixture.install()
    before = snapshot(_managed_paths(fixture))
    sources = read_sources()
    original = fixture.root_path.read_text(encoding="utf-8")
    fixture.root_path.unlink()
    fixture.root_path.write_text(original, encoding="utf-8")
    config: Dict[str, Any] = dict(fixture.config)
    config["org_id"] = "org-updated"
    paths = preflight_droid_installation(config, sources)
    rendered = droid._render_installation(  # noqa: SLF001
        sources,
        paths.guard_path,
        paths.audit_path,
    )
    prepared = prepare_droid_installation(config, sources, rendered)
    with pytest.raises(OSError, match="hooks changed during Install"):
        commit_droid_installation(prepared)
    assert fixture.root_path.read_text(encoding="utf-8") == original
    for path, source in before.items():
        if path != fixture.root_path:
            assert path.read_text(encoding="utf-8") == source
    assert_no_transaction_files(tmp_path)


def test_orphaned_runtime_is_preserved_without_verifiable_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = DroidFixture(monkeypatch, tmp_path)
    fixture.agent_dir.mkdir(parents=True)
    fixture.guard_path.write_text("orphaned guard\n", encoding="utf-8")
    with pytest.raises(ValueError, match="identity cannot be verified"):
        fixture.install()
    assert fixture.guard_path.read_text(encoding="utf-8") == "orphaned guard\n"
    assert not fixture.root_path.exists()


def test_uninstall_rolls_back_all_hook_documents(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = DroidFixture(monkeypatch, tmp_path)
    fixture.install()
    installed = load_jsonc(fixture.root_path)
    write_json(
        fixture.settings_path,
        {"hooks": installed["hooks"], "owner": "user"},
    )
    paths = (*_managed_paths(fixture), fixture.settings_path)
    before = snapshot(paths)
    sources = read_sources()
    rendered = [
        render_document(document, AGENT_ID, {})
        for document in source_documents(sources)
    ]
    prepared = prepare_droid_uninstall(rendered)
    real_replace = _transaction.os.replace
    failed = False

    def fail_second_source(source: Any, destination: Any) -> None:
        nonlocal failed
        if not failed and Path(destination) == fixture.settings_path:
            failed = True
            raise OSError("injected Droid uninstall failure")
        real_replace(source, destination)

    monkeypatch.setattr(_transaction.os, "replace", fail_second_source)
    with pytest.raises(OSError, match="injected Droid uninstall failure"):
        commit_droid_uninstall(prepared)
    assert failed is True
    assert_snapshot(before)
    assert_no_transaction_files(tmp_path)


def test_cli_preflight_blocks_disabled_hooks_before_runtime_creation(
    tmp_path: Path,
) -> None:
    home_dir = tmp_path / "cli-home"
    settings_path = home_dir / ".factory" / "settings.json"
    key_path = tmp_path / "private.key"
    write_json(settings_path, {"hooksDisabled": True})
    key_path.write_text(
        VALID_PRIVATE_KEY,
        encoding="utf-8",
    )
    environment = {
        **os.environ,
        "HOME": str(home_dir),
        "USERPROFILE": str(home_dir),
    }
    result = subprocess.run(  # nosec B603
        [
            sys.executable,
            "-m",
            "elydora.cli",
            "install",
            "--agent",
            "droid",
            "--org_id",
            "org-1",
            "--agent_id",
            AGENT_ID,
            "--private_key_file",
            str(key_path),
            "--kid",
            "kid-1",
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
    assert "hooksDisabled" in result.stderr
    assert not (home_dir / ".elydora").exists()
