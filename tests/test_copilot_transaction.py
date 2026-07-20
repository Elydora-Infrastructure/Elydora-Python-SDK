from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from elydora.plugins import _transaction, copilot
from elydora.plugins.copilot_installation import prepare_copilot_installation
from elydora.plugins.copilot_io import read_sources

from copilot_support import (
    AGENT_ID,
    assert_runtime_absent,
    legacy_managed_config,
    prepare_fixture,
    write_json_or_text,
)


def test_install_rolls_back_runtime_hooks_and_legacy_after_late_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        user_config={"version": 1, "hooks": {"notification": []}},
    )
    write_json_or_text(fixture.legacy_path, legacy_managed_config(fixture))
    user_before = fixture.config_path.read_text(encoding="utf-8")
    legacy_before = fixture.legacy_path.read_text(encoding="utf-8")
    original_commit = _transaction._commit
    commits = 0

    def fail_after_fifth_commit(staged: Any) -> None:
        nonlocal commits
        original_commit(staged)
        commits += 1
        if commits == 5:
            raise OSError("injected late commit failure")

    monkeypatch.setattr(_transaction, "_commit", fail_after_fifth_commit)
    with pytest.raises(OSError, match="injected late commit failure"):
        fixture.plugin.install(fixture.config)

    assert fixture.config_path.read_text(encoding="utf-8") == user_before
    assert fixture.legacy_path.read_text(encoding="utf-8") == legacy_before
    assert_runtime_absent(fixture)


def test_install_detects_concurrent_hook_replacement_before_its_commit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        user_config={"version": 1, "hooks": {"notification": []}},
    )
    concurrent = '{"version":1,"hooks":{"notification":[]},"external":true}\n'
    original_commit = _transaction._commit
    commits = 0

    def replace_after_first_commit(staged: Any) -> None:
        nonlocal commits
        original_commit(staged)
        commits += 1
        if commits == 1:
            fixture.config_path.write_text(concurrent, encoding="utf-8")

    monkeypatch.setattr(_transaction, "_commit", replace_after_first_commit)
    with pytest.raises(OSError, match="changed during installation"):
        fixture.plugin.install(fixture.config)

    assert fixture.config_path.read_text(encoding="utf-8") == concurrent
    assert_runtime_absent(fixture)


def test_install_rolls_back_when_effective_settings_change_mid_transaction(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        user_settings={"disableAllHooks": False},
    )
    original_commit = _transaction._commit
    commits = 0

    def disable_after_third_commit(staged: Any) -> None:
        nonlocal commits
        original_commit(staged)
        commits += 1
        if commits == 3:
            write_json_or_text(
                fixture.user_settings_path,
                {"disableAllHooks": True},
            )

    monkeypatch.setattr(_transaction, "_commit", disable_after_third_commit)
    with pytest.raises(OSError, match="user settings changed"):
        fixture.plugin.install(fixture.config)

    assert json.loads(
        fixture.user_settings_path.read_text(encoding="utf-8")
    )["disableAllHooks"] is True
    assert fixture.config_path.exists() is False
    assert_runtime_absent(fixture)


def test_prepare_rejects_same_content_stale_hook_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        user_config={"version": 1, "hooks": {"notification": []}},
    )
    sources = read_sources()
    paths = copilot.preflight_copilot_installation(fixture.config, sources)
    rendered = copilot._render_installation(
        sources,
        paths.guard_path,
        paths.audit_path,
    )
    original = fixture.config_path.read_text(encoding="utf-8")
    replacement = fixture.config_path.with_name("replacement.json")
    replacement.write_text(original, encoding="utf-8")
    os.replace(replacement, fixture.config_path)

    with pytest.raises(OSError, match="changed before staging"):
        prepare_copilot_installation(fixture.config, sources, rendered)
    assert_runtime_absent(fixture)


def test_install_preserves_orphaned_runtime_without_verifiable_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.agent_dir.mkdir(parents=True)
    fixture.hook_path.write_text("# orphaned\n", encoding="utf-8")

    with pytest.raises(ValueError, match="cannot be verified"):
        fixture.plugin.install(fixture.config)

    assert fixture.hook_path.read_text(encoding="utf-8") == "# orphaned\n"
    assert fixture.config_path.exists() is False
    assert fixture.guard_path.exists() is False
    assert fixture.runtime_config_path.exists() is False
    assert fixture.private_key_path.exists() is False


def _symlink_or_skip(
    target: Path,
    link: Path,
    *,
    directory: bool,
) -> None:
    try:
        link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, link, target_is_directory=directory)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symbolic links unavailable: {error}")


@pytest.mark.parametrize("location", ["home", "hook", "runtime"])
def test_install_rejects_linked_hook_and_runtime_paths(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    location: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    if location == "home":
        target = tmp_path / "copilot-target"
        target.mkdir()
        linked = tmp_path / "linked-copilot-home"
        _symlink_or_skip(target, linked, directory=True)
        monkeypatch.setenv("COPILOT_HOME", str(linked))
    elif location == "hook":
        target = tmp_path / "hook-target.json"
        write_json_or_text(target, {"version": 1, "hooks": {}})
        _symlink_or_skip(target, fixture.config_path, directory=False)
    else:
        target = tmp_path / "runtime-target"
        target.mkdir()
        fixture.agent_dir.parent.mkdir(parents=True)
        _symlink_or_skip(target, fixture.agent_dir, directory=True)

    with pytest.raises(OSError, match="physical"):
        fixture.plugin.install(fixture.config)


def test_uninstall_restores_both_hook_documents_when_second_commit_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    managed = fixture.config_path.read_text(encoding="utf-8")
    fixture.legacy_path.parent.mkdir(parents=True, exist_ok=True)
    fixture.legacy_path.write_text(managed, encoding="utf-8")
    user_before = fixture.config_path.read_text(encoding="utf-8")
    legacy_before = fixture.legacy_path.read_text(encoding="utf-8")
    original_commit = _transaction._commit
    commits = 0

    def fail_after_second_commit(staged: Any) -> None:
        nonlocal commits
        original_commit(staged)
        commits += 1
        if commits == 2:
            raise OSError("injected uninstall failure")

    monkeypatch.setattr(_transaction, "_commit", fail_after_second_commit)
    with pytest.raises(OSError, match="injected uninstall failure"):
        fixture.plugin.uninstall(AGENT_ID)

    assert fixture.config_path.read_text(encoding="utf-8") == user_before
    assert fixture.legacy_path.read_text(encoding="utf-8") == legacy_before


def test_installation_leaves_no_transaction_artifacts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    for directory in (fixture.agent_dir, fixture.config_path.parent):
        assert all(
            path.suffix not in {".tmp", ".rollback"}
            for path in directory.iterdir()
        )
