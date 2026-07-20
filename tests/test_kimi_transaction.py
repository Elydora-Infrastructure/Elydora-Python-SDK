from __future__ import annotations

import os
from pathlib import Path

import pytest

from elydora.plugins import _transaction, kimi_installation
from elydora.plugins.kimi_contract import (
    build_kimi_hook,
    remove_managed_kimi_hooks,
    render_kimi_document,
)
from elydora.plugins.kimi_io import read_kimi_documents
from kimi_support import (
    AGENT_ID,
    assert_no_transaction_files,
    prepare_fixture,
    write_text,
)


RUNTIME_NAMES = ("guard.py", "config.json", "private.key", "hook.py")


def snapshot_files(paths: list[Path]) -> dict[Path, str]:
    return {path: path.read_text(encoding="utf-8") for path in paths}


def assert_snapshot(snapshot: dict[Path, str]) -> None:
    for path, source in snapshot.items():
        assert path.read_text(encoding="utf-8") == source


def test_install_restores_both_configs_when_final_commit_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    stable = '# stable owner config\ndefault_model = "kimi-code/k3"\n'
    legacy = "# legacy owner config\ntelemetry = false\n"
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        stable_config=stable,
        legacy_config=legacy,
    )
    real_replace = _transaction.os.replace
    failed = False

    def fail_legacy_once(source: str, destination: str) -> None:
        nonlocal failed
        if os.path.abspath(destination) == str(fixture.legacy_path) and not failed:
            failed = True
            raise OSError("injected legacy config failure")
        real_replace(source, destination)

    monkeypatch.setattr(_transaction.os, "replace", fail_legacy_once)

    with pytest.raises(OSError, match="injected legacy config failure"):
        fixture.install()

    assert fixture.stable_path.read_text(encoding="utf-8") == stable
    assert fixture.legacy_path.read_text(encoding="utf-8") == legacy
    for name in RUNTIME_NAMES:
        assert not (fixture.agent_dir / name).exists()
    assert_no_transaction_files(fixture.home_dir)


def test_install_rejects_concurrent_config_change_before_runtime_staging(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    original = '# owner config\ndefault_model = "kimi-code/k3"\n'
    concurrent = "# concurrent owner change\ntelemetry = false\n"
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        stable_config=original,
        legacy_detected=False,
    )
    real_rendered_change = kimi_installation.rendered_change
    changed = False

    def mutate_before_change(rendered: object):
        nonlocal changed
        if not changed:
            changed = True
            write_text(fixture.stable_path, concurrent)
        return real_rendered_change(rendered)  # type: ignore[arg-type]

    monkeypatch.setattr(kimi_installation, "rendered_change", mutate_before_change)

    with pytest.raises(OSError, match="changed before staging"):
        fixture.install()

    assert fixture.stable_path.read_text(encoding="utf-8") == concurrent
    assert not fixture.agent_dir.exists()
    assert_no_transaction_files(fixture.home_dir)


def test_uninstall_restores_first_config_when_second_removal_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    paths = [
        *(fixture.agent_dir / name for name in RUNTIME_NAMES),
        fixture.stable_path,
        fixture.legacy_path,
    ]
    before = snapshot_files(paths)
    real_replace = _transaction.os.replace
    removal_commits = 0

    def fail_second_removal(source: str, destination: str) -> None:
        nonlocal removal_commits
        if destination.endswith(".rollback"):
            removal_commits += 1
            if removal_commits == 2:
                raise OSError("injected uninstall failure")
        real_replace(source, destination)

    monkeypatch.setattr(_transaction.os, "replace", fail_second_removal)

    with pytest.raises(OSError, match="injected uninstall failure"):
        fixture.plugin.uninstall(AGENT_ID)

    assert_snapshot(before)
    assert_no_transaction_files(fixture.home_dir)


def test_prepared_install_detects_change_before_commit_and_rolls_back_staging(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, legacy_detected=False)
    documents = read_kimi_documents()
    paths = kimi_installation.preflight_kimi_installation(
        fixture.config, documents
    )
    rendered = [
        render_kimi_document(
            document,
            [
                *remove_managed_kimi_hooks(document.hooks),
                build_kimi_hook("PreToolUse", paths.guard_path),
                build_kimi_hook("PostToolUse", paths.audit_path),
                build_kimi_hook("PostToolUseFailure", paths.audit_path),
            ],
        )
        for document in documents
    ]
    changes = kimi_installation.prepare_kimi_installation(
        fixture.config, paths, rendered
    )
    write_text(fixture.stable_path, "# changed after preparation\n")

    with pytest.raises(OSError, match="changed during installation"):
        kimi_installation.commit_kimi_installation(changes)

    for name in RUNTIME_NAMES:
        assert not (fixture.agent_dir / name).exists()
    assert fixture.stable_path.read_text(encoding="utf-8") == "# changed after preparation\n"
    assert_no_transaction_files(fixture.home_dir)
