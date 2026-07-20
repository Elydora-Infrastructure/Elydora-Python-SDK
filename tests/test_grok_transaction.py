from __future__ import annotations

import os
from pathlib import Path

import pytest

from elydora.plugins import _transaction, grok_installation
from elydora.plugins.grok_contract import (
    build_grok_group,
    remove_managed_grok_hooks,
    render_grok_document,
)
from elydora.plugins.grok_io import read_grok_document
from elydora.utils import base64url_encode
from grok_support import (
    AGENT_ID,
    GrokFixture,
    assert_no_transaction_files,
    prepare_fixture,
    write_text,
)


RUNTIME_NAMES = ("guard.py", "config.json", "private.key", "hook.py")


def prepare_installation(fixture: GrokFixture):
    document = read_grok_document()
    config = fixture.config
    paths = grok_installation.preflight_grok_installation(config, document)
    cleaned = remove_managed_grok_hooks(document.hooks)
    hooks = {
        **cleaned,
        "PreToolUse": [
            *cleaned.get("PreToolUse", []),
            build_grok_group(paths.guard_path),
        ],
        "PostToolUse": [
            *cleaned.get("PostToolUse", []),
            build_grok_group(paths.audit_path),
        ],
        "PostToolUseFailure": [
            *cleaned.get("PostToolUseFailure", []),
            build_grok_group(paths.audit_path),
        ],
    }
    rendered = render_grok_document(document, hooks)
    return grok_installation.prepare_grok_installation(
        config, paths, rendered
    )


def snapshot_files(paths: list[Path]) -> dict[Path, str]:
    return {path: path.read_text(encoding="utf-8") for path in paths}


def assert_snapshot(snapshot: dict[Path, str]) -> None:
    for path, source in snapshot.items():
        assert path.read_text(encoding="utf-8") == source


def preserved_rollback(directory: Path, basename: str) -> Path:
    matches = list(directory.glob(f".{basename}.*.rollback"))
    assert len(matches) == 1, [path.name for path in directory.iterdir()]
    return matches[0]


def test_install_restores_config_and_four_runtimes_when_final_commit_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    original = '{"owner":"user"}\n'
    fixture = prepare_fixture(
        monkeypatch, tmp_path, existing_config=original
    )
    real_replace = _transaction.os.replace
    failed = False

    def fail_config_once(source: str, destination: str) -> None:
        nonlocal failed
        if os.path.abspath(destination) == str(fixture.config_path) and not failed:
            failed = True
            raise OSError("injected Grok config failure")
        real_replace(source, destination)

    monkeypatch.setattr(_transaction.os, "replace", fail_config_once)

    with pytest.raises(OSError, match="injected Grok config failure"):
        fixture.install()

    assert fixture.config_path.read_text(encoding="utf-8") == original
    for name in RUNTIME_NAMES:
        assert not (fixture.agent_dir / name).exists()
    assert_no_transaction_files(fixture.home_dir)


def test_install_rejects_concurrent_config_change_and_restores_runtimes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        existing_config={"owner": "user"},
    )
    changes = prepare_installation(fixture)
    concurrent = '{"owner":"concurrent"}\n'
    fixture.config_path.write_text(concurrent, encoding="utf-8")

    with pytest.raises(OSError, match="changed during installation"):
        grok_installation.commit_grok_installation(changes)

    assert fixture.config_path.read_text(encoding="utf-8") == concurrent
    for name in RUNTIME_NAMES:
        assert not (fixture.agent_dir / name).exists()
    assert_no_transaction_files(fixture.home_dir)


def test_uninstall_preserves_config_when_commit_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        existing_config={"owner": "user"},
    )
    fixture.install()
    before = fixture.config_path.read_text(encoding="utf-8")
    document = read_grok_document()
    rendered = render_grok_document(
        document,
        remove_managed_grok_hooks(document.hooks, AGENT_ID),
    )
    changes = grok_installation.prepare_grok_uninstall(rendered)

    def fail_replace(_source: str, _destination: str) -> None:
        raise OSError("injected Grok uninstall failure")

    monkeypatch.setattr(_transaction.os, "replace", fail_replace)

    with pytest.raises(OSError, match="injected Grok uninstall failure"):
        grok_installation.commit_grok_uninstall(changes)

    assert fixture.config_path.read_text(encoding="utf-8") == before
    assert_no_transaction_files(fixture.home_dir)


def test_recovery_preserves_original_after_committed_file_changes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    original = fixture.runtime_config_path.read_text(encoding="utf-8")
    fixture.config["org_id"] = "org-updated"
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

    monkeypatch.setattr(
        _transaction.os, "replace", change_first_then_fail
    )

    with pytest.raises(OSError, match="original content preserved at"):
        grok_installation.commit_grok_installation(changes)

    assert fixture.runtime_config_path.read_text(encoding="utf-8") == (
        "external change\n"
    )
    rollback = preserved_rollback(fixture.agent_dir, "config.json")
    assert rollback.read_text(encoding="utf-8") == original


def test_recovery_preserves_original_after_restore_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    original = fixture.runtime_config_path.read_text(encoding="utf-8")
    fixture.config["org_id"] = "org-updated"
    fixture.config["private_key"] = base64url_encode(
        bytes(range(31, -1, -1))
    )
    changes = prepare_installation(fixture)
    real_replace = _transaction.os.replace
    commits = 0

    def fail_commit_and_restore(source: str, destination: str) -> None:
        nonlocal commits
        if source.endswith(".rollback"):
            raise OSError("injected rollback failure")
        commits += 1
        if commits == 2:
            raise OSError("injected later commit failure")
        real_replace(source, destination)

    monkeypatch.setattr(
        _transaction.os, "replace", fail_commit_and_restore
    )

    with pytest.raises(OSError, match="original content preserved at"):
        grok_installation.commit_grok_installation(changes)

    rollback = preserved_rollback(fixture.agent_dir, "config.json")
    assert rollback.read_text(encoding="utf-8") == original


def test_prepared_install_detects_change_before_commit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        existing_config={"owner": "user"},
    )
    changes = prepare_installation(fixture)
    concurrent = '{"owner":"concurrent-before-stage"}\n'
    fixture.config_path.write_text(concurrent, encoding="utf-8")

    with pytest.raises(OSError, match="changed during installation"):
        grok_installation.commit_grok_installation(changes)

    assert fixture.config_path.read_text(encoding="utf-8") == concurrent
    assert_no_transaction_files(fixture.home_dir)


def test_transaction_rejects_oversized_source_before_staging(
    tmp_path: Path,
) -> None:
    target = tmp_path / "managed" / "config.json"

    with pytest.raises(ValueError, match="exceeds 4 bytes"):
        _transaction.file_change(
            str(target),
            "managed test source",
            "five!",
            0o600,
            maximum_bytes=4,
        )

    assert not target.parent.exists()
