from __future__ import annotations

from pathlib import Path

import pytest

from elydora.plugins import _transaction
from elydora.plugins._pinned_directory import PinnedDirectory
from elydora.plugins._transaction_journal import active_journal_path


def _change(path: Path, original: str, next_source: str) -> _transaction.FileChange:
    change = _transaction.source_change(
        str(path),
        path.name,
        original,
        next_source,
        0o600,
    )
    assert change is not None
    return change


def _no_op_file_boundary(
    source: str,
    destination: str,
    directory: PinnedDirectory,
) -> None:
    del source, destination, directory


def test_durable_commit_marker_keeps_change_after_post_commit_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "managed.json"
    target.write_bytes(b"old\n")

    def fail_after_marker() -> None:
        raise OSError("injected post-commit failure")

    monkeypatch.setattr(_transaction, "_after_journal_commit", fail_after_marker)

    with pytest.raises(OSError, match="committed before post-commit failure"):
        _transaction.write_changes(
            [_change(target, "old\n", "new\n")],
            "post-commit boundary",
        )

    assert target.read_text(encoding="utf-8") == "new\n"
    assert not Path(active_journal_path()).exists()
    assert not list(tmp_path.glob(".*.rollback"))


def test_failed_in_process_recovery_preserves_journal_for_restart(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_bytes(b"first-old\n")
    second.write_bytes(b"second-old\n")

    def fail_second_commit(
        source: str,
        destination: str,
        directory: PinnedDirectory,
    ) -> None:
        del source, directory
        if Path(destination) == second:
            raise OSError("injected second commit failure")

    def fail_first_restore(
        source: str,
        destination: str,
        directory: PinnedDirectory,
    ) -> None:
        del source, destination, directory
        raise OSError("injected restoration failure")

    monkeypatch.setattr(_transaction, "_replace_physical", fail_second_commit)
    monkeypatch.setattr(_transaction, "_restore_physical", fail_first_restore)

    with pytest.raises(OSError, match="recovery journal preserved"):
        _transaction.write_changes(
            [
                _change(first, "first-old\n", "first-new\n"),
                _change(second, "second-old\n", "second-new\n"),
            ],
            "recoverable in-process failure",
        )

    assert Path(active_journal_path()).is_file()
    assert first.read_text(encoding="utf-8") == "first-new\n"
    assert second.read_text(encoding="utf-8") == "second-old\n"

    monkeypatch.setattr(_transaction, "_restore_physical", _no_op_file_boundary)
    _transaction.recover_pending_transactions()

    assert first.read_text(encoding="utf-8") == "first-old\n"
    assert second.read_text(encoding="utf-8") == "second-old\n"
    assert not Path(active_journal_path()).exists()


def test_committed_cleanup_failure_leaves_restart_record(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "managed.json"
    target.write_bytes(b"old\n")
    real_cleanup = _transaction.cleanup_staged
    calls = 0

    def fail_first_cleanup(staged: _transaction.StagedChange) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("injected committed cleanup failure")
        real_cleanup(staged)

    monkeypatch.setattr(_transaction, "cleanup_staged", fail_first_cleanup)

    with pytest.raises(OSError, match="cleanup pending"):
        _transaction.write_changes(
            [_change(target, "old\n", "new\n")],
            "committed cleanup failure",
        )

    assert target.read_text(encoding="utf-8") == "new\n"
    assert Path(active_journal_path()).is_file()

    monkeypatch.setattr(_transaction, "cleanup_staged", real_cleanup)
    _transaction.recover_pending_transactions()

    assert target.read_text(encoding="utf-8") == "new\n"
    assert not Path(active_journal_path()).exists()
    assert not list(tmp_path.glob(".*.rollback"))
