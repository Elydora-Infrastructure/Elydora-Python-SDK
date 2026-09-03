from __future__ import annotations

import os
from pathlib import Path

import pytest

from elydora.plugins import _transaction, _transaction_staging
from elydora.plugins._managed_files import read_physical_directory
from transaction_support import (
    make_change,
    swap_directory,
)


@pytest.mark.skipif(os.name == "nt", reason="Windows handle blocks directory rename")
def test_staging_directory_swap_never_writes_secret_to_redirected_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    parent = tmp_path / "runtime"
    backup = tmp_path / "runtime-original"
    redirected = tmp_path / "runtime-redirected"
    parent.mkdir()
    redirected.mkdir()
    target = parent / "private.key"
    real_write = _transaction_staging.write_staged
    swapped = False

    def swap_then_stage(*args: object, **kwargs: object):
        nonlocal swapped
        if not swapped:
            swapped = True
            swap_directory(parent, backup, redirected)
        return real_write(*args, **kwargs)

    monkeypatch.setattr(_transaction_staging, "write_staged", swap_then_stage)

    with pytest.raises(OSError, match="changed during transaction"):
        _transaction.write_changes(
            [make_change(target, None, "secret\n")],
            "staging swap",
        )

    assert not (parent / "private.key").exists()
    assert not (backup / "private.key").exists()
    assert list(parent.iterdir()) == []
    assert list(backup.iterdir()) == []


@pytest.mark.skipif(os.name == "nt", reason="Windows handle blocks directory rename")
def test_commit_directory_swap_rolls_back_inside_pinned_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    parent = tmp_path / "runtime"
    backup = tmp_path / "runtime-original"
    redirected = tmp_path / "runtime-redirected"
    parent.mkdir()
    redirected.mkdir()
    target = parent / "private.key"
    real_replace = _transaction._replace_physical
    swapped = False

    def swap_then_replace(
        source: str,
        destination: str,
        directory: _transaction.PinnedDirectory,
    ) -> None:
        nonlocal swapped
        if not swapped:
            swapped = True
            swap_directory(parent, backup, redirected)
        real_replace(source, destination, directory)

    monkeypatch.setattr(_transaction, "_replace_physical", swap_then_replace)

    with pytest.raises(OSError, match="changed during transaction"):
        _transaction.write_changes(
            [make_change(target, None, "secret\n")],
            "commit swap",
        )

    assert not (parent / "private.key").exists()
    assert not (backup / "private.key").exists()
    assert list(parent.iterdir()) == []
    assert list(backup.iterdir()) == []


def test_failed_transaction_removes_only_created_empty_directories(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kiro = tmp_path / ".kiro"
    hooks = kiro / "hooks"
    hooks.mkdir(parents=True)
    kiro_snapshot = read_physical_directory(str(kiro), "Kiro directory")
    hooks_snapshot = read_physical_directory(str(hooks), "hooks directory")
    target = hooks / "elydora-audit.json"

    def fail_replace(
        _source: str,
        _destination: str,
        _directory: _transaction.PinnedDirectory,
    ) -> None:
        raise OSError("injected commit failure")

    monkeypatch.setattr(_transaction, "_replace_physical", fail_replace)

    with pytest.raises(OSError, match="injected commit failure"):
        _transaction.write_changes(
            [make_change(target, None, "{}\n")],
            "created directory recovery",
            directory_preconditions=[
                _transaction.DirectoryPrecondition(
                    str(kiro), "Kiro directory", kiro_snapshot, created=True
                ),
                _transaction.DirectoryPrecondition(
                    str(hooks), "hooks directory", hooks_snapshot, created=True
                ),
            ],
        )

    assert not hooks.exists()
    assert not kiro.exists()


def test_created_directory_recovery_keeps_parent_and_child_pinned(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    kiro = tmp_path / ".kiro"
    hooks = kiro / "hooks"
    hooks.mkdir(parents=True)
    kiro_snapshot = read_physical_directory(str(kiro), "Kiro directory")
    hooks_snapshot = read_physical_directory(str(hooks), "hooks directory")
    target = hooks / "elydora-audit.json"
    observed: list[tuple[Path, Path]] = []
    real_remove = _transaction_staging.remove_pinned_empty_directory

    def observe_pins(
        parent: object,
        child: object,
        *,
        require_empty: bool = True,
    ) -> None:
        assert isinstance(parent, _transaction.PinnedDirectory)
        assert isinstance(child, _transaction.PinnedDirectory)
        assert parent.descriptor is not None
        assert child.descriptor is not None
        assert os.fstat(child.descriptor).st_ino == child.snapshot.inode
        observed.append((Path(parent.path), Path(child.path)))
        real_remove(parent, child, require_empty=require_empty)

    def fail_replace(
        _source: str,
        _destination: str,
        _directory: _transaction.PinnedDirectory,
    ) -> None:
        raise OSError("injected pinned cleanup failure")

    monkeypatch.setattr(
        _transaction_staging,
        "remove_pinned_empty_directory",
        observe_pins,
    )
    monkeypatch.setattr(_transaction, "_replace_physical", fail_replace)

    with pytest.raises(OSError, match="injected pinned cleanup failure"):
        _transaction.write_changes(
            [make_change(target, None, "{}\n")],
            "pinned directory recovery",
            directory_preconditions=[
                _transaction.DirectoryPrecondition(
                    str(kiro), "Kiro directory", kiro_snapshot, created=True
                ),
                _transaction.DirectoryPrecondition(
                    str(hooks), "hooks directory", hooks_snapshot, created=True
                ),
            ],
        )

    expected = [(kiro, hooks), (tmp_path, kiro)]
    assert observed == expected
    assert not kiro.exists()


@pytest.mark.skipif(os.name == "nt", reason="Windows handle blocks directory rename")
def test_created_directory_recovery_preserves_swapped_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    created = tmp_path / "created"
    created.mkdir()
    created_snapshot = read_physical_directory(str(created), "created directory")
    target = created / "managed.json"
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    marker = replacement / "user-owned"
    marker.write_text("preserve", encoding="utf-8")
    original = tmp_path / "created-original"
    real_remove = _transaction_staging.remove_pinned_empty_directory

    def swap_before_removal(
        parent: _transaction.PinnedDirectory,
        child: _transaction.PinnedDirectory,
        *,
        require_empty: bool = True,
    ) -> None:
        created.rename(original)
        replacement.rename(created)
        real_remove(parent, child, require_empty=require_empty)

    def fail_replace(
        _source: str,
        _destination: str,
        _directory: _transaction.PinnedDirectory,
    ) -> None:
        raise OSError("injected swap cleanup failure")

    monkeypatch.setattr(
        _transaction_staging,
        "remove_pinned_empty_directory",
        swap_before_removal,
    )
    monkeypatch.setattr(_transaction, "_replace_physical", fail_replace)

    with pytest.raises(OSError, match="recovery failed"):
        _transaction.write_changes(
            [make_change(target, None, "{}\n")],
            "swapped directory recovery",
            directory_preconditions=[
                _transaction.DirectoryPrecondition(
                    str(created),
                    "created directory",
                    created_snapshot,
                    created=True,
                )
            ],
        )

    assert (created / marker.name).read_text(encoding="utf-8") == "preserve"
    assert original.is_dir()
    assert Path(_transaction.active_journal_path()).is_file()
    _transaction.clear_journal()
