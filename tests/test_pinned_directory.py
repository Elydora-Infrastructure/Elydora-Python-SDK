from __future__ import annotations

import os
from pathlib import Path
import stat

import pytest

from elydora.plugins import _private_artifact
from elydora.plugins import _pinned_directory
from elydora.plugins._managed_files import DirectorySnapshot
from elydora.plugins._pinned_directory import PinnedDirectory


def test_darwin_private_directory_removal_uses_stdlib_dir_fd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, int | None]] = []

    def record_rmdir(path: str, *, dir_fd: int | None = None) -> None:
        calls.append((path, dir_fd))

    monkeypatch.setattr(_private_artifact.os, "rmdir", record_rmdir)
    monkeypatch.setattr(_private_artifact, "_RMDIR_SUPPORTS_DIR_FD", True)

    _private_artifact._remove_posix_private_directory(41, "private-container")

    assert calls == [("private-container", 41)]


def test_assert_path_stable_detects_visible_identity_change(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = tmp_path / "managed"
    directory.mkdir()
    pinned = PinnedDirectory.open(str(directory), "managed directory")
    changed = DirectorySnapshot(
        pinned.snapshot.device + 1,
        pinned.snapshot.inode,
    )
    monkeypatch.setattr(
        _pinned_directory,
        "read_physical_directory",
        lambda _path, _label: changed,
    )

    try:
        with pytest.raises(OSError, match="changed during test operation"):
            pinned.assert_path_stable("test operation")
    finally:
        pinned.close()


def test_closed_pin_rejects_file_operations(tmp_path: Path) -> None:
    directory = tmp_path / "managed"
    directory.mkdir()
    pinned = PinnedDirectory.open(str(directory), "managed directory")
    pinned.close()

    with pytest.raises(OSError, match="is closed"):
        pinned.stat_file("state.json")


@pytest.mark.skipif(os.name != "nt", reason="Windows handle contract")
def test_windows_pin_blocks_directory_swap_and_allows_child_replace(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "managed"
    directory.mkdir()
    (directory / "source").write_text("new", encoding="utf-8")
    (directory / "target").write_text("old", encoding="utf-8")
    moved = tmp_path / "moved"
    pinned = PinnedDirectory.open(str(directory), "managed directory")

    try:
        pinned.replace_file("source", "target")
        assert (directory / "target").read_text(encoding="utf-8") == "new"
        with pytest.raises(OSError):
            directory.rename(moved)
        pinned.assert_path_stable("replace test")
    finally:
        pinned.close()

    directory.rename(moved)
    moved.rename(directory)


@pytest.mark.skipif(os.name != "nt", reason="Windows handle contract")
def test_windows_pin_compares_volume_and_inode(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = tmp_path / "managed"
    directory.mkdir()
    real_open = _pinned_directory._open_windows_directory

    def open_with_changed_volume(
        path: str, label: str
    ) -> tuple[int, DirectorySnapshot]:
        descriptor, snapshot = real_open(path, label)
        return descriptor, DirectorySnapshot(
            snapshot.device + 1,
            snapshot.inode,
        )

    monkeypatch.setattr(
        _pinned_directory,
        "_open_windows_directory",
        open_with_changed_volume,
    )

    with pytest.raises(OSError, match="changed while pinning"):
        PinnedDirectory.open(str(directory), "managed directory")

    moved = tmp_path / "moved"
    directory.rename(moved)
    moved.rename(directory)


@pytest.mark.skipif(os.name != "nt", reason="Windows handle contract")
def test_windows_descriptor_chmod_fallback_changes_open_file_mode(
    tmp_path: Path,
) -> None:
    target = tmp_path / "secret"
    target.write_text("secret", encoding="utf-8")
    descriptor = os.open(
        target,
        os.O_RDWR | getattr(os, "O_BINARY", 0),
    )
    try:
        _pinned_directory._chmod_windows_descriptor(descriptor, stat.S_IREAD)
        assert not os.fstat(descriptor).st_mode & stat.S_IWRITE
        _pinned_directory._chmod_windows_descriptor(
            descriptor,
            stat.S_IREAD | stat.S_IWRITE,
        )
        assert os.fstat(descriptor).st_mode & stat.S_IWRITE
    finally:
        os.close(descriptor)


@pytest.mark.skipif(os.name != "nt", reason="Windows handle contract")
def test_windows_chmod_file_uses_the_open_descriptor(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = tmp_path / "managed"
    directory.mkdir()
    target = directory / "secret"
    target.write_text("secret", encoding="utf-8")
    pinned = PinnedDirectory.open(str(directory), "managed directory")
    snapshot = pinned.read_file("secret", "secret", 1024)
    assert snapshot is not None
    restore_descriptor = os.open(
        target,
        os.O_RDWR | getattr(os, "O_BINARY", 0),
    )

    def reject_path_chmod(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("path chmod was called")

    monkeypatch.setattr(_pinned_directory.os, "chmod", reject_path_chmod)
    try:
        pinned.chmod_file(
            "secret",
            stat.S_IREAD,
            (snapshot.device, snapshot.inode),
        )
        assert not target.stat().st_mode & stat.S_IWRITE
        _pinned_directory.chmod_open_file(
            restore_descriptor,
            stat.S_IREAD | stat.S_IWRITE,
        )
    finally:
        os.close(restore_descriptor)
        pinned.close()
