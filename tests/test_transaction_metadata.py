from __future__ import annotations

import os
from pathlib import Path
from types import TracebackType
from typing import BinaryIO, Optional, Type

import pytest

from elydora.plugins import _managed_files
from elydora.plugins._pinned_directory import PinnedDirectory
from elydora.plugins._private_artifact import QuarantinedFile


class _MutatingReader:
    def __init__(self, file: BinaryIO, target: Path, replacement: bytes) -> None:
        self._file = file
        self._target = target
        self._replacement = replacement

    def __enter__(self) -> "_MutatingReader":
        self._file.__enter__()
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> Optional[bool]:
        return self._file.__exit__(exc_type, exc_value, traceback)

    def fileno(self) -> int:
        return self._file.fileno()

    def read(self, size: int = -1) -> bytes:
        value = self._file.read(size)
        self._target.write_bytes(self._replacement)
        return value


def _mutate_during_read(
    monkeypatch: pytest.MonkeyPatch,
    target: Path,
    replacement: bytes,
) -> None:
    real_fdopen = os.fdopen

    def mutating_fdopen(
        descriptor: int,
        mode: str = "r",
        *args: object,
        **kwargs: object,
    ) -> _MutatingReader:
        file = real_fdopen(descriptor, mode, *args, **kwargs)
        return _MutatingReader(file, target, replacement)  # type: ignore[arg-type]

    monkeypatch.setattr(_managed_files.os, "fdopen", mutating_fdopen)


def test_read_physical_file_rejects_in_place_change_during_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "managed.json"
    target.write_bytes(b"original")
    _mutate_during_read(monkeypatch, target, b"replaced")

    with pytest.raises(OSError, match="changed while reading"):
        _managed_files.read_physical_file(str(target), "managed file")


def test_pinned_read_rejects_in_place_change_during_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "managed.json"
    target.write_bytes(b"original")
    directory = PinnedDirectory.open(str(tmp_path), "managed directory")
    try:
        _mutate_during_read(monkeypatch, target, b"replaced")
        with pytest.raises(OSError, match="changed while reading"):
            directory.read_file(target.name, "managed file", 1024)
    finally:
        directory.close()


def test_private_capture_restores_target_when_parent_boundary_changes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "managed.json"
    target.write_text("original", encoding="utf-8")
    directory = PinnedDirectory.open(str(tmp_path), "managed directory")
    real_assert = directory.assert_path_stable
    calls = 0

    def fail_after_capture(operation: str = "transaction") -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected parent boundary change")
        real_assert(operation)

    monkeypatch.setattr(directory, "assert_path_stable", fail_after_capture)
    try:
        with pytest.raises(OSError, match="injected parent boundary change"):
            QuarantinedFile.capture(directory, str(target), "managed file")
        assert target.read_text(encoding="utf-8") == "original"
        assert not list(tmp_path.glob("*.elydora-quarantine"))
    finally:
        directory.close()
