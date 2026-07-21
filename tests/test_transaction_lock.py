from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess  # nosec B404
import sys
import time

import pytest

from elydora.plugins import _transaction_lock


if os.name == "nt":
    from elydora.plugins._windows_security import verify_private_path


def _use_isolated_state(
    monkeypatch: pytest.MonkeyPatch,
    root: Path,
) -> None:
    monkeypatch.setenv("HOME", str(root))
    monkeypatch.setenv("USERPROFILE", str(root))


def test_transaction_state_directory_has_owner_boundary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _use_isolated_state(monkeypatch, tmp_path)

    state = Path(_transaction_lock.transaction_state_directory())

    assert state.is_dir()
    if os.name == "nt":
        verify_private_path(str(state), directory=True)
    else:
        metadata = state.stat()
        assert metadata.st_uid == getattr(os, "geteuid")()
        assert stat.S_IMODE(metadata.st_mode) == 0o700


@pytest.mark.skipif(os.name != "posix", reason="POSIX owner contract")
def test_transaction_state_directory_rejects_foreign_owner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _use_isolated_state(monkeypatch, tmp_path)
    state = Path(_transaction_lock.transaction_state_directory())
    owner = state.stat().st_uid
    monkeypatch.setattr(os, "geteuid", lambda: owner + 1)

    with pytest.raises(PermissionError, match="owned by the current user"):
        _transaction_lock.transaction_state_directory()


@pytest.mark.skipif(os.name != "posix", reason="POSIX owner contract")
def test_posix_lock_rejects_foreign_owner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lock_path = tmp_path / "transaction.lock"
    lock_path.write_bytes(b"")
    owner = lock_path.stat().st_uid
    monkeypatch.setattr(
        _transaction_lock,
        "transaction_state_directory",
        lambda: str(tmp_path),
    )
    monkeypatch.setattr(os, "geteuid", lambda: owner + 1)

    with pytest.raises(PermissionError, match="owned by the current user"):
        _transaction_lock._PosixLock().__enter__()


def test_transaction_lock_rejects_reparse_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _use_isolated_state(monkeypatch, tmp_path)
    state = Path(_transaction_lock.transaction_state_directory())
    target = tmp_path / "target.lock"
    target.write_bytes(b"")
    lock_path = state / "transaction.lock"
    try:
        lock_path.symlink_to(target)
    except OSError as error:
        pytest.skip(f"Symbolic links unavailable: {error}")

    with pytest.raises(OSError, match="physical file"):
        with _transaction_lock.serialized_transactions():
            pass


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL contract")
def test_windows_lock_file_has_owner_only_protected_dacl(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _use_isolated_state(monkeypatch, tmp_path)
    state = Path(_transaction_lock.transaction_state_directory())

    with _transaction_lock.serialized_transactions():
        lock_path = state / "transaction.lock"
        assert lock_path.is_file()
        verify_private_path(str(lock_path), directory=False)


def test_transaction_lock_serializes_independent_processes(tmp_path: Path) -> None:
    state_root = tmp_path / "state-root"
    state_root.mkdir()
    entered = tmp_path / "entered"
    release = tmp_path / "release"
    second_entered = tmp_path / "second-entered"
    script = """
import pathlib
import sys
import time
from elydora.plugins._transaction_lock import serialized_transactions

entered, release = map(pathlib.Path, sys.argv[1:3])
with serialized_transactions():
    entered.write_text("entered", encoding="utf-8")
    if len(sys.argv) == 4:
        deadline = time.monotonic() + 10
        while not release.exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("release gate timed out")
            time.sleep(0.01)
"""
    environment = os.environ.copy()
    environment["HOME"] = str(state_root)
    environment["USERPROFILE"] = str(state_root)
    repository = Path(__file__).resolve().parents[1]
    first = subprocess.Popen(  # nosec B603
        [sys.executable, "-c", script, str(entered), str(release), "wait"],
        cwd=repository,
        env=environment,
    )
    second: subprocess.Popen[bytes] | None = None
    try:
        deadline = time.monotonic() + 10
        while not entered.exists() and first.poll() is None:
            if time.monotonic() >= deadline:
                raise TimeoutError("first process did not acquire the lock")
            time.sleep(0.01)
        assert first.poll() is None

        second = subprocess.Popen(  # nosec B603
            [sys.executable, "-c", script, str(second_entered), str(release)],
            cwd=repository,
            env=environment,
        )
        time.sleep(0.25)
        assert second.poll() is None
        assert not second_entered.exists()

        release.write_text("release", encoding="utf-8")
        assert first.wait(timeout=10) == 0
        assert second.wait(timeout=10) == 0
        assert second_entered.read_text(encoding="utf-8") == "entered"
    finally:
        if first.poll() is None:
            first.kill()
            first.wait()
        if second is not None and second.poll() is None:
            second.kill()
            second.wait()
