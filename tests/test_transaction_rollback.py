from __future__ import annotations

import os
from pathlib import Path

import pytest

from elydora.plugins import _transaction
from transaction_support import (
    make_change,
    write_source,
)


def test_final_replace_exception_after_success_restores_original(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.txt"
    write_source(target, "old\n")
    real_replace = _transaction._replace_physical

    def replace_then_raise(
        source: str,
        destination: str,
        directory: _transaction.PinnedDirectory,
    ) -> None:
        real_replace(source, destination, directory)
        if os.path.abspath(destination) == os.path.abspath(str(target)):
            raise OSError("injected post-replace failure")

    monkeypatch.setattr(_transaction, "_replace_physical", replace_then_raise)

    with pytest.raises(OSError, match="injected post-replace failure"):
        _transaction.write_changes(
            [make_change(target, "old\n", "new\n")],
            "post-replace failure",
        )

    assert target.read_text(encoding="utf-8") == "old\n"
    assert list(tmp_path.glob(".*.rollback")) == []


def test_capture_exception_after_success_restores_original(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.txt"
    write_source(target, "old\n")
    real_capture = _transaction._capture_physical

    def capture_then_raise(
        source: str,
        destination: str,
        directory: _transaction.PinnedDirectory,
    ) -> None:
        real_capture(source, destination, directory)
        raise OSError("injected post-capture failure")

    monkeypatch.setattr(_transaction, "_capture_physical", capture_then_raise)

    with pytest.raises(OSError, match="injected post-capture failure"):
        _transaction.write_changes(
            [make_change(target, "old\n", "new\n")],
            "post-capture failure",
        )

    assert target.read_text(encoding="utf-8") == "old\n"
    assert list(tmp_path.glob(".*.rollback")) == []


def test_rollback_reservation_collision_preserves_victim_and_original(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.txt"
    write_source(target, "old\n")
    victim = "concurrent rollback destination\n"
    collision_path: Path | None = None

    def collide_with_rollback_destination(
        _source: str,
        destination: str,
        _directory: _transaction.PinnedDirectory,
    ) -> None:
        nonlocal collision_path
        if destination.endswith(".rollback"):
            collision_path = Path(destination)
            write_source(collision_path, victim)

    monkeypatch.setattr(
        _transaction,
        "_capture_physical",
        collide_with_rollback_destination,
    )

    with pytest.raises(OSError, match="exist"):
        _transaction.write_changes(
            [make_change(target, "old\n", "new\n")],
            "rollback destination collision",
        )

    assert collision_path is not None
    assert target.read_text(encoding="utf-8") == "old\n"
    assert collision_path.read_text(encoding="utf-8") == victim


def test_final_install_does_not_overwrite_concurrent_target(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.txt"
    write_source(target, "old\n")
    real_replace = _transaction._replace_physical
    injected = False

    def create_target_before_install(
        source: str,
        destination: str,
        directory: _transaction.PinnedDirectory,
    ) -> None:
        nonlocal injected
        if not injected and os.path.abspath(destination) == os.path.abspath(target):
            injected = True
            write_source(target, "concurrent\n")
        real_replace(source, destination, directory)

    monkeypatch.setattr(
        _transaction,
        "_replace_physical",
        create_target_before_install,
    )

    with pytest.raises(OSError, match="original content preserved"):
        _transaction.write_changes(
            [make_change(target, "old\n", "new\n")],
            "no-clobber install",
        )

    assert injected
    assert target.read_text(encoding="utf-8") == "concurrent\n"
    rollbacks = list(tmp_path.glob(".*.rollback"))
    assert len(rollbacks) == 1
    assert rollbacks[0].read_text(encoding="utf-8") == "old\n"


def test_restore_does_not_overwrite_concurrent_target(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.txt"
    second = tmp_path / "second.txt"
    write_source(target, "old\n")
    write_source(second, "second-old\n")
    real_replace = _transaction._replace_physical
    real_restore = _transaction._restore_physical
    injected = False

    def fail_second_commit(
        source: str,
        destination: str,
        directory: _transaction.PinnedDirectory,
    ) -> None:
        if os.path.abspath(destination) == os.path.abspath(second):
            raise OSError("injected second failure")
        real_replace(source, destination, directory)

    def create_target_before_restore(
        source: str,
        destination: str,
        directory: _transaction.PinnedDirectory,
    ) -> None:
        nonlocal injected
        if not injected and os.path.abspath(destination) == os.path.abspath(target):
            injected = True
            write_source(target, "concurrent recovery\n")
        real_restore(source, destination, directory)

    monkeypatch.setattr(_transaction, "_replace_physical", fail_second_commit)
    monkeypatch.setattr(
        _transaction,
        "_restore_physical",
        create_target_before_restore,
    )

    with pytest.raises(OSError, match="original content preserved"):
        _transaction.write_changes(
            [
                make_change(target, "old\n", "new\n"),
                make_change(second, "second-old\n", "second-new\n"),
            ],
            "no-clobber restoration",
        )

    assert injected
    assert target.read_text(encoding="utf-8") == "concurrent recovery\n"
    rollbacks = list(tmp_path.glob(".*.rollback"))
    assert len(rollbacks) == 1
    assert rollbacks[0].read_text(encoding="utf-8") == "old\n"
    assert Path(_transaction.active_journal_path()).is_file()
    _transaction.clear_journal()


def test_restore_source_replacement_reports_existing_preserved_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.txt"
    second = tmp_path / "second.txt"
    displaced = tmp_path / "displaced-original.txt"
    write_source(target, "old\n")
    write_source(second, "second-old\n")
    real_replace = _transaction._replace_physical
    real_restore = _transaction._restore_physical
    rollback_path: Path | None = None

    def fail_second_commit(
        source: str,
        destination: str,
        directory: _transaction.PinnedDirectory,
    ) -> None:
        if os.path.abspath(destination) == os.path.abspath(second):
            raise OSError("injected second failure")
        real_replace(source, destination, directory)

    def replace_restore_source(
        source: str,
        destination: str,
        directory: _transaction.PinnedDirectory,
    ) -> None:
        nonlocal rollback_path
        if (
            rollback_path is None
            and source.endswith(".rollback")
            and os.path.abspath(destination) == os.path.abspath(target)
        ):
            rollback_path = Path(source)
            rollback_path.rename(displaced)
            write_source(rollback_path, "concurrent recovery source\n")
        real_restore(source, destination, directory)

    monkeypatch.setattr(_transaction, "_replace_physical", fail_second_commit)
    monkeypatch.setattr(_transaction, "_restore_physical", replace_restore_source)

    with pytest.raises(OSError, match="recovery source changed") as raised:
        _transaction.write_changes(
            [
                make_change(target, "old\n", "new\n"),
                make_change(second, "second-old\n", "second-new\n"),
            ],
            "restore source replacement",
        )

    assert rollback_path is not None
    assert f"concurrent data preserved at {rollback_path}" in str(raised.value)
    assert rollback_path.read_text(encoding="utf-8") == "concurrent recovery source\n"
    assert displaced.read_text(encoding="utf-8") == "old\n"
    assert target.read_text(encoding="utf-8") == "new\n"
    assert second.read_text(encoding="utf-8") == "second-old\n"
    assert Path(_transaction.active_journal_path()).is_file()
    _transaction.clear_journal()


def test_creation_rollback_captures_and_preserves_concurrent_replacement(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    created = tmp_path / "created.txt"
    second = tmp_path / "second.txt"
    write_source(second, "second-old\n")
    real_replace = _transaction._replace_physical
    real_capture = _transaction._capture_physical
    injected = False

    def fail_second_commit(
        source: str,
        destination: str,
        directory: _transaction.PinnedDirectory,
    ) -> None:
        if os.path.abspath(destination) == os.path.abspath(second):
            raise OSError("injected second failure")
        real_replace(source, destination, directory)

    def replace_created_before_recovery_capture(
        source: str,
        destination: str,
        directory: _transaction.PinnedDirectory,
    ) -> None:
        nonlocal injected
        if (
            not injected
            and os.path.abspath(source) == os.path.abspath(created)
            and destination.endswith(".recovery")
        ):
            injected = True
            write_source(created, "concurrent replacement\n")
        real_capture(source, destination, directory)

    monkeypatch.setattr(_transaction, "_replace_physical", fail_second_commit)
    monkeypatch.setattr(
        _transaction,
        "_capture_physical",
        replace_created_before_recovery_capture,
    )

    with pytest.raises(OSError, match="changed at recovery boundary"):
        _transaction.write_changes(
            [
                make_change(created, None, "generated\n"),
                make_change(second, "second-old\n", "second-new\n"),
            ],
            "creation recovery capture",
        )

    assert injected
    assert created.read_text(encoding="utf-8") == "concurrent replacement\n"
    assert Path(_transaction.active_journal_path()).is_file()
    _transaction.clear_journal()


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode contract")
def test_mode_repair_uses_private_rollback_and_restores_original_mode(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    secret = tmp_path / "private.key"
    second = tmp_path / "config.json"
    write_source(secret, "secret\n")
    write_source(second, "old\n")
    secret.chmod(0o644)
    real_replace = _transaction._replace_physical
    rollback_modes: list[int] = []

    def inspect_then_fail_second(
        source: str,
        destination: str,
        directory: _transaction.PinnedDirectory,
    ) -> None:
        if os.path.abspath(destination) == os.path.abspath(str(secret)):
            rollback = next(tmp_path.glob(".private.key.*.rollback"))
            rollback_modes.append(rollback.stat().st_mode & 0o777)
        if os.path.abspath(destination) == os.path.abspath(str(second)):
            raise OSError("injected second commit failure")
        real_replace(source, destination, directory)

    monkeypatch.setattr(_transaction, "_replace_physical", inspect_then_fail_second)

    with pytest.raises(OSError, match="injected second commit failure"):
        _transaction.write_changes(
            [
                make_change(secret, "secret\n", "secret\n", enforce_mode=True),
                make_change(second, "old\n", "new\n"),
            ],
            "mode repair",
        )

    assert rollback_modes
    assert set(rollback_modes) == {0o600}
    assert secret.read_text(encoding="utf-8") == "secret\n"
    assert secret.stat().st_mode & 0o777 == 0o644
    assert second.read_text(encoding="utf-8") == "old\n"
    assert list(tmp_path.glob(".*.rollback")) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode contract")
def test_deletion_uses_private_rollback_and_restores_original_mode(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    removed = tmp_path / "removed.txt"
    second = tmp_path / "second.txt"
    write_source(removed, "remove me\n")
    write_source(second, "old\n")
    removed.chmod(0o644)
    real_replace = _transaction._replace_physical
    rollback_modes: list[int] = []

    def inspect_then_fail_second(
        source: str,
        destination: str,
        directory: _transaction.PinnedDirectory,
    ) -> None:
        if os.path.abspath(destination) == os.path.abspath(str(second)):
            rollback = next(tmp_path.glob(".removed.txt.*.rollback"))
            rollback_modes.append(rollback.stat().st_mode & 0o777)
            raise OSError("injected second commit failure")
        real_replace(source, destination, directory)

    monkeypatch.setattr(_transaction, "_replace_physical", inspect_then_fail_second)

    with pytest.raises(OSError, match="injected second commit failure"):
        _transaction.write_changes(
            [
                make_change(removed, "remove me\n", None),
                make_change(second, "old\n", "new\n"),
            ],
            "deletion rollback mode",
        )

    assert rollback_modes == [0o600]
    assert removed.read_text(encoding="utf-8") == "remove me\n"
    assert removed.stat().st_mode & 0o777 == 0o644
    assert second.read_text(encoding="utf-8") == "old\n"
    assert list(tmp_path.glob(".*.rollback")) == []
