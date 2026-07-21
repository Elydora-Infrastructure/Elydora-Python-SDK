from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

import pytest

from elydora.plugins import _transaction, _transaction_staging
from elydora.plugins._managed_files import read_physical_directory, read_physical_file


def _write(path: Path, source: str) -> None:
    path.write_bytes(source.encode("utf-8"))


def _change(
    path: Path,
    original: str | None,
    next_source: str | None,
    mode: int = 0o600,
    enforce_mode: bool = False,
) -> _transaction.FileChange:
    change = _transaction.source_change(
        str(path),
        path.name,
        original,
        next_source,
        mode,
        enforce_mode=enforce_mode,
    )
    assert change is not None
    return change


def test_post_replace_precondition_failure_restores_original_target(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.txt"
    provider = tmp_path / "provider.txt"
    _write(target, "old\n")
    _write(provider, "stable\n")
    provider_snapshot = read_physical_file(str(provider), "provider")
    real_replace = _transaction._replace_physical

    def replace_then_change_provider(
        source: str,
        destination: str,
        directory: _transaction.PinnedDirectory,
    ) -> None:
        real_replace(source, destination, directory)
        if os.path.abspath(destination) == os.path.abspath(str(target)):
            _write(provider, "concurrent\n")

    monkeypatch.setattr(
        _transaction, "_replace_physical", replace_then_change_provider
    )

    with pytest.raises(OSError, match="provider changed during"):
        _transaction.write_changes(
            [_change(target, "old\n", "new\n")],
            "provider transaction",
            [_transaction.FilePrecondition(str(provider), "provider", provider_snapshot)],
        )

    assert target.read_text(encoding="utf-8") == "old\n"
    assert provider.read_text(encoding="utf-8") == "concurrent\n"
    assert list(tmp_path.glob(".*.rollback")) == []


def test_commit_boundary_concurrent_write_is_restored_and_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.txt"
    _write(target, "old\n")
    real_capture = _transaction._capture_physical
    changed = False

    def write_before_capture(
        source: str,
        destination: str,
        directory: _transaction.PinnedDirectory,
    ) -> None:
        nonlocal changed
        if (
            not changed
            and os.path.abspath(source) == os.path.abspath(str(target))
            and destination.endswith(".rollback")
        ):
            changed = True
            _write(target, "concurrent\n")
        real_capture(source, destination, directory)

    monkeypatch.setattr(_transaction, "_capture_physical", write_before_capture)

    with pytest.raises(OSError, match="changed at commit boundary"):
        _transaction.write_changes(
            [_change(target, "old\n", "new\n")],
            "commit boundary",
        )

    assert changed
    assert target.read_text(encoding="utf-8") == "concurrent\n"
    assert list(tmp_path.glob(".*.tmp")) == []
    assert list(tmp_path.glob(".*.rollback")) == []


def test_existing_target_remains_visible_during_atomic_update(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.txt"
    _write(target, "old\n")
    replace_started = threading.Event()
    release_replace = threading.Event()
    failures: list[BaseException] = []
    observations: list[str] = []

    def pause_before_replace(
        _source: str,
        destination: str,
        _directory: _transaction.PinnedDirectory,
    ) -> None:
        if os.path.abspath(destination) == os.path.abspath(target):
            replace_started.set()
            if not release_replace.wait(5):
                raise TimeoutError("test replace gate timed out")

    def update() -> None:
        try:
            _transaction.write_changes(
                [_change(target, "old\n", "new\n")],
                "visible atomic update",
            )
        except BaseException as error:
            failures.append(error)

    monkeypatch.setattr(_transaction, "_replace_physical", pause_before_replace)
    worker = threading.Thread(target=update)
    worker.start()
    assert replace_started.wait(5)
    for _index in range(200):
        observations.append(target.read_text(encoding="utf-8"))
    release_replace.set()
    worker.join(5)

    assert not worker.is_alive()
    assert failures == []
    assert set(observations) <= {"old\n", "new\n"}
    assert target.read_text(encoding="utf-8") == "new\n"


def _transaction_subprocess_environment(home: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["HOME"] = str(home)
    environment["USERPROFILE"] = str(home)
    return environment


def test_process_exit_after_atomic_replace_recovers_on_restart(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    target = tmp_path / "target.txt"
    _write(target, "old\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    script = """
import os
import sys
from elydora.plugins import _transaction

target = sys.argv[1]
change = _transaction.source_change(target, "target", "old\\n", "new\\n", 0o600)
assert change is not None

def terminate_after_replace(source, destination, directory):
    del source, destination, directory
    os._exit(73)

_transaction._after_replace_physical = terminate_after_replace
_transaction.write_changes([change], "crash recovery")
"""

    completed = subprocess.run(
        [sys.executable, "-c", script, str(target)],
        cwd=Path(__file__).resolve().parents[1],
        env=_transaction_subprocess_environment(home),
        check=False,
    )

    assert completed.returncode == 73
    assert target.read_text(encoding="utf-8") == "new\n"
    _transaction.recover_pending_transactions()
    assert target.read_text(encoding="utf-8") == "old\n"
    assert list(tmp_path.glob(".*.tmp")) == []
    assert list(tmp_path.glob(".*.rollback")) == []


def test_process_exit_after_committed_marker_keeps_atomic_update(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    target = tmp_path / "target.txt"
    _write(target, "old\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    script = """
import os
import sys
from elydora.plugins import _transaction

target = sys.argv[1]
change = _transaction.source_change(target, "target", "old\\n", "new\\n", 0o600)
assert change is not None
_transaction._after_journal_commit = lambda: os._exit(74)
_transaction.write_changes([change], "committed crash recovery")
"""

    completed = subprocess.run(
        [sys.executable, "-c", script, str(target)],
        cwd=Path(__file__).resolve().parents[1],
        env=_transaction_subprocess_environment(home),
        check=False,
    )

    assert completed.returncode == 74
    assert target.read_text(encoding="utf-8") == "new\n"
    _transaction.recover_pending_transactions()
    assert target.read_text(encoding="utf-8") == "new\n"
    assert list(tmp_path.glob(".*.tmp")) == []
    assert list(tmp_path.glob(".*.rollback")) == []


def test_process_exit_mid_transaction_restores_all_targets(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    _write(first, "first-old\n")
    _write(second, "second-old\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    script = """
import os
import sys
from elydora.plugins import _transaction

first, second = sys.argv[1:]
changes = [
    _transaction.source_change(first, "first", "first-old\\n", "first-new\\n", 0o600),
    _transaction.source_change(second, "second", "second-old\\n", "second-new\\n", 0o600),
]
assert all(change is not None for change in changes)
calls = 0

def terminate_after_first(source, destination, directory):
    global calls
    del source, destination, directory
    calls += 1
    if calls == 1:
        os._exit(75)

_transaction._after_replace_physical = terminate_after_first
_transaction.write_changes(changes, "multi-file crash recovery")
"""

    completed = subprocess.run(
        [sys.executable, "-c", script, str(first), str(second)],
        cwd=Path(__file__).resolve().parents[1],
        env=_transaction_subprocess_environment(home),
        check=False,
    )

    assert completed.returncode == 75
    assert first.read_text(encoding="utf-8") == "first-new\n"
    assert second.read_text(encoding="utf-8") == "second-old\n"
    _transaction.recover_pending_transactions()
    assert first.read_text(encoding="utf-8") == "first-old\n"
    assert second.read_text(encoding="utf-8") == "second-old\n"
    assert list(tmp_path.glob(".*.tmp")) == []
    assert list(tmp_path.glob(".*.rollback")) == []


@pytest.mark.parametrize(
    ("original", "next_source", "exit_code"),
    [
        ("old\n", None, 76),
        (None, "created\n", 77),
    ],
)
def test_process_exit_recovers_atomic_create_and_remove(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    original: str | None,
    next_source: str | None,
    exit_code: int,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    target = tmp_path / "target.txt"
    if original is not None:
        _write(target, original)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    script = """
import json
import os
import sys
from elydora.plugins import _transaction

target = sys.argv[1]
original = json.loads(sys.argv[2])
next_source = json.loads(sys.argv[3])
exit_code = int(sys.argv[4])
change = _transaction.source_change(target, "target", original, next_source, 0o600)
assert change is not None
_transaction._after_replace_physical = lambda source, destination, directory: os._exit(exit_code)
_transaction.write_changes([change], "create-remove crash recovery")
"""

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(target),
            json.dumps(original),
            json.dumps(next_source),
            str(exit_code),
        ],
        cwd=Path(__file__).resolve().parents[1],
        env=_transaction_subprocess_environment(home),
        check=False,
    )

    assert completed.returncode == exit_code
    assert target.exists() is (next_source is not None)
    _transaction.recover_pending_transactions()
    assert target.exists() is (original is not None)
    if original is not None:
        assert target.read_text(encoding="utf-8") == original
    assert list(tmp_path.glob(".*.tmp")) == []
    assert list(tmp_path.glob(".*.rollback")) == []


def test_cross_process_writers_are_serialized(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    target = tmp_path / "target.txt"
    ready = tmp_path / "ready"
    second_ready = tmp_path / "second-ready"
    release = tmp_path / "release"
    _write(target, "old\n")
    environment = _transaction_subprocess_environment(home)
    first_script = """
import pathlib
import sys
import time
from elydora.plugins import _transaction

target, ready, release = map(pathlib.Path, sys.argv[1:])
change = _transaction.source_change(str(target), "target", "old\\n", "first\\n", 0o600)
assert change is not None

def pause(source, destination, directory):
    del source, destination, directory
    ready.write_text("ready", encoding="utf-8")
    deadline = time.monotonic() + 10
    while not release.exists():
        if time.monotonic() >= deadline:
            raise TimeoutError("writer release timed out")
        time.sleep(0.01)

_transaction._replace_physical = pause
_transaction.write_changes([change], "first writer")
"""
    second_script = """
import pathlib
import sys
from elydora.plugins import _transaction

target = sys.argv[1]
ready = pathlib.Path(sys.argv[2])
change = _transaction.source_change(target, "target", "old\\n", "second\\n", 0o600)
assert change is not None
ready.write_text("ready", encoding="utf-8")
try:
    _transaction.write_changes([change], "second writer")
except OSError as error:
    print(error)
    raise SystemExit(19)
"""
    first = subprocess.Popen(
        [sys.executable, "-c", first_script, str(target), str(ready), str(release)],
        cwd=Path(__file__).resolve().parents[1],
        env=environment,
    )
    deadline = time.monotonic() + 10
    while not ready.exists() and first.poll() is None:
        if time.monotonic() >= deadline:
            first.kill()
            raise TimeoutError("first writer did not reach the replace gate")
        time.sleep(0.01)
    assert first.poll() is None
    second = subprocess.Popen(
        [sys.executable, "-c", second_script, str(target), str(second_ready)],
        cwd=Path(__file__).resolve().parents[1],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    deadline = time.monotonic() + 10
    while not second_ready.exists() and second.poll() is None:
        if time.monotonic() >= deadline:
            second.kill()
            first.kill()
            raise TimeoutError("second writer did not reach the transaction gate")
        time.sleep(0.01)
    assert second.poll() is None
    time.sleep(0.2)
    assert second.poll() is None
    release.write_text("release", encoding="utf-8")
    assert first.wait(timeout=10) == 0
    output, _stderr = second.communicate(timeout=10)

    assert second.returncode == 19, output
    assert "changed during" in output
    assert target.read_text(encoding="utf-8") == "first\n"


def test_final_replace_exception_after_success_restores_original(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.txt"
    _write(target, "old\n")
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
            [_change(target, "old\n", "new\n")],
            "post-replace failure",
        )

    assert target.read_text(encoding="utf-8") == "old\n"
    assert list(tmp_path.glob(".*.rollback")) == []


def test_capture_exception_after_success_restores_original(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.txt"
    _write(target, "old\n")
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
            [_change(target, "old\n", "new\n")],
            "post-capture failure",
        )

    assert target.read_text(encoding="utf-8") == "old\n"
    assert list(tmp_path.glob(".*.rollback")) == []


def test_rollback_reservation_collision_preserves_victim_and_original(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.txt"
    _write(target, "old\n")
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
            _write(collision_path, victim)

    monkeypatch.setattr(
        _transaction,
        "_capture_physical",
        collide_with_rollback_destination,
    )

    with pytest.raises(OSError, match="exist"):
        _transaction.write_changes(
            [_change(target, "old\n", "new\n")],
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
    _write(target, "old\n")
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
            _write(target, "concurrent\n")
        real_replace(source, destination, directory)

    monkeypatch.setattr(
        _transaction,
        "_replace_physical",
        create_target_before_install,
    )

    with pytest.raises(OSError, match="original content preserved"):
        _transaction.write_changes(
            [_change(target, "old\n", "new\n")],
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
    _write(target, "old\n")
    _write(second, "second-old\n")
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
            _write(target, "concurrent recovery\n")
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
                _change(target, "old\n", "new\n"),
                _change(second, "second-old\n", "second-new\n"),
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
    _write(target, "old\n")
    _write(second, "second-old\n")
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
            _write(rollback_path, "concurrent recovery source\n")
        real_restore(source, destination, directory)

    monkeypatch.setattr(_transaction, "_replace_physical", fail_second_commit)
    monkeypatch.setattr(_transaction, "_restore_physical", replace_restore_source)

    with pytest.raises(OSError, match="recovery source changed") as raised:
        _transaction.write_changes(
            [
                _change(target, "old\n", "new\n"),
                _change(second, "second-old\n", "second-new\n"),
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
    _write(second, "second-old\n")
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
            _write(created, "concurrent replacement\n")
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
                _change(created, None, "generated\n"),
                _change(second, "second-old\n", "second-new\n"),
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
    _write(secret, "secret\n")
    _write(second, "old\n")
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
                _change(secret, "secret\n", "secret\n", enforce_mode=True),
                _change(second, "old\n", "new\n"),
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
    _write(removed, "remove me\n")
    _write(second, "old\n")
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
                _change(removed, "remove me\n", None),
                _change(second, "old\n", "new\n"),
            ],
            "deletion rollback mode",
        )

    assert rollback_modes == [0o600]
    assert removed.read_text(encoding="utf-8") == "remove me\n"
    assert removed.stat().st_mode & 0o777 == 0o644
    assert second.read_text(encoding="utf-8") == "old\n"
    assert list(tmp_path.glob(".*.rollback")) == []


def _swap_directory(parent: Path, backup: Path, redirected: Path) -> None:
    parent.rename(backup)
    redirected.rename(parent)


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
            _swap_directory(parent, backup, redirected)
        return real_write(*args, **kwargs)

    monkeypatch.setattr(_transaction_staging, "write_staged", swap_then_stage)

    with pytest.raises(OSError, match="changed during transaction"):
        _transaction.write_changes(
            [_change(target, None, "secret\n")],
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
            _swap_directory(parent, backup, redirected)
        real_replace(source, destination, directory)

    monkeypatch.setattr(_transaction, "_replace_physical", swap_then_replace)

    with pytest.raises(OSError, match="changed during transaction"):
        _transaction.write_changes(
            [_change(target, None, "secret\n")],
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
            [_change(target, None, "{}\n")],
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
            [_change(target, None, "{}\n")],
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
            [_change(target, None, "{}\n")],
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
