from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

import pytest

from elydora.plugins import _transaction
from elydora.plugins._managed_files import read_physical_file
from transaction_support import (
    make_change,
    transaction_subprocess_environment,
    write_source,
)


def test_post_replace_precondition_failure_restores_original_target(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.txt"
    provider = tmp_path / "provider.txt"
    write_source(target, "old\n")
    write_source(provider, "stable\n")
    provider_snapshot = read_physical_file(str(provider), "provider")
    real_replace = _transaction._replace_physical

    def replace_then_change_provider(
        source: str,
        destination: str,
        directory: _transaction.PinnedDirectory,
    ) -> None:
        real_replace(source, destination, directory)
        if os.path.abspath(destination) == os.path.abspath(str(target)):
            write_source(provider, "concurrent\n")

    monkeypatch.setattr(
        _transaction, "_replace_physical", replace_then_change_provider
    )

    with pytest.raises(OSError, match="provider changed during"):
        _transaction.write_changes(
            [make_change(target, "old\n", "new\n")],
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
    write_source(target, "old\n")
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
            write_source(target, "concurrent\n")
        real_capture(source, destination, directory)

    monkeypatch.setattr(_transaction, "_capture_physical", write_before_capture)

    with pytest.raises(OSError, match="changed at commit boundary"):
        _transaction.write_changes(
            [make_change(target, "old\n", "new\n")],
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
    write_source(target, "old\n")
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
                [make_change(target, "old\n", "new\n")],
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


def test_process_exit_after_atomic_replace_recovers_on_restart(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    target = tmp_path / "target.txt"
    write_source(target, "old\n")
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
        env=transaction_subprocess_environment(home),
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
    write_source(target, "old\n")
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
        env=transaction_subprocess_environment(home),
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
    write_source(first, "first-old\n")
    write_source(second, "second-old\n")
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
        env=transaction_subprocess_environment(home),
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
        write_source(target, original)
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
        env=transaction_subprocess_environment(home),
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
    write_source(target, "old\n")
    environment = transaction_subprocess_environment(home)
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
