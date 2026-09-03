from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest

from elydora.plugins import (
    _opaque_cleanup,
    _opaque_removal,
    _transaction,
)
from elydora.plugins._runtime_removal import (
    commit_runtime_removal,
    prepare_runtime_removal,
)
from runtime_removal_support import (
    AGENT_ID,
    AGENT_NAME,
    prepare_runtime,
    stream_digest,
    write_error_log,
)


def test_process_exit_after_opaque_removal_restores_error_log_on_restart(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, agent = prepare_runtime(monkeypatch, tmp_path)
    error_log = agent / "error.log"
    expected_digest = write_error_log(error_log, chunks=4)
    script = """
import os
import sys
from elydora.plugins import _transaction
from elydora.plugins._runtime_removal import prepare_runtime_removal, commit_runtime_removal

agent_id, agent_name = sys.argv[1:]
plan = prepare_runtime_removal(agent_id, agent_name)
assert plan is not None
_transaction._commit = lambda staged: os._exit(78)
commit_runtime_removal(plan)
"""
    environment = os.environ.copy()
    environment["HOME"] = os.environ["HOME"]
    environment["USERPROFILE"] = os.environ["USERPROFILE"]

    completed = subprocess.run(
        [sys.executable, "-c", script, AGENT_ID, AGENT_NAME],
        cwd=Path(__file__).resolve().parents[1],
        env=environment,
        check=False,
    )

    assert completed.returncode == 78
    assert not error_log.exists()
    _transaction.recover_pending_transactions()
    assert stream_digest(error_log) == expected_digest
    assert (agent / "config.json").is_file()
    assert list(agent.glob(".*.opaque-rollback")) == []


def test_error_log_append_at_capture_boundary_fails_and_preserves_append(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, agent = prepare_runtime(monkeypatch, tmp_path)
    error_log = agent / "error.log"
    write_error_log(error_log)
    appended = b"concurrent append\n"
    original_capture = _opaque_removal._capture_physical

    def append_then_capture(staged: Any) -> None:
        with error_log.open("ab") as file:
            file.write(appended)
            file.flush()
            os.fsync(file.fileno())
        original_capture(staged)

    plan = prepare_runtime_removal(AGENT_ID, AGENT_NAME)
    assert plan is not None
    monkeypatch.setattr(
        _opaque_removal,
        "_capture_physical",
        append_then_capture,
    )

    with pytest.raises(OSError, match="changed at commit boundary"):
        commit_runtime_removal(plan)

    assert error_log.read_bytes().endswith(appended)
    assert (agent / "config.json").is_file()


def test_error_log_replace_at_capture_boundary_preserves_both_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, agent = prepare_runtime(monkeypatch, tmp_path)
    error_log = agent / "error.log"
    original_digest = write_error_log(error_log)
    displaced = agent / "displaced-error.log"
    replacement = b"concurrent replacement\n"
    original_capture = _opaque_removal._capture_physical

    def replace_then_capture(staged: Any) -> None:
        error_log.rename(displaced)
        error_log.write_bytes(replacement)
        if os.name != "nt":
            error_log.chmod(0o600)
        original_capture(staged)

    plan = prepare_runtime_removal(AGENT_ID, AGENT_NAME)
    assert plan is not None
    monkeypatch.setattr(
        _opaque_removal,
        "_capture_physical",
        replace_then_capture,
    )

    with pytest.raises(OSError, match="changed at commit boundary"):
        commit_runtime_removal(plan)

    assert error_log.read_bytes() == replacement
    assert stream_digest(displaced) == original_digest
    assert (agent / "config.json").is_file()


def test_error_log_rollback_destination_collision_preserves_victim(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, agent = prepare_runtime(monkeypatch, tmp_path)
    error_log = agent / "error.log"
    original_digest = write_error_log(error_log)
    victim = b"concurrent opaque rollback destination\n"
    rollback_path: Path | None = None
    original_capture = _opaque_removal._capture_physical

    def collide_with_rollback_destination(staged: Any) -> None:
        nonlocal rollback_path
        assert staged.rollback_path is not None
        rollback_path = Path(staged.rollback_path)
        rollback_path.write_bytes(victim)
        if os.name != "nt":
            rollback_path.chmod(0o600)
        original_capture(staged)

    plan = prepare_runtime_removal(AGENT_ID, AGENT_NAME)
    assert plan is not None
    monkeypatch.setattr(
        _opaque_removal,
        "_capture_physical",
        collide_with_rollback_destination,
    )

    with pytest.raises(OSError, match="exist"):
        commit_runtime_removal(plan)

    assert rollback_path is not None
    assert rollback_path.read_bytes() == victim
    assert stream_digest(error_log) == original_digest
    assert (agent / "config.json").is_file()


def test_error_log_cleanup_boundary_append_is_preserved_and_reported(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, agent = prepare_runtime(monkeypatch, tmp_path)
    error_log = agent / "error.log"
    write_error_log(error_log)
    appended = b"cleanup boundary append\n"
    original_capture = _opaque_cleanup._capture_cleanup_physical

    def append_then_capture(
        staged: Any,
        source_path: str,
    ) -> None:
        with Path(source_path).open("ab") as file:
            file.write(appended)
            file.flush()
            os.fsync(file.fileno())
        original_capture(staged, source_path)

    plan = prepare_runtime_removal(AGENT_ID, AGENT_NAME)
    assert plan is not None
    monkeypatch.setattr(
        _opaque_cleanup,
        "_capture_cleanup_physical",
        append_then_capture,
    )

    with pytest.raises(OSError, match="changed at cleanup boundary"):
        commit_runtime_removal(plan)

    preserved = list(agent.glob(".error.log.*.opaque-rollback"))
    assert len(preserved) == 1
    assert preserved[0].read_bytes().endswith(appended)
    assert list(agent.glob(".*.elydora-quarantine")) == []


def test_error_log_cleanup_replacement_preserves_both_identities(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, agent = prepare_runtime(monkeypatch, tmp_path)
    error_log = agent / "error.log"
    original_digest = write_error_log(error_log)
    replacement = b"concurrent cleanup replacement\n"
    displaced = agent / "displaced-opaque-rollback"
    rollback_path: Path | None = None
    original_capture = _opaque_cleanup._capture_cleanup_physical

    def replace_before_cleanup_capture(staged: Any, source_path: str) -> None:
        nonlocal rollback_path
        rollback_path = Path(source_path)
        rollback_path.rename(displaced)
        rollback_path.write_bytes(replacement)
        if os.name != "nt":
            rollback_path.chmod(0o600)
        original_capture(staged, source_path)

    plan = prepare_runtime_removal(AGENT_ID, AGENT_NAME)
    assert plan is not None
    monkeypatch.setattr(
        _opaque_cleanup,
        "_capture_cleanup_physical",
        replace_before_cleanup_capture,
    )

    with pytest.raises(OSError, match="changed at cleanup boundary") as raised:
        commit_runtime_removal(plan)

    assert rollback_path is not None
    assert f"concurrent data preserved at {rollback_path}" in str(raised.value)
    assert rollback_path.read_bytes() == replacement
    assert stream_digest(displaced) == original_digest
    assert list(agent.glob(".*.elydora-quarantine")) == []


@pytest.mark.parametrize("entry_kind", ["directory", "symlink"])
def test_error_log_rejects_nonphysical_entries_before_runtime_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    entry_kind: str,
) -> None:
    _root, agent = prepare_runtime(monkeypatch, tmp_path)
    error_log = agent / "error.log"
    original_config = (agent / "config.json").read_bytes()
    if entry_kind == "directory":
        error_log.mkdir()
        (error_log / "marker").write_text("preserve", encoding="utf-8")
    else:
        target = tmp_path / "external-error.log"
        target.write_text("preserve", encoding="utf-8")
        try:
            error_log.symlink_to(target)
        except OSError as error:
            pytest.skip(f"File symbolic links are unavailable: {error}")

    with pytest.raises(OSError, match="not a physical file"):
        prepare_runtime_removal(AGENT_ID, AGENT_NAME)

    assert (agent / "config.json").read_bytes() == original_config
    assert error_log.exists() or error_log.is_symlink()


@pytest.mark.skipif(os.name == "nt", reason="POSIX owner-only contract")
def test_error_log_requires_owner_only_permissions_during_prepare(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, agent = prepare_runtime(monkeypatch, tmp_path)
    error_log = agent / "error.log"
    error_log.write_text("historical error\n", encoding="utf-8")
    error_log.chmod(0o640)

    with pytest.raises(PermissionError, match="accessible only by its owner"):
        prepare_runtime_removal(AGENT_ID, AGENT_NAME)

    assert error_log.read_text(encoding="utf-8") == "historical error\n"
