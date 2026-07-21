from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any

import pytest

from elydora import cli
from elydora.plugins import (
    _directory_removal,
    _opaque_cleanup,
    _opaque_removal,
    _transaction,
)
from elydora.plugins._runtime_removal import (
    commit_runtime_removal,
    finalize_runtime_removal,
    prepare_runtime_removal,
)


AGENT_ID = "agent-1"
AGENT_NAME = "opencode"
PRIVATE_KEY = base64.urlsafe_b64encode(bytes([19]) * 32).rstrip(b"=").decode()


def _set_home(monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _write_secret(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o600)


def _write_error_log(path: Path, chunks: int = 1) -> str:
    digest = hashlib.sha256()
    block = b"opaque historical error\n" * 4096
    with path.open("wb") as file:
        for _index in range(chunks):
            file.write(block)
            digest.update(block)
    if os.name != "nt":
        path.chmod(0o600)
    return digest.hexdigest()


def _stream_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _runtime(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    agent_name: str = AGENT_NAME,
) -> tuple[Path, Path]:
    home = tmp_path / "home"
    root = home / ".elydora"
    agent = root / AGENT_ID
    _set_home(monkeypatch, home)
    _write_json(
        agent / "config.json",
        {"agent_id": AGENT_ID, "agent_name": agent_name},
    )
    return root, agent


def _uninstall_args(agent_name: str = AGENT_NAME) -> argparse.Namespace:
    return cli.build_parser().parse_args(
        [
            "uninstall",
            "--agent",
            agent_name,
            "--agent_id",
            AGENT_ID,
        ]
    )


@pytest.mark.parametrize("entry_kind", ["file", "directory", "symlink"])
def test_cli_runtime_removal_rejects_unknown_entries_before_provider_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    entry_kind: str,
) -> None:
    _root, agent = _runtime(monkeypatch, tmp_path)
    unknown = agent / "user-owned"
    if entry_kind == "file":
        unknown.write_text("preserve", encoding="utf-8")
    elif entry_kind == "directory":
        unknown.mkdir()
        (unknown / "marker").write_text("preserve", encoding="utf-8")
    else:
        target = tmp_path / "symlink-target"
        target.write_text("preserve", encoding="utf-8")
        try:
            unknown.symlink_to(target)
        except OSError as error:
            pytest.skip(f"File symbolic links are unavailable: {error}")

    provider_calls: list[str] = []

    class Plugin:
        def uninstall(self, agent_id: str = "") -> None:
            provider_calls.append(agent_id)

    monkeypatch.setattr(cli, "_get_plugin", lambda _name: Plugin())

    with pytest.raises(OSError, match="unmanaged entries"):
        cli.cmd_uninstall(_uninstall_args())

    assert provider_calls == []
    assert unknown.exists() or unknown.is_symlink()
    assert (agent / "config.json").is_file()


def test_cli_skips_generic_cleanup_for_plugin_managed_runtime_removal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, agent = _runtime(monkeypatch, tmp_path, agent_name="kiroide")
    provider_calls: list[str] = []

    class Plugin:
        manages_runtime_removal = True

        def uninstall(self, agent_id: str = "") -> None:
            provider_calls.append(agent_id)

    def reject_generic_prepare(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("generic runtime removal must stay unused")

    monkeypatch.setattr(cli, "_get_plugin", lambda _name: Plugin())
    monkeypatch.setattr(cli, "prepare_runtime_removal", reject_generic_prepare)

    cli.cmd_uninstall(_uninstall_args("kiroide"))

    assert provider_calls == [AGENT_ID]
    assert (agent / "config.json").is_file()


def test_runtime_removal_rejects_config_identity_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, agent = _runtime(monkeypatch, tmp_path)
    plan = prepare_runtime_removal(AGENT_ID, AGENT_NAME)
    assert plan is not None
    concurrent = {"agent_id": AGENT_ID, "agent_name": "cursor"}
    _write_json(agent / "config.json", concurrent)

    with pytest.raises(OSError, match="changed"):
        commit_runtime_removal(plan)

    assert json.loads((agent / "config.json").read_text(encoding="utf-8")) == (
        concurrent
    )


def test_runtime_removal_treats_other_plugin_wrappers_as_unmanaged(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, agent = _runtime(monkeypatch, tmp_path)
    wrapper_name = "augment-guard.cmd" if os.name == "nt" else "augment-guard.sh"
    user_file = agent / wrapper_name
    user_file.write_text("user-owned payload", encoding="utf-8")

    with pytest.raises(OSError, match="unmanaged entries"):
        prepare_runtime_removal(AGENT_ID, AGENT_NAME)

    assert user_file.read_text(encoding="utf-8") == "user-owned payload"


@pytest.mark.parametrize("swap", ["agent", "root"])
def test_runtime_removal_rejects_directory_swaps_without_deleting_replacements(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    swap: str,
) -> None:
    root, agent = _runtime(monkeypatch, tmp_path)
    plan = prepare_runtime_removal(AGENT_ID, AGENT_NAME)
    assert plan is not None

    if swap == "agent":
        original = root / "original-agent"
        agent.rename(original)
        agent.mkdir()
        replacement = agent
    else:
        original = root.with_name("original-root")
        root.rename(original)
        replacement = root / AGENT_ID
        replacement.mkdir(parents=True)
    marker = replacement / "replacement-marker"
    marker.write_text("preserve", encoding="utf-8")

    with pytest.raises(OSError, match="changed"):
        commit_runtime_removal(plan)

    assert marker.read_text(encoding="utf-8") == "preserve"
    assert (original / "config.json").is_file() if swap == "agent" else (
        original / AGENT_ID / "config.json"
    ).is_file()


def test_runtime_removal_rejects_concurrent_creation_of_missing_managed_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, agent = _runtime(monkeypatch, tmp_path)
    plan = prepare_runtime_removal(AGENT_ID, AGENT_NAME)
    assert plan is not None
    concurrent = agent / "status-cache.json"
    concurrent.write_text('{"state":"concurrent"}\n', encoding="utf-8")

    with pytest.raises(OSError, match="changed"):
        commit_runtime_removal(plan)

    assert concurrent.read_text(encoding="utf-8") == (
        '{"state":"concurrent"}\n'
    )
    assert (agent / "config.json").is_file()


def test_runtime_removal_preserves_unknown_entry_created_before_finalize(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, agent = _runtime(monkeypatch, tmp_path)
    plan = prepare_runtime_removal(AGENT_ID, AGENT_NAME)
    assert plan is not None
    _transaction.write_changes(
        plan.changes,
        "Remove test runtime",
        plan.file_preconditions,
        plan.directory_preconditions,
    )
    concurrent = agent / "concurrent-user-file"
    concurrent.write_text("preserve", encoding="utf-8")

    with pytest.raises(OSError, match="contains entries after managed cleanup"):
        finalize_runtime_removal(plan)

    assert concurrent.read_text(encoding="utf-8") == "preserve"
    assert agent.is_dir()


def test_runtime_removal_deletes_all_known_dynamic_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root, agent = _runtime(monkeypatch, tmp_path)
    dynamic = {
        "chain-state.json": '{"sequence":1}\n',
        "status-cache.json": '{"status":"active"}\n',
        "error.log": "recorded delivery error\n",
    }
    for name, contents in dynamic.items():
        (agent / name).write_text(contents, encoding="utf-8")
    if os.name != "nt":
        (agent / "error.log").chmod(0o600)
    plan = prepare_runtime_removal(AGENT_ID, AGENT_NAME)
    assert plan is not None

    commit_runtime_removal(plan)

    assert not agent.exists()
    assert root.is_dir()


def test_runtime_removal_streams_oversized_error_log(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root, agent = _runtime(monkeypatch, tmp_path)
    expected_digest = _write_error_log(agent / "error.log", chunks=32)
    assert (agent / "error.log").stat().st_size > 2 * 1024 * 1024

    plan = prepare_runtime_removal(AGENT_ID, AGENT_NAME)
    assert plan is not None
    assert plan.opaque_removals[0].original is not None
    assert plan.opaque_removals[0].original.sha256 == expected_digest

    commit_runtime_removal(plan)

    assert not agent.exists()
    assert root.is_dir()


def test_oversized_error_log_rolls_back_after_later_text_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, agent = _runtime(monkeypatch, tmp_path)
    error_log = agent / "error.log"
    expected_digest = _write_error_log(error_log, chunks=32)
    expected_mode = stat.S_IMODE(error_log.stat().st_mode)
    original_commit = _transaction._commit

    def fail_first_text_commit(_staged: object) -> None:
        raise OSError("injected text commit failure")

    plan = prepare_runtime_removal(AGENT_ID, AGENT_NAME)
    assert plan is not None
    monkeypatch.setattr(_transaction, "_commit", fail_first_text_commit)

    with pytest.raises(OSError, match="injected text commit failure"):
        commit_runtime_removal(plan)

    monkeypatch.setattr(_transaction, "_commit", original_commit)
    assert _stream_digest(error_log) == expected_digest
    assert stat.S_IMODE(error_log.stat().st_mode) == expected_mode
    assert (agent / "config.json").is_file()
    assert list(agent.glob("*.opaque-rollback")) == []


def test_process_exit_after_opaque_removal_restores_error_log_on_restart(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, agent = _runtime(monkeypatch, tmp_path)
    error_log = agent / "error.log"
    expected_digest = _write_error_log(error_log, chunks=4)
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
    assert _stream_digest(error_log) == expected_digest
    assert (agent / "config.json").is_file()
    assert list(agent.glob(".*.opaque-rollback")) == []


def test_error_log_append_at_capture_boundary_fails_and_preserves_append(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, agent = _runtime(monkeypatch, tmp_path)
    error_log = agent / "error.log"
    _write_error_log(error_log)
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
    _root, agent = _runtime(monkeypatch, tmp_path)
    error_log = agent / "error.log"
    original_digest = _write_error_log(error_log)
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
    assert _stream_digest(displaced) == original_digest
    assert (agent / "config.json").is_file()


def test_error_log_rollback_destination_collision_preserves_victim(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, agent = _runtime(monkeypatch, tmp_path)
    error_log = agent / "error.log"
    original_digest = _write_error_log(error_log)
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
    assert _stream_digest(error_log) == original_digest
    assert (agent / "config.json").is_file()


def test_error_log_cleanup_boundary_append_is_preserved_and_reported(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, agent = _runtime(monkeypatch, tmp_path)
    error_log = agent / "error.log"
    _write_error_log(error_log)
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
    _root, agent = _runtime(monkeypatch, tmp_path)
    error_log = agent / "error.log"
    original_digest = _write_error_log(error_log)
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
    assert _stream_digest(displaced) == original_digest
    assert list(agent.glob(".*.elydora-quarantine")) == []


@pytest.mark.parametrize("entry_kind", ["directory", "symlink"])
def test_error_log_rejects_nonphysical_entries_before_runtime_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    entry_kind: str,
) -> None:
    _root, agent = _runtime(monkeypatch, tmp_path)
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
    _root, agent = _runtime(monkeypatch, tmp_path)
    error_log = agent / "error.log"
    error_log.write_text("historical error\n", encoding="utf-8")
    error_log.chmod(0o640)

    with pytest.raises(PermissionError, match="accessible only by its owner"):
        prepare_runtime_removal(AGENT_ID, AGENT_NAME)

    assert error_log.read_text(encoding="utf-8") == "historical error\n"


@pytest.mark.skipif(os.name == "nt", reason="POSIX parent-dirfd contract")
def test_posix_runtime_directory_removal_cleans_exact_quarantine(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, agent = _runtime(monkeypatch, tmp_path)
    plan = prepare_runtime_removal(AGENT_ID, AGENT_NAME)
    assert plan is not None
    original_rename = _directory_removal._rename_posix_into_quarantine
    calls: list[tuple[int, str, int, str, str]] = []

    def record_rename(
        parent_descriptor: int,
        source_name: str,
        quarantine_descriptor: int,
        source_path: str,
        destination_path: str,
    ) -> None:
        calls.append(
            (
                parent_descriptor,
                source_name,
                quarantine_descriptor,
                source_path,
                destination_path,
            )
        )
        original_rename(
            parent_descriptor,
            source_name,
            quarantine_descriptor,
            source_path,
            destination_path,
        )

    monkeypatch.setattr(
        _directory_removal,
        "_rename_posix_into_quarantine",
        record_rename,
    )

    commit_runtime_removal(plan)

    assert len(calls) == 1
    assert isinstance(calls[0][0], int)
    assert calls[0][1] == AGENT_ID
    assert isinstance(calls[0][2], int)
    assert Path(calls[0][3]) == agent
    assert Path(calls[0][4]).name == "entry"
    quarantined = list(
        Path(plan.runtime_root).glob(
            f".{AGENT_ID}.*.elydora-removed/entry"
        )
    )
    assert quarantined == []
    assert list(Path(plan.runtime_root).glob(f".{AGENT_ID}.*.elydora-removed")) == []
    assert not agent.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX quarantine contract")
def test_posix_runtime_quarantine_preserves_atomic_boundary_swap(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root, agent = _runtime(monkeypatch, tmp_path)
    plan = prepare_runtime_removal(AGENT_ID, AGENT_NAME)
    assert plan is not None
    replacement = root / "replacement"
    replacement.mkdir()
    marker = replacement / "user-owned"
    marker.write_text("preserve", encoding="utf-8")
    original = root / "agent-original"
    real_rename = _directory_removal._rename_posix_into_quarantine

    def swap_then_quarantine(
        parent_descriptor: int,
        source_name: str,
        quarantine_descriptor: int,
        source_path: str,
        destination_path: str,
    ) -> None:
        agent.rename(original)
        replacement.rename(agent)
        real_rename(
            parent_descriptor,
            source_name,
            quarantine_descriptor,
            source_path,
            destination_path,
        )

    real_rmdir = _directory_removal.os.rmdir

    def reject_path_rmdir(
        path: str,
        *,
        dir_fd: int | None = None,
    ) -> None:
        if dir_fd is None:
            raise AssertionError("POSIX runtime cleanup must use a parent dirfd")
        real_rmdir(path, dir_fd=dir_fd)

    monkeypatch.setattr(
        _directory_removal,
        "_rename_posix_into_quarantine",
        swap_then_quarantine,
    )
    monkeypatch.setattr(_directory_removal.os, "rmdir", reject_path_rmdir)

    with pytest.raises(OSError, match="changed while quarantining"):
        commit_runtime_removal(plan)

    quarantined_markers = list(
        root.glob(f".{AGENT_ID}.*.elydora-removed/entry/user-owned")
    )
    assert len(quarantined_markers) == 1
    assert quarantined_markers[0].read_text(encoding="utf-8") == "preserve"
    assert original.is_dir()


@pytest.mark.skipif(os.name != "nt", reason="Windows exact-handle contract")
def test_windows_runtime_directory_removal_marks_exact_pinned_handle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, agent = _runtime(monkeypatch, tmp_path)
    plan = prepare_runtime_removal(AGENT_ID, AGENT_NAME)
    assert plan is not None
    original_mark = _directory_removal._mark_windows_directory_for_deletion
    observed: list[tuple[int, int]] = []

    def record_mark(directory: Any) -> None:
        assert directory.descriptor is not None
        opened = os.fstat(directory.descriptor)
        observed.append((opened.st_dev, opened.st_ino))
        assert observed[-1] == (
            plan.agent_snapshot.device,
            plan.agent_snapshot.inode,
        )
        original_mark(directory)

    monkeypatch.setattr(
        _directory_removal,
        "_mark_windows_directory_for_deletion",
        record_mark,
    )

    commit_runtime_removal(plan)

    assert observed == [(plan.agent_snapshot.device, plan.agent_snapshot.inode)]
    assert not agent.exists()


def test_kiroide_cli_install_failure_leaves_no_runtime_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    home.mkdir()
    workspace.mkdir()
    _set_home(monkeypatch, home)
    monkeypatch.chdir(workspace)
    key_path = tmp_path / "install-private.key"
    _write_secret(key_path, PRIVATE_KEY)
    args = cli.build_parser().parse_args(
        [
            "install",
            "--agent",
            "kiroide",
            "--org_id",
            "org-1",
            "--agent_id",
            AGENT_ID,
            "--private_key_file",
            str(key_path),
            "--kid",
            "kid-1",
        ]
    )

    def fail_commit(_staged: object) -> None:
        raise OSError("injected Kiro IDE CLI commit failure")

    monkeypatch.setattr(_transaction, "_commit", fail_commit)

    with pytest.raises(OSError, match="injected Kiro IDE CLI commit failure"):
        cli.cmd_install(args)

    # The durable transaction state directory survives failures by design;
    # everything else under the runtime root must be rolled back.
    elydora_root = home / ".elydora"
    if elydora_root.exists():
        assert [entry.name for entry in elydora_root.iterdir()] == ["transactions"]
    assert not (workspace / ".kiro").exists()
