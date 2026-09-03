from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from elydora import cli
from elydora.plugins import (
    _directory_removal,
    _transaction,
)
from elydora.plugins._runtime_removal import (
    commit_runtime_removal,
    prepare_runtime_removal,
)
from runtime_removal_support import (
    AGENT_ID,
    AGENT_NAME,
    PRIVATE_KEY,
    prepare_runtime,
    set_home,
    write_secret,
)


@pytest.mark.skipif(os.name == "nt", reason="POSIX parent-dirfd contract")
def test_posix_runtime_directory_removal_cleans_exact_quarantine(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, agent = prepare_runtime(monkeypatch, tmp_path)
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
    root, agent = prepare_runtime(monkeypatch, tmp_path)
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
    _root, agent = prepare_runtime(monkeypatch, tmp_path)
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
    set_home(monkeypatch, home)
    monkeypatch.chdir(workspace)
    key_path = tmp_path / "install-private.key"
    write_secret(key_path, PRIVATE_KEY)
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
