from __future__ import annotations

import json
import os
from pathlib import Path
import stat

import pytest

from elydora import cli
from elydora.plugins import (
    _transaction,
)
from elydora.plugins._runtime_removal import (
    commit_runtime_removal,
    finalize_runtime_removal,
    prepare_runtime_removal,
)
from runtime_removal_support import (
    AGENT_ID,
    AGENT_NAME,
    prepare_runtime,
    stream_digest,
    uninstall_args,
    write_error_log,
    write_json,
)


@pytest.mark.parametrize("entry_kind", ["file", "directory", "symlink"])
def test_cli_runtime_removal_rejects_unknown_entries_before_provider_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    entry_kind: str,
) -> None:
    _root, agent = prepare_runtime(monkeypatch, tmp_path)
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
        cli.cmd_uninstall(uninstall_args())

    assert provider_calls == []
    assert unknown.exists() or unknown.is_symlink()
    assert (agent / "config.json").is_file()


def test_cli_skips_generic_cleanup_for_plugin_managed_runtime_removal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, agent = prepare_runtime(monkeypatch, tmp_path, agent_name="kiroide")
    provider_calls: list[str] = []

    class Plugin:
        manages_runtime_removal = True

        def uninstall(self, agent_id: str = "") -> None:
            provider_calls.append(agent_id)

    def reject_generic_prepare(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("generic runtime removal must stay unused")

    monkeypatch.setattr(cli, "_get_plugin", lambda _name: Plugin())
    monkeypatch.setattr(cli, "prepare_runtime_removal", reject_generic_prepare)

    cli.cmd_uninstall(uninstall_args("kiroide"))

    assert provider_calls == [AGENT_ID]
    assert (agent / "config.json").is_file()


def test_runtime_removal_rejects_config_identity_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, agent = prepare_runtime(monkeypatch, tmp_path)
    plan = prepare_runtime_removal(AGENT_ID, AGENT_NAME)
    assert plan is not None
    concurrent = {"agent_id": AGENT_ID, "agent_name": "cursor"}
    write_json(agent / "config.json", concurrent)

    with pytest.raises(OSError, match="changed"):
        commit_runtime_removal(plan)

    assert json.loads((agent / "config.json").read_text(encoding="utf-8")) == (
        concurrent
    )


def test_runtime_removal_treats_other_plugin_wrappers_as_unmanaged(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, agent = prepare_runtime(monkeypatch, tmp_path)
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
    root, agent = prepare_runtime(monkeypatch, tmp_path)
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
    _root, agent = prepare_runtime(monkeypatch, tmp_path)
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
    _root, agent = prepare_runtime(monkeypatch, tmp_path)
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
    root, agent = prepare_runtime(monkeypatch, tmp_path)
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
    root, agent = prepare_runtime(monkeypatch, tmp_path)
    expected_digest = write_error_log(agent / "error.log", chunks=32)
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
    _root, agent = prepare_runtime(monkeypatch, tmp_path)
    error_log = agent / "error.log"
    expected_digest = write_error_log(error_log, chunks=32)
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
    assert stream_digest(error_log) == expected_digest
    assert stat.S_IMODE(error_log.stat().st_mode) == expected_mode
    assert (agent / "config.json").is_file()
    assert list(agent.glob("*.opaque-rollback")) == []
