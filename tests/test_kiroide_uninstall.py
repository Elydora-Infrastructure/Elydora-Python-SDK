from __future__ import annotations

import json
from pathlib import Path

import pytest

from elydora.plugins import (
    _transaction,
    kiroide_installation,
)
from elydora.plugins.base import InstallConfig

from kiroide_support import (
    AGENT_ID,
    PRIVATE_KEY,
    ROTATED_PRIVATE_KEY,
    find_hook,
    legacy_document,
    prepare_fixture,
    prepare_installation,
    write_json,
    write_large_error_log,
    write_legacy_runtime,
)


def test_kiroide_uninstall_removes_exact_ownership_and_preserves_user_hooks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    user_hook = {
        "name": "workspace-context",
        "trigger": "SessionStart",
        "action": {"type": "agent", "prompt": "Read AGENTS.md"},
    }
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        current={"version": "v1", "owner": "workspace", "hooks": [user_hook]},
    )
    fixture.plugin.install(fixture.config)

    fixture.plugin.uninstall("agent-2")
    assert len(json.loads(fixture.config_path.read_text())["hooks"]) == 3
    assert fixture.agent_directory.exists()
    assert (fixture.agent_directory / "private.key").read_text(
        encoding="utf-8"
    ) == PRIVATE_KEY
    fixture.plugin.uninstall(AGENT_ID)
    assert json.loads(fixture.config_path.read_text(encoding="utf-8")) == {
        "version": "v1",
        "owner": "workspace",
        "hooks": [user_hook],
    }

    owned = prepare_fixture(monkeypatch, tmp_path / "owned")
    owned.plugin.install(owned.config)
    owned.plugin.uninstall(AGENT_ID)
    assert not owned.config_path.exists()


def test_kiroide_uninstall_without_agent_id_removes_owned_runtime(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)

    fixture.plugin.uninstall()

    assert not fixture.config_path.exists()
    assert not fixture.agent_directory.exists()
    assert not (fixture.agent_directory / "private.key").exists()


def test_kiroide_uninstall_without_agent_id_removes_current_and_legacy_runtimes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    legacy_agent_id = "agent-2"
    legacy_directory = write_legacy_runtime(fixture, legacy_agent_id)
    write_json(fixture.legacy_path, legacy_document(fixture, legacy_agent_id))

    fixture.plugin.uninstall()

    assert not fixture.config_path.exists()
    assert not fixture.legacy_path.exists()
    assert not fixture.agent_directory.exists()
    assert not legacy_directory.exists()
    assert not (legacy_directory / "private.key").exists()


def test_kiroide_no_id_uninstall_streams_all_oversized_error_logs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    current_error = write_large_error_log(
        fixture.agent_directory,
        b"current runtime error\n",
    )
    legacy_agent_id = "agent-2"
    legacy_directory = write_legacy_runtime(fixture, legacy_agent_id)
    legacy_error = write_large_error_log(
        legacy_directory,
        b"legacy runtime error\n",
    )
    write_json(fixture.legacy_path, legacy_document(fixture, legacy_agent_id))

    fixture.plugin.uninstall()

    assert not current_error.exists()
    assert not legacy_error.exists()
    assert not fixture.agent_directory.exists()
    assert not legacy_directory.exists()


def test_kiroide_uninstall_without_agent_id_deduplicates_current_and_legacy_owner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    write_json(fixture.legacy_path, legacy_document(fixture))

    fixture.plugin.uninstall()

    assert not fixture.config_path.exists()
    assert not fixture.legacy_path.exists()
    assert not fixture.agent_directory.exists()


def test_kiroide_uninstall_without_agent_id_rejects_unknown_runtime_before_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    legacy_agent_id = "agent-2"
    legacy_directory = write_legacy_runtime(fixture, legacy_agent_id)
    write_json(fixture.legacy_path, legacy_document(fixture, legacy_agent_id))
    unknown = legacy_directory / "user-data.txt"
    unknown.write_text("preserve\n", encoding="utf-8")
    original_provider = fixture.config_path.read_bytes()
    original_legacy = fixture.legacy_path.read_bytes()
    original_key = (fixture.agent_directory / "private.key").read_bytes()
    original_legacy_key = (legacy_directory / "private.key").read_bytes()

    with pytest.raises(OSError, match="contains unmanaged entries"):
        fixture.plugin.uninstall()

    assert fixture.config_path.read_bytes() == original_provider
    assert fixture.legacy_path.read_bytes() == original_legacy
    assert (fixture.agent_directory / "private.key").read_bytes() == original_key
    assert (legacy_directory / "private.key").read_bytes() == original_legacy_key
    assert unknown.read_text(encoding="utf-8") == "preserve\n"


def test_kiroide_uninstall_without_agent_id_rolls_back_provider_and_runtime(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    runtime_paths = [
        fixture.guard_path,
        fixture.audit_path,
        fixture.agent_directory / "private.key",
        fixture.agent_directory / "config.json",
    ]
    original_provider = fixture.config_path.read_bytes()
    original_runtime = {path: path.read_bytes() for path in runtime_paths}
    original_capture = _transaction._capture_physical

    def fail_private_key_removal(
        source: str,
        destination: str,
        directory: _transaction.PinnedDirectory,
    ) -> None:
        if Path(source) == fixture.agent_directory / "private.key" and (
            destination.endswith(".rollback")
        ):
            raise OSError("injected private key removal failure")
        original_capture(source, destination, directory)

    monkeypatch.setattr(_transaction, "_capture_physical", fail_private_key_removal)

    with pytest.raises(OSError, match="injected private key removal failure"):
        fixture.plugin.uninstall()

    assert fixture.config_path.read_bytes() == original_provider
    assert {path: path.read_bytes() for path in runtime_paths} == original_runtime


def test_kiroide_transaction_rolls_back_when_legacy_cleanup_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    original = {"version": "v1", "owner": "workspace", "hooks": []}
    fixture = prepare_fixture(monkeypatch, tmp_path, current=original)
    write_json(fixture.legacy_path, legacy_document(fixture))
    original_capture = _transaction._capture_physical

    def fail_legacy_removal(
        source: str,
        destination: str,
        directory: _transaction.PinnedDirectory,
    ) -> None:
        if Path(source) == fixture.legacy_path and destination.endswith(".rollback"):
            raise OSError("injected legacy cleanup failure")
        original_capture(source, destination, directory)

    monkeypatch.setattr(_transaction, "_capture_physical", fail_legacy_removal)

    with pytest.raises(OSError, match="injected legacy cleanup failure"):
        fixture.plugin.install(fixture.config)

    assert json.loads(fixture.config_path.read_text(encoding="utf-8")) == original
    assert fixture.legacy_path.exists()
    for path in (
        fixture.guard_path,
        fixture.audit_path,
        fixture.agent_directory / "config.json",
        fixture.agent_directory / "private.key",
    ):
        assert not path.exists()
    leftovers = list(fixture.config_path.parent.glob(".*.tmp"))
    leftovers += list(fixture.config_path.parent.glob(".*.rollback"))
    assert leftovers == []


@pytest.mark.parametrize("swapped", ["workspace", "kiro", "hooks"])
def test_kiroide_transaction_rejects_provider_directory_identity_swaps(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    swapped: str,
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        current={"version": "v1", "hooks": []},
    )
    sources, paths, prepared, _rendered = prepare_installation(fixture)
    monkeypatch.chdir(tmp_path)
    original_paths = {
        "workspace": fixture.workspace,
        "kiro": fixture.workspace / ".kiro",
        "hooks": fixture.workspace / ".kiro" / "hooks",
    }
    original = original_paths[swapped]
    backup = original.with_name(original.name + "-original")
    replacement = tmp_path / f"redirected-{swapped}"
    if swapped == "workspace":
        (replacement / ".kiro" / "hooks").mkdir(parents=True)
        redirected_config = replacement / ".kiro" / "hooks" / "elydora-audit.json"
    elif swapped == "kiro":
        (replacement / "hooks").mkdir(parents=True)
        redirected_config = replacement / "hooks" / "elydora-audit.json"
    else:
        replacement.mkdir()
        redirected_config = replacement / "elydora-audit.json"
    original.rename(backup)
    try:
        original.symlink_to(replacement, target_is_directory=True)
    except OSError as error:
        backup.rename(original)
        pytest.skip(f"Directory symbolic links are unavailable: {error}")

    with pytest.raises(OSError, match="not a physical directory|changed during"):
        kiroide_installation.commit_kiroide_installation(
            prepared, sources, paths
        )

    assert not redirected_config.exists()
    assert not fixture.agent_directory.exists()


def test_kiroide_key_rotation_pins_unchanged_provider_sources(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    original_key = (fixture.agent_directory / "private.key").read_text(
        encoding="utf-8"
    )
    rotated = InstallConfig(**fixture.config)
    rotated["private_key"] = ROTATED_PRIVATE_KEY
    sources, paths, prepared, rendered = prepare_installation(fixture, rotated)
    assert rendered.changed is False
    document = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    document["concurrent_change"] = True
    write_json(fixture.config_path, document)

    with pytest.raises(OSError, match="Kiro IDE hooks changed during"):
        kiroide_installation.commit_kiroide_installation(
            prepared, sources, paths
        )

    assert (fixture.agent_directory / "private.key").read_text(
        encoding="utf-8"
    ) == original_key
    assert json.loads(fixture.config_path.read_text(encoding="utf-8"))[
        "concurrent_change"
    ] is True


def test_kiroide_noop_install_rejects_concurrent_provider_changes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    sources, paths, prepared, rendered = prepare_installation(fixture)
    assert prepared.changes == []
    assert rendered.changed is False
    document = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    find_hook(document, "elydora-guard")["enabled"] = False
    write_json(fixture.config_path, document)

    with pytest.raises(OSError, match="Kiro IDE hooks changed during"):
        kiroide_installation.commit_kiroide_installation(
            prepared, sources, paths
        )

    assert find_hook(
        json.loads(fixture.config_path.read_text(encoding="utf-8")),
        "elydora-guard",
    )["enabled"] is False


@pytest.mark.parametrize(
    "relative_path",
    ["private.key", "config.json", "guard.py", "hook.py"],
)
def test_kiroide_noop_install_pins_every_runtime_source(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    relative_path: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    sources, paths, prepared, _rendered = prepare_installation(fixture)
    assert prepared.changes == []
    assert len(prepared.runtime_preconditions) == 4
    target = fixture.agent_directory / relative_path
    concurrent = target.read_text(encoding="utf-8") + "\nconcurrent-change"
    target.write_text(concurrent, encoding="utf-8")

    with pytest.raises(OSError, match="changed during Install Kiro IDE hooks"):
        kiroide_installation.commit_kiroide_installation(
            prepared, sources, paths
        )

    assert target.read_text(encoding="utf-8") == concurrent
