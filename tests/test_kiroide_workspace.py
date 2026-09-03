from __future__ import annotations

import json
import os
from pathlib import Path
import stat

import pytest

from elydora import cli
from elydora.plugins import (
    _transaction,
    kiroide_installation,
)
from elydora.plugins.base import InstallConfig

from kiroide_support import (
    AGENT_ID,
    PRIVATE_KEY,
    ROTATED_PRIVATE_KEY,
    legacy_document,
    legacy_runtime_config,
    prepare_fixture,
    prepare_installation,
    write_json,
)


def test_kiroide_runtime_config_binds_agent_to_absolute_workspace(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)

    runtime_config = json.loads(
        (fixture.agent_directory / "config.json").read_text(encoding="utf-8")
    )
    assert runtime_config["workspace_root"] == str(fixture.workspace.resolve())
    assert Path(runtime_config["workspace_root"]).is_absolute()


def test_kiroide_rejects_same_agent_install_from_another_workspace(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    original_hook = fixture.config_path.read_bytes()
    runtime_config_path = fixture.agent_directory / "config.json"
    original_runtime = runtime_config_path.read_bytes()
    second_workspace = tmp_path / "second workspace"
    second_workspace.mkdir()
    monkeypatch.chdir(second_workspace)

    with pytest.raises(ValueError, match="bound to another workspace"):
        fixture.plugin.install(fixture.config)

    assert fixture.config_path.read_bytes() == original_hook
    assert runtime_config_path.read_bytes() == original_runtime
    assert not (second_workspace / ".kiro").exists()


def test_kiroide_cli_uninstall_requires_bound_workspace(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    original_hook = fixture.config_path.read_bytes()
    second_workspace = tmp_path / "second workspace"
    second_workspace.mkdir()
    args = cli.build_parser().parse_args(
        [
            "uninstall",
            "--agent",
            "kiroide",
            "--agent_id",
            AGENT_ID,
        ]
    )
    monkeypatch.chdir(second_workspace)

    with pytest.raises(ValueError, match="bound to another workspace"):
        cli.cmd_uninstall(args)

    assert fixture.config_path.read_bytes() == original_hook
    assert fixture.agent_directory.exists()
    assert not (second_workspace / ".kiro").exists()

    monkeypatch.chdir(fixture.workspace)
    cli.cmd_uninstall(args)
    assert not fixture.config_path.exists()
    assert not fixture.agent_directory.exists()


def test_kiroide_install_claims_legacy_runtime_owner_from_matching_hooks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    runtime_config_path = fixture.agent_directory / "config.json"
    runtime_config = json.loads(runtime_config_path.read_text(encoding="utf-8"))
    runtime_config.pop("workspace_root")
    write_json(runtime_config_path, runtime_config)

    fixture.plugin.install(fixture.config)

    claimed = json.loads(runtime_config_path.read_text(encoding="utf-8"))
    assert claimed["workspace_root"] == str(fixture.workspace.resolve())


def test_kiroide_install_migrates_exact_global_legacy_runtime_owner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    write_json(fixture.legacy_path, legacy_document(fixture))
    runtime_config_path = fixture.agent_directory / "config.json"
    write_json(runtime_config_path, legacy_runtime_config(fixture))
    config = dict(fixture.config)
    config.pop("token")

    fixture.plugin.install(config)

    migrated = json.loads(runtime_config_path.read_text(encoding="utf-8"))
    assert migrated["workspace_root"] == str(fixture.workspace.resolve())
    assert "token" not in migrated
    assert fixture.config_path.exists()
    assert not fixture.legacy_path.exists()


def test_kiroide_legacy_owner_migration_rolls_back_runtime_claim(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    write_json(fixture.legacy_path, legacy_document(fixture))
    runtime_config_path = fixture.agent_directory / "config.json"
    original_runtime = legacy_runtime_config(fixture)
    write_json(runtime_config_path, original_runtime)
    original_capture = _transaction._capture_physical

    def fail_legacy_removal(
        source: str,
        destination: str,
        directory: _transaction.PinnedDirectory,
    ) -> None:
        if Path(source) == fixture.legacy_path and destination.endswith(
            ".rollback"
        ):
            raise OSError("injected legacy migration failure")
        original_capture(source, destination, directory)

    monkeypatch.setattr(_transaction, "_capture_physical", fail_legacy_removal)

    with pytest.raises(OSError, match="injected legacy migration failure"):
        fixture.plugin.install(fixture.config)

    assert json.loads(runtime_config_path.read_text(encoding="utf-8")) == (
        original_runtime
    )
    assert fixture.legacy_path.exists()
    assert not fixture.config_path.exists()


def test_kiroide_cli_uninstall_accepts_exact_global_legacy_ownership(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    write_json(fixture.legacy_path, legacy_document(fixture))
    write_json(
        fixture.agent_directory / "config.json",
        legacy_runtime_config(fixture),
    )
    args = cli.build_parser().parse_args(
        [
            "uninstall",
            "--agent",
            "kiroide",
            "--agent_id",
            AGENT_ID,
        ]
    )

    cli.cmd_uninstall(args)

    assert not fixture.legacy_path.exists()
    assert not fixture.agent_directory.exists()
    assert not fixture.config_path.exists()


def test_kiroide_rejects_unproved_legacy_runtime_owner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    write_json(fixture.legacy_path, legacy_document(fixture, "agent-2"))
    runtime_config_path = fixture.agent_directory / "config.json"
    original = legacy_runtime_config(fixture)
    write_json(runtime_config_path, original)

    with pytest.raises(ValueError, match="token is invalid"):
        fixture.plugin.install(fixture.config)

    assert json.loads(runtime_config_path.read_text(encoding="utf-8")) == original
    assert fixture.legacy_path.exists()
    assert not fixture.config_path.exists()


def test_kiroide_rejects_invalid_ownerless_legacy_runtime_config(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    write_json(fixture.legacy_path, legacy_document(fixture))
    runtime_config_path = fixture.agent_directory / "config.json"
    invalid = legacy_runtime_config(fixture)
    invalid["token"] = " "
    write_json(runtime_config_path, invalid)

    with pytest.raises(ValueError, match="token is invalid"):
        fixture.plugin.install(fixture.config)

    assert json.loads(runtime_config_path.read_text(encoding="utf-8")) == invalid
    assert fixture.legacy_path.exists()
    assert not fixture.config_path.exists()


@pytest.mark.parametrize(
    ("owner", "message"),
    [("relative", "must be absolute"), ("other", "bound to another workspace")],
)
def test_kiroide_status_rejects_invalid_runtime_workspace_owner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    owner: str,
    message: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    runtime_config_path = fixture.agent_directory / "config.json"
    runtime_config = json.loads(runtime_config_path.read_text(encoding="utf-8"))
    runtime_config["workspace_root"] = (
        "relative" if owner == "relative" else str((tmp_path / "other").resolve())
    )
    write_json(runtime_config_path, runtime_config)

    with pytest.raises(ValueError, match=message):
        fixture.plugin.status()


def test_kiroide_failed_install_removes_created_workspace_and_runtime_directories(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)

    def fail_first_commit(
        _source: str,
        _destination: str,
        _directory: _transaction.PinnedDirectory,
    ) -> None:
        raise OSError("injected Kiro IDE commit failure")

    monkeypatch.setattr(_transaction, "_replace_physical", fail_first_commit)

    with pytest.raises(OSError, match="injected Kiro IDE commit failure"):
        fixture.plugin.install(fixture.config)

    assert not (fixture.workspace / ".kiro").exists()
    # The durable transaction state directory survives failures by design;
    # everything else under the runtime root must be rolled back.
    elydora_root = fixture.home / ".elydora"
    if elydora_root.exists():
        assert [entry.name for entry in elydora_root.iterdir()] == ["transactions"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission contract")
@pytest.mark.parametrize("relative_path", ["private.key", "config.json"])
def test_kiroide_noop_install_pins_runtime_secret_modes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    relative_path: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    sources, paths, prepared, _rendered = prepare_installation(fixture)
    target = fixture.agent_directory / relative_path
    target.chmod(0o640)

    with pytest.raises(OSError, match="changed during Install Kiro IDE hooks"):
        kiroide_installation.commit_kiroide_installation(
            prepared, sources, paths
        )

    assert stat.S_IMODE(target.stat().st_mode) == 0o640


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission contract")
def test_kiroide_key_rotation_rejects_concurrent_mode_changes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    rotated = InstallConfig(**fixture.config)
    rotated["private_key"] = ROTATED_PRIVATE_KEY
    sources, paths, prepared, _rendered = prepare_installation(
        fixture, rotated
    )
    key_path = fixture.agent_directory / "private.key"
    assert any(change.file_path == str(key_path) for change in prepared.changes)
    key_path.chmod(0o640)

    with pytest.raises(OSError, match="changed during installation"):
        kiroide_installation.commit_kiroide_installation(
            prepared, sources, paths
        )

    assert key_path.read_text(encoding="utf-8") == PRIVATE_KEY
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o640


def test_kiroide_install_rejects_runtime_root_link_created_after_prepare(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    sources, paths, prepared, _rendered = prepare_installation(fixture)
    runtime_root = fixture.home / ".elydora"
    redirected_root = tmp_path / "redirected-runtime-root"
    redirected_root.mkdir()
    try:
        runtime_root.symlink_to(redirected_root, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"Directory symbolic links are unavailable: {error}")

    with pytest.raises(OSError, match="not a physical directory|changed during"):
        kiroide_installation.commit_kiroide_installation(
            prepared, sources, paths
        )

    assert not (redirected_root / AGENT_ID / "private.key").exists()
    assert not fixture.config_path.exists()


def test_kiroide_install_rejects_agent_directory_identity_swap(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.agent_directory.mkdir(parents=True)
    sources, paths, prepared, _rendered = prepare_installation(fixture)
    original_directory = fixture.agent_directory.with_name("agent-original")
    fixture.agent_directory.rename(original_directory)
    fixture.agent_directory.mkdir()

    with pytest.raises(OSError, match="changed during"):
        kiroide_installation.commit_kiroide_installation(
            prepared, sources, paths
        )

    assert not (fixture.agent_directory / "private.key").exists()
    assert not fixture.config_path.exists()
