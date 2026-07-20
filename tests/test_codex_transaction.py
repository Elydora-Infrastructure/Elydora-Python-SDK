from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess  # nosec B404
import sys

import pytest

from codex_support import (
    AGENT_ID,
    VALID_PRIVATE_KEY,
    prepare_fixture,
    symlink_or_skip,
    write_json,
    write_text,
)
from elydora.plugins import codex


def assert_no_transaction_files(root: Path) -> None:
    assert not list(root.rglob("*.tmp"))
    assert not list(root.rglob("*.rollback"))


def test_transaction_rolls_back_all_five_files_when_hooks_commit_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        existing_config={"hooks": {"SessionStart": []}},
    )
    original = fixture.config_path.read_text(encoding="utf-8")
    real_replace = os.replace
    failed = False

    def fail_hooks_once(source: str, destination: str) -> None:
        nonlocal failed
        if os.path.abspath(destination) == str(fixture.config_path) and not failed:
            failed = True
            raise OSError("injected hooks commit failure")
        real_replace(source, destination)

    monkeypatch.setattr(os, "replace", fail_hooks_once)

    with pytest.raises(OSError, match="injected hooks commit failure"):
        fixture.install()

    assert fixture.config_path.read_text(encoding="utf-8") == original
    for path in (
        fixture.guard_path,
        fixture.hook_path,
        fixture.runtime_config_path,
        fixture.private_key_path,
    ):
        assert path.exists() is False
    assert_no_transaction_files(fixture.home_dir)


def test_install_detects_a_concurrent_hooks_change_before_staging(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        existing_config={"hooks": {"SessionStart": []}},
    )
    concurrent = '{"hooks":{"SessionStart":[{"hooks":[]}]}}\n'
    real_rendered_change = codex.rendered_change

    def mutate_before_change(rendered: object):
        write_text(fixture.config_path, concurrent)
        return real_rendered_change(rendered)  # type: ignore[arg-type]

    monkeypatch.setattr(codex, "rendered_change", mutate_before_change)

    with pytest.raises(OSError, match="changed before staging"):
        fixture.install()

    assert fixture.config_path.read_text(encoding="utf-8") == concurrent
    assert list(fixture.agent_dir.iterdir()) == []
    assert_no_transaction_files(fixture.home_dir)


@pytest.mark.parametrize(
    "runtime_name",
    [
        "private.key",
        "guard.py",
        "hook.py",
        "chain-state.json",
        "status-cache.json",
        "error.log",
    ],
)
def test_orphan_runtime_artifacts_are_rejected_before_hooks_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    runtime_name: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    artifact = fixture.agent_dir / runtime_name
    write_text(artifact, "orphan\n")

    with pytest.raises(ValueError, match="identity cannot be verified"):
        fixture.install()

    assert artifact.read_text(encoding="utf-8") == "orphan\n"
    assert fixture.config_path.exists() is False


def test_mismatched_runtime_identity_is_rejected_before_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    write_json(
        fixture.runtime_config_path,
        {"agent_id": "another-agent", "agent_name": "codex"},
    )
    original = fixture.runtime_config_path.read_text(encoding="utf-8")

    with pytest.raises(ValueError, match="identity does not match"):
        fixture.install()

    assert fixture.runtime_config_path.read_text(encoding="utf-8") == original
    assert fixture.config_path.exists() is False


@pytest.mark.parametrize("kind", ["codex", "runtime"])
def test_linked_hooks_and_runtime_directories_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    kind: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    target = tmp_path / f"{kind}-target"
    target.mkdir()
    if kind == "codex":
        link = fixture.config_path.parent
    else:
        link = fixture.agent_dir.parent
        shutil.rmtree(link)
    link.parent.mkdir(parents=True, exist_ok=True)
    symlink_or_skip(target, link, directory=True)

    with pytest.raises(OSError, match="physical directory"):
        fixture.install()

    assert list(target.iterdir()) == []
    assert fixture.config_path.exists() is False


def test_uninstall_rejects_a_linked_default_hooks_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    codex_directory = fixture.config_path.parent
    target = tmp_path / "codex-hooks-target"
    codex_directory.rename(target)
    symlink_or_skip(target, codex_directory, directory=True)

    with pytest.raises(OSError, match="physical directory"):
        fixture.plugin.uninstall(AGENT_ID)

    assert (target / "hooks.json").is_file()


def test_install_protects_credentials_and_cleans_transaction_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()

    assert_no_transaction_files(fixture.home_dir)
    if os.name != "nt":
        for path in (
            fixture.config_path,
            fixture.runtime_config_path,
            fixture.private_key_path,
        ):
            assert path.stat().st_mode & 0o777 == 0o600


def test_cli_preflight_preserves_malformed_hooks_before_runtime_creation(
    tmp_path: Path,
) -> None:
    home_dir = tmp_path / "cli-home"
    hooks_path = home_dir / ".codex" / "hooks.json"
    key_path = tmp_path / "private.key"
    write_text(hooks_path, "{ malformed")
    write_text(key_path, VALID_PRIVATE_KEY)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "elydora.cli",
            "install",
            "--agent",
            "codex",
            "--org_id",
            "org-1",
            "--agent_id",
            AGENT_ID,
            "--private_key_file",
            str(key_path),
            "--kid",
            "key-1",
            "--base_url",
            "https://api.elydora.com",
        ],
        capture_output=True,
        check=False,
        cwd=Path(__file__).parents[1],
        env={
            **os.environ,
            "HOME": str(home_dir),
            "USERPROFILE": str(home_dir),
            "CODEX_HOME": "",
        },
        text=True,
    )

    assert result.returncode == 1
    assert "parse Codex user hooks" in result.stderr
    assert hooks_path.read_text(encoding="utf-8") == "{ malformed"
    assert (home_dir / ".elydora").exists() is False
