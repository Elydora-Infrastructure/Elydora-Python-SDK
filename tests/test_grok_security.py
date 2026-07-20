from __future__ import annotations

import os
from pathlib import Path
import subprocess  # nosec B404
import sys

import pytest

from grok_support import (
    AGENT_ID,
    VALID_PRIVATE_KEY,
    prepare_fixture,
    write_text,
)


def symlink_or_skip(
    target: Path, link: Path, *, directory: bool = False
) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as error:
        pytest.skip(f"Symbolic links unavailable: {error}")


def test_install_rejects_linked_hook_file_before_runtime_creation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    target = tmp_path / "hooks-target.json"
    source = '{"owner":"protected"}\n'
    write_text(target, source)
    fixture.config_path.parent.mkdir(parents=True)
    symlink_or_skip(target, fixture.config_path)

    with pytest.raises(OSError, match="not a physical file"):
        fixture.install()

    assert target.read_text(encoding="utf-8") == source
    assert not fixture.agent_dir.exists()


@pytest.mark.parametrize("kind", ["home", "hooks", "runtime"])
def test_install_rejects_linked_directories_before_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    kind: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    target = tmp_path / f"{kind}-target"
    target.mkdir()
    if kind == "home":
        link = fixture.grok_home
        (target / "hooks").mkdir()
    elif kind == "hooks":
        link = fixture.config_path.parent
        fixture.grok_home.mkdir(parents=True)
    else:
        link = fixture.agent_dir.parent
    link.parent.mkdir(parents=True, exist_ok=True)
    symlink_or_skip(target, link, directory=True)

    with pytest.raises(OSError, match="physical directory"):
        fixture.install()

    untouched = fixture.config_path if kind == "runtime" else fixture.agent_dir
    assert not untouched.exists()


def test_status_rejects_linked_private_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    target = tmp_path / "private-key-target"
    source = fixture.private_key_path.read_text(encoding="utf-8")
    write_text(target, source)
    fixture.private_key_path.unlink()
    symlink_or_skip(target, fixture.private_key_path)

    with pytest.raises(OSError, match="not a physical file"):
        fixture.plugin.status()

    assert target.read_text(encoding="utf-8") == source


def test_preflight_inspects_every_runtime_artifact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.agent_dir.mkdir(parents=True)
    write_text(fixture.guard_path, "orphaned guard\n", 0o700)
    target = tmp_path / "linked-audit-target"
    write_text(target, "linked audit\n", 0o700)
    symlink_or_skip(target, fixture.hook_path)

    with pytest.raises(OSError, match="not a physical file"):
        fixture.install()

    assert target.read_text(encoding="utf-8") == "linked audit\n"
    assert not fixture.config_path.exists()


@pytest.mark.parametrize("kind", ["orphaned", "mismatched"])
def test_install_rejects_unverifiable_runtime_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    kind: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.agent_dir.mkdir(parents=True)
    if kind == "orphaned":
        write_text(fixture.guard_path, "orphaned guard\n", 0o700)
    else:
        write_text(
            fixture.runtime_config_path,
            '{"agent_name":"grok","agent_id":"another-agent"}\n',
        )

    pattern = (
        "identity cannot be verified"
        if kind == "orphaned"
        else "identity does not match"
    )
    with pytest.raises(ValueError, match=pattern):
        fixture.install()

    assert not fixture.config_path.exists()


@pytest.mark.parametrize(
    ("field", "value", "pattern"),
    [
        ("agent_name", "codex", "requires agent_name grok"),
        ("agent_id", "../escape", "Invalid agent ID"),
        ("private_key", "invalid", "canonical 32-byte"),
        ("token", "", "non-empty string"),
        (
            "base_url",
            "https://api.elydora.com/path?token=secret",
            "query parameters",
        ),
        ("guard_script_path", "outside", "managed agent directory"),
    ],
)
def test_install_validates_runtime_inputs_before_creating_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    field: str,
    value: str,
    pattern: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.config[field] = (
        str(fixture.home_dir / "outside" / "guard.py")
        if field == "guard_script_path"
        else value
    )

    with pytest.raises(ValueError, match=pattern):
        fixture.install()

    assert not fixture.config_path.exists()
    assert not fixture.agent_dir.exists()


def test_status_surfaces_malformed_runtime_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    fixture.runtime_config_path.write_text("{ malformed", encoding="utf-8")

    with pytest.raises(ValueError, match="parse Elydora runtime config"):
        fixture.plugin.status()


def test_cli_preflight_preserves_malformed_config_before_runtime_creation(
    tmp_path: Path,
) -> None:
    home_dir = tmp_path / "cli-home"
    config_path = home_dir / ".grok" / "hooks" / "elydora-audit.json"
    key_path = tmp_path / "private.key"
    write_text(config_path, "{ malformed")
    write_text(key_path, VALID_PRIVATE_KEY)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "elydora.cli",
            "install",
            "--agent",
            "grok",
            "--org_id",
            "org-1",
            "--agent_id",
            AGENT_ID,
            "--private_key_file",
            str(key_path),
            "--kid",
            "kid-1",
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
            "GROK_HOME": "",
        },
        text=True,
    )

    assert result.returncode == 1
    assert "parse Grok user hooks" in result.stderr
    assert config_path.read_text(encoding="utf-8") == "{ malformed"
    assert not (home_dir / ".elydora").exists()
