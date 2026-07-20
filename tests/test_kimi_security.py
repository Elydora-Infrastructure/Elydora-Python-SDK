from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess  # nosec B404
import sys

import pytest

from kimi_support import (
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


def test_install_rejects_linked_config_before_creating_runtimes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, legacy_detected=False)
    target = tmp_path / "config-target.toml"
    source = "# protected target\ntelemetry = false\n"
    write_text(target, source)
    fixture.stable_path.parent.mkdir(parents=True)
    symlink_or_skip(target, fixture.stable_path)

    with pytest.raises(OSError, match="not a physical file"):
        fixture.install()

    assert target.read_text(encoding="utf-8") == source
    assert not fixture.agent_dir.exists()


@pytest.mark.parametrize("kind", ["config", "runtime"])
def test_install_rejects_linked_config_and_runtime_directories(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    kind: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, legacy_detected=False)
    target = tmp_path / f"{kind}-target"
    target.mkdir()
    link = fixture.kimi_home if kind == "config" else fixture.agent_dir.parent
    if link.exists():
        shutil.rmtree(link)
    link.parent.mkdir(parents=True, exist_ok=True)
    symlink_or_skip(target, link, directory=True)

    with pytest.raises(OSError, match="physical directory"):
        fixture.install()

    assert list(target.iterdir()) == []
    untouched = fixture.agent_dir if kind == "config" else fixture.stable_path
    assert not untouched.exists()


def test_status_rejects_linked_private_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, legacy_detected=False)
    fixture.install()
    target = tmp_path / "private-key-target"
    source = fixture.private_key_path.read_text(encoding="utf-8")
    write_text(target, source)
    fixture.private_key_path.unlink()
    symlink_or_skip(target, fixture.private_key_path)

    with pytest.raises(OSError, match="not a physical file"):
        fixture.plugin.status()

    assert target.read_text(encoding="utf-8") == source


@pytest.mark.parametrize("kind", ["orphaned", "mismatched"])
def test_install_rejects_unverifiable_runtime_identity_before_config_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    kind: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, legacy_detected=False)
    fixture.agent_dir.mkdir(parents=True)
    if kind == "orphaned":
        write_text(fixture.guard_path, "orphaned guard\n", 0o700)
    else:
        write_text(
            fixture.runtime_config_path,
            '{"agent_name":"kimi","agent_id":"another-agent"}\n',
        )

    pattern = "identity cannot be verified" if kind == "orphaned" else "identity does not match"
    with pytest.raises(ValueError, match=pattern):
        fixture.install()

    assert not fixture.stable_path.exists()


@pytest.mark.parametrize(
    ("field", "value", "pattern"),
    [
        ("agent_name", "codex", "requires agent_name kimi"),
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
    fixture = prepare_fixture(monkeypatch, tmp_path, legacy_detected=False)
    fixture.config[field] = (
        str(fixture.home_dir / "outside" / "guard.py")
        if field == "guard_script_path"
        else value
    )

    with pytest.raises(ValueError, match=pattern):
        fixture.install()

    assert not fixture.stable_path.exists()
    assert not fixture.agent_dir.exists()


def test_status_surfaces_malformed_runtime_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, legacy_detected=False)
    fixture.install()
    fixture.runtime_config_path.write_text("{ malformed", encoding="utf-8")

    with pytest.raises(ValueError, match="parse Elydora runtime config"):
        fixture.plugin.status()


def test_cli_preflight_preserves_malformed_config_before_runtime_creation(
    tmp_path: Path,
) -> None:
    home_dir = tmp_path / "cli-home"
    config_path = home_dir / ".kimi-code" / "config.toml"
    key_path = tmp_path / "private.key"
    write_text(config_path, "[malformed")
    write_text(key_path, VALID_PRIVATE_KEY)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "elydora.cli",
            "install",
            "--agent",
            "kimi",
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
            "KIMI_CODE_HOME": "",
        },
        text=True,
    )

    assert result.returncode == 1
    assert "parse Kimi Code hooks config" in result.stderr
    assert config_path.read_text(encoding="utf-8") == "[malformed"
    assert not (home_dir / ".elydora").exists()
