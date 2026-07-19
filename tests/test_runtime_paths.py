from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from elydora._runtime_paths import (
    ensure_private_directory,
    require_physical_directory,
    require_physical_file,
    resolve_agent_directory,
)
from elydora import cli


@pytest.mark.parametrize(
    "agent_id",
    [
        "../escape",
        "..\\escape",
        "C:escape",
        "agent.",
        "agent ",
        " agent",
        "CON",
        "COM¹.log",
        ".",
        "..",
    ],
)
def test_agent_directory_rejects_unsafe_cross_platform_names(
    tmp_path: Path,
    agent_id: str,
) -> None:
    with pytest.raises(ValueError, match="agent ID"):
        resolve_agent_directory(str(tmp_path / ".elydora"), agent_id)


def test_agent_directory_is_one_private_physical_child(tmp_path: Path) -> None:
    root = tmp_path / ".elydora"
    agent_dir = Path(resolve_agent_directory(str(root), "agent-1"))

    ensure_private_directory(str(root))
    ensure_private_directory(str(agent_dir))

    assert agent_dir == root / "agent-1"
    assert require_physical_directory(str(agent_dir)) is True
    if os.name != "nt":
        assert root.stat().st_mode & 0o777 == 0o700
        assert agent_dir.stat().st_mode & 0o777 == 0o700


def test_private_directory_rejects_symbolic_links(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "agent-link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"Directory symbolic links are unavailable: {error}")

    with pytest.raises(OSError, match="physical directory"):
        ensure_private_directory(str(link))
    with pytest.raises(OSError, match="physical directory"):
        require_physical_directory(str(link))


def test_runtime_config_rejects_symbolic_links(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "config.json"
    try:
        link.symlink_to(target)
    except OSError as error:
        pytest.skip(f"File symbolic links are unavailable: {error}")

    with pytest.raises(OSError, match="physical file"):
        require_physical_file(str(link))


def test_install_rejects_unsafe_agent_id_before_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    args = cli.build_parser().parse_args(
        [
            "install",
            "--agent",
            "opencode",
            "--org_id",
            "org-1",
            "--agent_id",
            "../escape",
            "--private_key_file",
            "unused",
            "--kid",
            "key-1",
        ]
    )

    with pytest.raises(SystemExit) as exc_info:
        cli.cmd_install(args)

    assert exc_info.value.code == 1
    assert "Invalid agent ID for local storage" in capsys.readouterr().err
    assert (tmp_path / ".elydora").exists() is False


def test_uninstall_validates_config_directory_before_plugin_changes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    runtime_dir = tmp_path / ".elydora" / "stored-directory"
    runtime_dir.mkdir(parents=True)
    (runtime_dir / "config.json").write_text(
        json.dumps({"agent_name": "opencode", "agent_id": "different-agent"}),
        encoding="utf-8",
    )
    plugin_calls: list[str] = []

    class Plugin:
        def uninstall(self, agent_id: str = "") -> None:
            plugin_calls.append(agent_id)

    monkeypatch.setattr(cli, "_get_plugin", lambda _name: Plugin())
    args = cli.build_parser().parse_args(["uninstall", "--agent", "opencode"])

    with pytest.raises(SystemExit) as exc_info:
        cli.cmd_uninstall(args)

    assert exc_info.value.code == 1
    assert "crosses its runtime directory" in capsys.readouterr().err
    assert plugin_calls == []
    assert runtime_dir.is_dir()


def test_uninstall_requires_explicit_id_for_ambiguous_runtimes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    for agent_id in ("agent-1", "agent-2"):
        runtime_dir = tmp_path / ".elydora" / agent_id
        runtime_dir.mkdir(parents=True)
        (runtime_dir / "config.json").write_text(
            json.dumps({"agent_name": "opencode", "agent_id": agent_id}),
            encoding="utf-8",
        )
    plugin_calls: list[str] = []

    class Plugin:
        def uninstall(self, agent_id: str = "") -> None:
            plugin_calls.append(agent_id)

    monkeypatch.setattr(cli, "_get_plugin", lambda _name: Plugin())
    args = cli.build_parser().parse_args(["uninstall", "--agent", "opencode"])

    with pytest.raises(SystemExit) as exc_info:
        cli.cmd_uninstall(args)

    assert exc_info.value.code == 1
    assert "Multiple installed agents" in capsys.readouterr().err
    assert plugin_calls == []
    assert (tmp_path / ".elydora" / "agent-1").is_dir()
    assert (tmp_path / ".elydora" / "agent-2").is_dir()


def test_explicit_uninstall_validates_agent_ownership_before_plugin_changes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    runtime_dir = tmp_path / ".elydora" / "agent-1"
    runtime_dir.mkdir(parents=True)
    (runtime_dir / "config.json").write_text(
        json.dumps({"agent_name": "codex", "agent_id": "agent-1"}),
        encoding="utf-8",
    )
    plugin_calls: list[str] = []

    class Plugin:
        def uninstall(self, agent_id: str = "") -> None:
            plugin_calls.append(agent_id)

    monkeypatch.setattr(cli, "_get_plugin", lambda _name: Plugin())
    args = cli.build_parser().parse_args(
        ["uninstall", "--agent", "opencode", "--agent_id", "agent-1"]
    )

    with pytest.raises(SystemExit) as exc_info:
        cli.cmd_uninstall(args)

    assert exc_info.value.code == 1
    assert "belongs to codex" in capsys.readouterr().err
    assert plugin_calls == []
    assert runtime_dir.is_dir()
