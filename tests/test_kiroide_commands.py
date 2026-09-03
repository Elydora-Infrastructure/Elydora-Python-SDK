from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import stat

import pytest

from elydora.plugins._shell_command import is_python_executable, windows_powershell_path
from elydora.plugins import (
    kiroide_command,
)

from kiroide_support import (
    AGENT_ID,
    find_hook,
    managed_document,
    prepare_fixture,
    write_json,
)


def test_kiroide_exact_managed_commands_survive_python_relocation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    executable_name = "python.exe" if os.name == "nt" else "python3"
    fake_executable = tmp_path / "other-runtime" / executable_name
    with monkeypatch.context() as command_context:
        command_context.setattr(
            kiroide_command.sys, "executable", str(fake_executable)
        )
        guard_command = kiroide_command.build_kiroide_command(
            str(fixture.guard_path)
        )
        audit_command = kiroide_command.build_kiroide_command(
            str(fixture.audit_path)
        )
    stale_document = managed_document(guard_command, audit_command)
    write_json(fixture.config_path, stale_document)

    assert fixture.plugin.status() == {
        "installed": False,
        "agent": "kiroide",
        "details": (
            "Managed hooks are incomplete or invalid: "
            f"{fixture.config_path}"
        ),
    }

    fixture.plugin.install(fixture.config)
    repaired = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    assert kiroide_command.kiroide_runtime_reference(
        find_hook(repaired, "elydora-guard")["action"]["command"],
        "guard.py",
    ) is not None
    assert kiroide_command.kiroide_runtime_reference(
        find_hook(repaired, "elydora-audit")["action"]["command"],
        "hook.py",
    ) is not None

    write_json(fixture.config_path, stale_document)
    fixture.plugin.uninstall(AGENT_ID)

    assert not fixture.config_path.exists()


@pytest.mark.parametrize("damage", ["field", "orphan"])
def test_kiroide_stale_command_ownership_survives_contract_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    damage: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    executable_name = "python.exe" if os.name == "nt" else "python3"
    fake_executable = tmp_path / "other-runtime" / executable_name
    with monkeypatch.context() as command_context:
        command_context.setattr(
            kiroide_command.sys, "executable", str(fake_executable)
        )
        document = managed_document(
            kiroide_command.build_kiroide_command(str(fixture.guard_path)),
            kiroide_command.build_kiroide_command(str(fixture.audit_path)),
        )
    if damage == "field":
        find_hook(document, "elydora-guard")["timeout"] = 9
    else:
        document["hooks"].remove(find_hook(document, "elydora-audit"))
    write_json(fixture.config_path, document)

    fixture.plugin.install(fixture.config)
    repaired = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    assert len(repaired["hooks"]) == 2
    assert all(hook["timeout"] == 10 for hook in repaired["hooks"])

    write_json(fixture.config_path, document)
    fixture.plugin.uninstall(AGENT_ID)

    assert json.loads(fixture.config_path.read_text(encoding="utf-8"))[
        "hooks"
    ] == []


@pytest.mark.skipif(os.name != "nt", reason="Windows launcher contract")
def test_kiroide_current_commands_require_the_system_powershell_launcher(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    command = kiroide_command.build_kiroide_command(str(fixture.guard_path))
    expected = f'"{windows_powershell_path()}"'
    altered = command.replace(expected, r'"C:\Other\powershell.exe"', 1)

    assert kiroide_command.kiroide_runtime_reference(altered, "guard.py") is None


@pytest.mark.skipif(os.name != "nt", reason="Windows launcher contract")
def test_kiroide_windows_launcher_fails_when_python_is_missing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    missing_python = tmp_path / "missing-runtime" / "python.exe"
    script_path = tmp_path / "guard.py"
    with monkeypatch.context() as command_context:
        command_context.setattr(
            kiroide_command.sys, "executable", str(missing_python)
        )
        command = kiroide_command.build_kiroide_command(str(script_path))

    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 1
    assert result.stderr


@pytest.mark.parametrize(
    "executable_name",
    ["python3.13t", "python3.14t", "python3.13d.exe", "pypy3", "pypy3.10.exe"],
)
def test_kiroide_ownership_accepts_supported_python_runtime_names(
    executable_name: str,
) -> None:
    assert is_python_executable(executable_name)


def test_kiroide_builder_rejects_unrecoverable_executable_names(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    with monkeypatch.context() as command_context:
        command_context.setattr(
            kiroide_command.sys,
            "executable",
            str(tmp_path / "embedded-runtime"),
        )
        with pytest.raises(ValueError, match="absolute Python executable"):
            kiroide_command.build_kiroide_command(str(tmp_path / "guard.py"))


@pytest.mark.parametrize("damage", ["orphan", "duplicate", "altered"])
def test_kiroide_status_rejects_every_incomplete_managed_hook_set(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    damage: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    document = json.loads(fixture.config_path.read_text(encoding="utf-8"))
    audit = find_hook(document, "elydora-audit")
    if damage == "orphan":
        document["hooks"].remove(audit)
    elif damage == "duplicate":
        document["hooks"].append(copy.deepcopy(audit))
    else:
        find_hook(document, "elydora-guard")["timeout"] = 9
    write_json(fixture.config_path, document)

    status = fixture.plugin.status()
    assert status["installed"] is False
    assert status["details"] == (
        f"Managed hooks are incomplete or invalid: {fixture.config_path}"
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission contract")
@pytest.mark.parametrize(
    ("target", "message"),
    [
        ("key", "private key must be accessible only by its owner"),
        ("config", "Token-bearing Elydora runtime config must be accessible"),
    ],
)
def test_kiroide_repairs_and_enforces_owner_only_runtime_secrets(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    target: str,
    message: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    paths = {
        "key": fixture.agent_directory / "private.key",
        "config": fixture.agent_directory / "config.json",
    }
    paths[target].chmod(0o644)

    with pytest.raises(ValueError, match=message):
        fixture.plugin.status()

    fixture.plugin.install(fixture.config)
    assert stat.S_IMODE(paths[target].stat().st_mode) == 0o600
    assert fixture.plugin.status()["installed"] is True
