from __future__ import annotations

import os
from pathlib import Path
import subprocess  # nosec B404

import pytest

from claudecode_support import prepare_fixture


CLAUDE_BINARY = os.environ.get("ELYDORA_CLAUDE_BINARY")


@pytest.mark.skipif(
    not CLAUDE_BINARY,
    reason="set ELYDORA_CLAUDE_BINARY to the official Claude Code executable",
)
def test_official_claude_code_accepts_installed_settings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    environment = {
        **os.environ,
        "HOME": str(fixture.home_dir),
        "USERPROFILE": str(fixture.home_dir),
        "CLAUDE_CONFIG_DIR": str(fixture.config_path.parent),
        "DISABLE_AUTOUPDATER": "1",
        "DISABLE_TELEMETRY": "1",
    }

    version = subprocess.run(
        [str(CLAUDE_BINARY), "--version"],
        capture_output=True,
        check=False,
        cwd=fixture.project_dir,
        env=environment,
        text=True,
    )
    doctor = subprocess.run(
        [str(CLAUDE_BINARY), "doctor"],
        capture_output=True,
        check=False,
        cwd=fixture.project_dir,
        env=environment,
        text=True,
    )

    assert version.returncode == 0, version.stderr
    assert "Claude Code" in version.stdout
    assert doctor.returncode == 0, doctor.stderr
    output = (doctor.stdout + "\n" + doctor.stderr).lower()
    assert "invalid settings" not in output
    assert "settings validation" not in output
    assert "failed to parse" not in output
