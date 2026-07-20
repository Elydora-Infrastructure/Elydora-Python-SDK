from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess  # nosec B404

import pytest

from gemini_support import prepare_fixture


GEMINI_ENTRY = os.environ.get("ELYDORA_GEMINI_ENTRY")


@pytest.mark.skipif(
    not GEMINI_ENTRY,
    reason="set ELYDORA_GEMINI_ENTRY to the official Gemini CLI entry file",
)
def test_official_gemini_cli_accepts_installed_user_hooks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    node = shutil.which("node")
    assert node is not None
    environment = {
        **os.environ,
        "HOME": str(fixture.home_dir),
        "USERPROFILE": str(fixture.home_dir),
        "GEMINI_CLI_HOME": str(fixture.home_dir),
        "GEMINI_API_KEY": "official-loader-test-key",
        "GEMINI_TELEMETRY_ENABLED": "false",
        "OTEL_SDK_DISABLED": "true",
    }

    version = subprocess.run(  # nosec B603
        [node, str(GEMINI_ENTRY), "--version"],
        capture_output=True,
        check=False,
        cwd=fixture.project_dir,
        env=environment,
        text=True,
    )
    loaded = subprocess.run(  # nosec B603
        [node, str(GEMINI_ENTRY), "--skip-trust", "--list-extensions"],
        capture_output=True,
        check=False,
        cwd=fixture.project_dir,
        env=environment,
        text=True,
    )

    assert version.returncode == 0, version.stderr
    assert "0.51.0" in version.stdout
    assert loaded.returncode == 0, loaded.stderr
    output = (loaded.stdout + "\n" + loaded.stderr).lower()
    for message in (
        "invalid settings",
        "settings validation",
        "failed to parse",
        "hook configuration error",
    ):
        assert message not in output
