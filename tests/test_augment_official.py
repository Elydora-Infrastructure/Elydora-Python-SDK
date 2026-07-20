from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess  # nosec B404

import pytest

from augment_support import prepare_fixture


AUGGIE_ENTRY = os.environ.get("ELYDORA_AUGGIE_ENTRY")


@pytest.mark.skipif(
    AUGGIE_ENTRY is None,
    reason="set ELYDORA_AUGGIE_ENTRY to the official Auggie entry file",
)
def test_official_auggie_accepts_installed_user_hook_contract(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    node = shutil.which("node")
    assert node is not None
    assert AUGGIE_ENTRY is not None
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    environment = {
        **os.environ,
        "HOME": str(fixture.home_dir),
        "USERPROFILE": str(fixture.home_dir),
    }
    version = subprocess.run(  # nosec B603
        [node, AUGGIE_ENTRY, "--version"],
        capture_output=True,
        check=False,
        cwd=fixture.project_dir,
        env=environment,
        text=True,
        timeout=10,
    )
    assert version.returncode == 0, version.stderr
    assert "0.33.0" in version.stdout

    load = subprocess.run(  # nosec B603
        [node, AUGGIE_ENTRY, "tools", "list"],
        capture_output=True,
        check=False,
        cwd=fixture.project_dir,
        env=environment,
        text=True,
        timeout=15,
    )
    assert load.returncode == 0, load.stderr
    output = f"{load.stdout}\n{load.stderr}".lower()
    for error in (
        "invalid settings",
        "settings validation",
        "failed to parse",
        "hook configuration error",
    ):
        assert error not in output
