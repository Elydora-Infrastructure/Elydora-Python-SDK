from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess  # nosec B404

import pytest

from cline_support import prepare_fixture


CLINE_CORE_ENTRY = os.environ.get("ELYDORA_CLINE_CORE_ENTRY")
CLINE_ENTRY = os.environ.get("ELYDORA_CLINE_ENTRY")


@pytest.mark.skipif(
    not (CLINE_CORE_ENTRY and CLINE_ENTRY),
    reason=(
        "set ELYDORA_CLINE_CORE_ENTRY and ELYDORA_CLINE_ENTRY "
        "to official Cline files"
    ),
)
def test_official_cline_loader_discovers_both_managed_hooks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    node = shutil.which("node")
    assert node is not None
    assert CLINE_CORE_ENTRY is not None
    assert CLINE_ENTRY is not None
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()
    version = subprocess.run(  # nosec B603
        [node, CLINE_ENTRY, "--version"],
        cwd=fixture.project_dir,
        env=fixture.environment(),
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )
    assert version.returncode == 0, version.stderr
    assert version.stdout.strip() == "3.0.46"

    source = """
import { pathToFileURL } from 'node:url';
const { listHookConfigFiles } = await import(
  pathToFileURL(process.env.ELYDORA_CLINE_CORE_ENTRY).href
);
console.log(JSON.stringify(listHookConfigFiles(process.env.ELYDORA_WORKSPACE)));
"""
    environment = {
        **fixture.environment(),
        "ELYDORA_CLINE_CORE_ENTRY": CLINE_CORE_ENTRY,
        "ELYDORA_WORKSPACE": str(fixture.project_dir),
    }
    loaded = subprocess.run(  # nosec B603
        [node, "--input-type=module", "--eval", source],
        cwd=fixture.project_dir,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )

    assert loaded.returncode == 0, loaded.stderr
    assert json.loads(loaded.stdout) == [
        {
            "fileName": "PostToolUse",
            "hookEventName": "tool_result",
            "path": str(fixture.audit_wrapper),
        },
        {
            "fileName": "PreToolUse",
            "hookEventName": "tool_call",
            "path": str(fixture.guard_wrapper),
        },
    ]
