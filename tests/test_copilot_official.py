from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from copilot_support import prepare_fixture


COPILOT_ENTRY = os.environ.get("ELYDORA_COPILOT_ENTRY")
COPILOT_RUNTIME_ENTRY = os.environ.get("ELYDORA_COPILOT_RUNTIME_ENTRY")
NODE = shutil.which("node")


@pytest.mark.skipif(
    not COPILOT_ENTRY or not COPILOT_RUNTIME_ENTRY or not NODE,
    reason=(
        "set ELYDORA_COPILOT_ENTRY and ELYDORA_COPILOT_RUNTIME_ENTRY "
        "to official package files"
    ),
)
def test_official_copilot_1_0_71_loads_all_three_managed_hooks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.plugin.install(fixture.config)
    environment = {
        **os.environ,
        "HOME": str(fixture.home_dir),
        "USERPROFILE": str(fixture.home_dir),
        "COPILOT_HOME": str(fixture.copilot_home),
    }
    version = subprocess.run(
        [str(NODE), str(COPILOT_ENTRY), "--version"],
        capture_output=True,
        check=False,
        cwd=fixture.project_dir,
        env=environment,
        text=True,
    )
    assert version.returncode == 0, version.stderr
    assert "GitHub Copilot CLI 1.0.71." in version.stdout

    source = """
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const runtime = require(process.env.ELYDORA_COPILOT_RUNTIME_ENTRY);
const session = await runtime.hookSessionCreate({
  cwd: process.env.ELYDORA_PROJECT,
  repoRoot: process.env.ELYDORA_PROJECT,
  sessionId: 'elydora-python-official-test',
  settingsJson: '{}',
  userHooksDir: process.env.ELYDORA_HOOKS,
  allowLocalhost: false,
  allowHttpAuthHooks: false,
  discoverPolicies: false,
});
try {
  const snapshot = JSON.parse(await runtime.hookSessionSnapshot(session.handle));
  console.log(JSON.stringify({ load: session.load, snapshot }));
} finally {
  runtime.hookSessionDispose(session.handle);
}
"""
    loaded = subprocess.run(
        [str(NODE), "--input-type=module", "--eval", source],
        capture_output=True,
        check=False,
        cwd=fixture.project_dir,
        env={
            **environment,
            "ELYDORA_COPILOT_RUNTIME_ENTRY": str(COPILOT_RUNTIME_ENTRY),
            "ELYDORA_HOOKS": str(fixture.config_path.parent),
            "ELYDORA_PROJECT": str(fixture.project_dir),
        },
        text=True,
    )
    assert loaded.returncode == 0, loaded.stderr
    result = json.loads(loaded.stdout)
    assert result["load"]["hookCount"] == 3
    assert result["load"]["errors"] == []
    assert result["load"]["warnings"] == []
    hooks = result["snapshot"]["hooks"]
    assert sorted(hook["eventName"] for hook in hooks) == [
        "postToolUse",
        "postToolUseFailure",
        "preToolUse",
    ]
    for hook in hooks:
        assert Path(hook["source"]).name == "elydora-audit.json"
        spec = json.loads(hook["specJson"])
        assert spec["config"]["type"] == "command"
        assert spec["config"]["timeoutSec"] == 10
        assert "python" in spec["config"]["bash"].lower()
        assert spec["config"]["powershell"].startswith("& ")
