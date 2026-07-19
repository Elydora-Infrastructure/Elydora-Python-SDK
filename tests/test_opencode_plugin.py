from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import time

import pytest

from elydora.plugins import opencode
from elydora.plugins.registry import SUPPORTED_AGENTS


AGENT_ID = "agent-1"


def install_plugin(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[Path, Path, Path]:
    plugin_dir = tmp_path / ".config" / "opencode" / "plugins"
    elydora_dir = tmp_path / ".elydora"
    monkeypatch.setattr(opencode, "PLUGIN_DIR", str(plugin_dir))
    monkeypatch.setattr(opencode, "ELYDORA_DIR", str(elydora_dir))

    agent_dir = elydora_dir / AGENT_ID
    agent_dir.mkdir(parents=True)
    guard_path = agent_dir / "guard.py"
    guard_path.write_text(
        "import sys\nsys.stderr.write('Agent is frozen by Elydora.')\nraise SystemExit(2)\n",
        encoding="utf-8",
    )

    plugin = opencode.OpenCodePlugin()
    plugin.install({
        "agent_id": AGENT_ID,
        "agent_name": "opencode",
        "org_id": "org-1",
        "private_key": "test-key",
        "kid": "kid-1",
        "base_url": "https://api.elydora.test",
        "guard_script_path": str(guard_path),
    })
    return plugin_dir / "elydora-audit.mjs", agent_dir / "hook.py", guard_path


def run_node(script: str, home_dir: Path) -> subprocess.CompletedProcess[str]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required to execute generated OpenCode plugins")
    env = {
        **os.environ,
        "HOME": str(home_dir),
        "USERPROFILE": str(home_dir),
    }
    return subprocess.run(
        [node, "--input-type=module", "--eval", script],
        capture_output=True,
        check=False,
        env=env,
        text=True,
    )


def test_generated_opencode_plugin_uses_current_api_and_blocks_frozen_agent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    plugin_path, hook_path, _guard_path = install_plugin(monkeypatch, tmp_path)

    assert hook_path.is_file()
    module_url = plugin_path.as_uri()
    script = f"""
      const pluginModule = await import({json.dumps(module_url)});
      const hooks = await pluginModule.ElydoraAuditPlugin({{ project: {{ name: 'project' }} }});
      if (typeof hooks['tool.execute.before'] !== 'function') process.exit(10);
      if (typeof hooks['tool.execute.after'] !== 'function') process.exit(11);
      try {{
        await hooks['tool.execute.before'](
          {{ tool: 'bash', sessionID: 'session-1', callID: 'call-1' }},
          {{ args: {{ command: 'echo test' }} }},
        );
        process.exit(12);
      }} catch (error) {{
        if (!String(error.message).includes('Agent is frozen by Elydora')) process.exit(13);
      }}
    """

    result = run_node(script, tmp_path)

    assert result.returncode == 0, result.stderr
    assert opencode.OpenCodePlugin().status()["installed"] is True
    assert SUPPORTED_AGENTS["opencode"]["config_path"] == "~/.config/opencode/plugins/"


def test_generated_opencode_plugin_forwards_tool_event(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    plugin_path, hook_path, _guard_path = install_plugin(monkeypatch, tmp_path)
    capture_path = tmp_path / "captured-event.json"
    hook_path.write_text(
        "import pathlib, sys\n"
        f"pathlib.Path({str(capture_path)!r}).write_text(sys.stdin.read(), encoding='utf-8')\n",
        encoding="utf-8",
    )
    script = f"""
      const pluginModule = await import({json.dumps(plugin_path.as_uri())});
      const hooks = await pluginModule.ElydoraAuditPlugin({{ project: {{ name: 'project' }} }});
      await hooks['tool.execute.after'](
        {{
          tool: 'bash',
          sessionID: 'session-1',
          callID: 'call-1',
          args: {{ command: 'echo test' }},
        }},
        {{ title: 'Shell', output: 'test' }},
      );
    """

    result = run_node(script, tmp_path)
    assert result.returncode == 0, result.stderr

    deadline = time.monotonic() + 3
    while not capture_path.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert capture_path.is_file()
    event = json.loads(capture_path.read_text(encoding="utf-8"))
    assert event == {
        "tool_name": "bash",
        "tool_input": {"command": "echo test"},
        "session_id": "session-1",
    }
