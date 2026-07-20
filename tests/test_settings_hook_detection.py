from __future__ import annotations

from pathlib import Path
import sys

import pytest

from elydora.plugins.letta_command import build_letta_command
from elydora.plugins.letta_contract import managed_letta_removals


def test_letta_hook_detection_requires_exact_owned_commands(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    home = tmp_path / "home"
    guard = home / ".elydora" / "agent-1" / "guard.py"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    hooks = {
        "PreToolUse": [{
            "matcher": "*",
            "hooks": [{
                "type": "command",
                "command": build_letta_command(str(guard)),
                "timeout": 10_000,
            }],
        }],
    }
    assert len(managed_letta_removals(hooks)) == 1

    hooks["PreToolUse"][0]["hooks"][0]["quiet"] = True
    assert managed_letta_removals(hooks) == []

    hooks["PreToolUse"][0]["hooks"][0] = {
        "type": "command",
        "command": f'"{sys.executable}" {guard}',
    }
    assert len(managed_letta_removals(hooks, "agent-1")) == 1
    assert managed_letta_removals(hooks, "agent-2") == []
