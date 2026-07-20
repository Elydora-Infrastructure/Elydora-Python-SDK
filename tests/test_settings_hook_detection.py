from __future__ import annotations

from elydora.plugins.letta import _is_elydora_hook as is_letta_hook


def test_hook_detection_handles_only_string_commands() -> None:
    assert is_letta_hook({"command": 42}, "") is False
    assert is_letta_hook({"hooks": [{"command": None}]}, "") is False
    assert is_letta_hook(
        {"hooks": [{"command": "run .elydora/agent-1/hook.py"}]}, ""
    ) is True
    assert is_letta_hook(
        {"hooks": [{"command": "run .elydora/agent-1/hook.py"}]},
        "agent-2",
    ) is False
