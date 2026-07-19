from __future__ import annotations

from collections.abc import Callable

import pytest

from elydora.plugins.claudecode import _is_elydora_hook as is_claude_hook
from elydora.plugins.gemini import _is_elydora_hook as is_gemini_hook
from elydora.plugins.letta import _is_elydora_hook as is_letta_hook


HookDetector = Callable[[dict, str], bool]


@pytest.mark.parametrize("detector", [is_claude_hook, is_gemini_hook, is_letta_hook])
def test_hook_detection_handles_only_string_commands(detector: HookDetector) -> None:
    assert detector({"command": 42}, "") is False
    assert detector({"hooks": [{"command": None}]}, "") is False
    assert detector({"hooks": [{"command": "run .elydora/agent-1/hook.py"}]}, "") is True
    assert detector(
        {"hooks": [{"command": "run .elydora/agent-1/hook.py"}]},
        "agent-2",
    ) is False
