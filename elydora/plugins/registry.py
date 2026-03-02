"""Supported agent registry."""

from __future__ import annotations

from typing import Dict


SUPPORTED_AGENTS: Dict[str, Dict[str, str]] = {
    "claudecode": {
        "name": "Claude Code",
        "hook_event": "PostToolUse",
        "config_path": "~/.claude/settings.json",
    },
    "copilot": {
        "name": "Copilot CLI",
        "hook_event": "PostToolUse",
        "config_path": ".github/hooks/hooks.json",
    },
    "cursor": {
        "name": "Cursor",
        "hook_event": "PostToolUse",
        "config_path": "~/.cursor/hooks.json",
    },
    "gemini": {
        "name": "Gemini CLI",
        "hook_event": "AfterTool",
        "config_path": "~/.gemini/settings.json",
    },
    "kirocli": {
        "name": "Kiro CLI",
        "hook_event": "PostToolUse",
        "config_path": "~/.kiro/settings.json",
    },
    "kiroide": {
        "name": "Kiro IDE",
        "hook_event": "PostToolUse",
        "config_path": "~/.kiro/hooks/",
    },
    "letta": {
        "name": "Letta Code",
        "hook_event": "PostToolUse",
        "config_path": "~/.letta/settings.json",
    },
    "opencode": {
        "name": "OpenCode",
        "hook_event": "PostToolUse",
        "config_path": "~/.opencode/plugins/",
    },
}


def get_agent_names() -> list[str]:
    """Return sorted list of supported agent names."""
    return sorted(SUPPORTED_AGENTS.keys())
