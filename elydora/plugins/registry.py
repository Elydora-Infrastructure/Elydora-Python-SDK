"""Supported agent registry."""

from __future__ import annotations

from typing import Dict


SUPPORTED_AGENTS: Dict[str, Dict[str, str]] = {
    "claudecode": {
        "name": "Claude Code",
        "hook_event": "PostToolUse",
        "config_path": "~/.claude/settings.json",
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
    "augment": {
        "name": "Augment Code",
        "hook_event": "PostToolUse",
        "config_path": "~/.augment/settings.json",
    },
    "kiro": {
        "name": "Kiro",
        "hook_event": "PostToolUse",
        "config_path": "~/.kiro/hooks/",
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
