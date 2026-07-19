"""Supported agent registry."""

from __future__ import annotations

from typing import Dict


SUPPORTED_AGENTS: Dict[str, Dict[str, str]] = {
    "claudecode": {
        "name": "Claude Code",
        "hook_event": "PostToolUse",
        "config_path": "~/.claude/settings.json",
    },
    "codex": {
        "name": "OpenAI Codex",
        "hook_event": "PreToolUse/PostToolUse",
        "config_path": "~/.codex/hooks.json",
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
        "hook_event": "PreToolUse/PostToolUse",
        "config_path": "~/.kiro/hooks/elydora-audit.json",
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
        "hook_event": "tool.execute.after",
        "config_path": "~/.config/opencode/plugins/",
    },
}


def get_agent_names() -> list[str]:
    """Return sorted list of supported agent names."""
    return sorted(SUPPORTED_AGENTS.keys())
