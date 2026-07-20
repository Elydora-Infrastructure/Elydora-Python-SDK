"""Supported agent registry."""

from __future__ import annotations

from typing import Dict


SUPPORTED_AGENTS: Dict[str, Dict[str, str]] = {
    "augment": {
        "name": "Augment Code CLI",
        "hook_event": "PreToolUse/PostToolUse",
        "config_path": "~/.augment/settings.json",
    },
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
    "cline": {
        "name": "Cline",
        "hook_event": "PreToolUse/PostToolUse",
        "config_path": "~/.cline/hooks/PreToolUse.mjs",
    },
    "copilot": {
        "name": "GitHub Copilot CLI",
        "hook_event": "preToolUse/postToolUse",
        "config_path": "~/.copilot/hooks/elydora-audit.json",
    },
    "cursor": {
        "name": "Cursor",
        "hook_event": "PostToolUse",
        "config_path": "~/.cursor/hooks.json",
    },
    "droid": {
        "name": "Factory Droid",
        "hook_event": "PreToolUse/PostToolUse",
        "config_path": "~/.factory/hooks.json",
    },
    "gemini": {
        "name": "Gemini CLI",
        "hook_event": "AfterTool",
        "config_path": "~/.gemini/settings.json",
    },
    "grok": {
        "name": "Grok Build",
        "hook_event": "PreToolUse/PostToolUse",
        "config_path": "~/.grok/hooks/elydora-audit.json",
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
    "kimi": {
        "name": "Kimi Code",
        "hook_event": "PreToolUse/PostToolUse",
        "config_path": "~/.kimi-code/config.toml",
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
    "qwen": {
        "name": "Qwen Code",
        "hook_event": "PreToolUse/PostToolUse",
        "config_path": "~/.qwen/settings.json",
    },
}


def get_agent_names() -> list[str]:
    """Return sorted list of supported agent names."""
    return sorted(SUPPORTED_AGENTS.keys())
