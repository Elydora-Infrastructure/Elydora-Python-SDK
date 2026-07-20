"""GitHub Copilot CLI hook schema validation."""

from __future__ import annotations

import math
import os
import json
import shutil
import subprocess  # nosec B404 - validates official JavaScript regex syntax
from typing import Any, Dict, List
import urllib.parse


JsonObject = Dict[str, Any]
CopilotHooks = Dict[str, List[JsonObject]]

SUPPORTED_EVENTS = frozenset({
    "agentStop",
    "Stop",
    "errorOccurred",
    "ErrorOccurred",
    "notification",
    "Notification",
    "permissionRequest",
    "PermissionRequest",
    "postToolUse",
    "PostToolUse",
    "postToolUseFailure",
    "PostToolUseFailure",
    "preCompact",
    "PreCompact",
    "preToolUse",
    "PreToolUse",
    "sessionEnd",
    "SessionEnd",
    "sessionStart",
    "SessionStart",
    "subagentStart",
    "SubagentStart",
    "subagentStop",
    "SubagentStop",
    "userPromptSubmitted",
    "UserPromptSubmit",
    "userPromptTransformed",
})

_REGEX_TIMEOUT_SECONDS = 10
_REGEX_VALIDATOR = """import fs from "node:fs";
const entries = JSON.parse(fs.readFileSync(0, "utf8"));
for (const entry of entries) {
  try {
    new RegExp("^(?:" + entry.pattern + ")$");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(entry.label + ": " + message);
    process.exit(1);
  }
}
"""


def _field_label(label: str, field: str) -> str:
    return f'{label} field "{field}"'


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _validate_optional_string(
    handler: JsonObject, field: str, label: str
) -> None:
    if field in handler and not isinstance(handler[field], str):
        raise ValueError(f"{_field_label(label, field)} must be a string")


def _validate_timeout(handler: JsonObject, label: str) -> None:
    for field in ("timeout", "timeoutSec"):
        if field not in handler:
            continue
        value = handler[field]
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value <= 0
        ):
            raise ValueError(
                f"{_field_label(label, field)} must be a positive number"
            )


def _validate_matcher(handler: JsonObject, event: str, label: str) -> None:
    if "matcher" not in handler:
        return
    matcher = _require_string(
        handler["matcher"], _field_label(label, "matcher")
    )
    if event in (
        "preToolUse",
        "PreToolUse",
        "permissionRequest",
        "PermissionRequest",
    ) and matcher in ("*", "**"):
        return


def _validate_string_map(value: Any, label: str) -> None:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    for key, item in value.items():
        if not isinstance(key, str):
            raise ValueError(f"{label} keys must be strings")
        _require_string(item, f"{label}.{key}")


def _validate_command(
    handler: JsonObject, event: str, label: str
) -> None:
    command_fields = tuple(
        field for field in ("bash", "powershell", "command") if field in handler
    )
    if not command_fields:
        raise ValueError(f"{label} must define bash, powershell, or command")
    for field in ("bash", "powershell", "command", "cwd"):
        _validate_optional_string(handler, field, label)
    if "env" in handler:
        _validate_string_map(handler["env"], _field_label(label, "env"))
    _validate_timeout(handler, label)
    _validate_matcher(handler, event, label)


def _is_loopback(hostname: str) -> bool:
    return hostname in ("localhost", "::1") or hostname.startswith("127.")


def _validate_http(handler: JsonObject, event: str, label: str) -> None:
    raw_url = _require_string(handler.get("url"), _field_label(label, "url"))
    try:
        parsed = urllib.parse.urlsplit(raw_url)
        hostname = parsed.hostname
        parsed.port
    except ValueError as error:
        raise ValueError(f"{_field_label(label, 'url')} is invalid") from error
    localhost_allowed = (
        os.environ.get("COPILOT_HOOK_ALLOW_LOCALHOST") == "1"
        and parsed.scheme == "http"
        and hostname is not None
        and _is_loopback(hostname)
    )
    if (
        (parsed.scheme != "https" and not localhost_allowed)
        or not parsed.netloc
        or hostname is None
    ):
        raise ValueError(f"{_field_label(label, 'url')} must use HTTPS")
    if "headers" in handler:
        _validate_string_map(
            handler["headers"], _field_label(label, "headers")
        )
    if "allowedEnvVars" in handler:
        value = handler["allowedEnvVars"]
        if not isinstance(value, list) or any(
            not isinstance(item, str) or not item for item in value
        ):
            raise ValueError(
                f"{_field_label(label, 'allowedEnvVars')} must be an array of strings"
            )
    _validate_timeout(handler, label)
    _validate_matcher(handler, event, label)


def _validate_prompt(handler: JsonObject, event: str, label: str) -> None:
    if event not in ("sessionStart", "SessionStart"):
        raise ValueError(
            f"{label} prompt hooks are supported only for sessionStart"
        )
    _require_string(handler.get("prompt"), _field_label(label, "prompt"))


def _validate_handler(handler: JsonObject, event: str, label: str) -> None:
    handler_type = handler.get("type")
    if handler_type is None:
        handler_type = "command"
    if handler_type == "command":
        _validate_command(handler, event, label)
    elif handler_type == "http":
        _validate_http(handler, event, label)
    elif handler_type == "prompt":
        _validate_prompt(handler, event, label)
    else:
        raise ValueError(
            f'{_field_label(label, "type")} is unsupported'
        )


def validate_hooks(value: Any, label: str) -> CopilotHooks:
    if not isinstance(value, dict):
        raise ValueError(f'{label} field "hooks" must be an object')
    hooks: CopilotHooks = {}
    for event, handlers in value.items():
        if not isinstance(event, str) or event not in SUPPORTED_EVENTS:
            raise ValueError(f'{label} hook event "{event}" is unsupported')
        if not isinstance(handlers, list):
            raise ValueError(f'{label} field "hooks.{event}" must be an array')
        validated = []
        for index, handler in enumerate(handlers):
            item_label = f"{label} handler hooks.{event}[{index}]"
            if not isinstance(handler, dict):
                raise ValueError(f"{item_label} must be an object")
            _validate_handler(handler, event, item_label)
            validated.append(dict(handler))
        hooks[event] = validated
    return hooks


def _matcher_entries(hooks: CopilotHooks) -> List[JsonObject]:
    entries = []
    wildcard_events = {
        "preToolUse",
        "PreToolUse",
        "permissionRequest",
        "PermissionRequest",
    }
    for event, handlers in hooks.items():
        for index, handler in enumerate(handlers):
            matcher = handler.get("matcher")
            if not isinstance(matcher, str):
                continue
            if event in wildcard_events and matcher in ("*", "**"):
                continue
            entries.append({
                "label": f"GitHub Copilot hooks.{event}[{index}] matcher",
                "pattern": matcher,
            })
    return entries


def validate_javascript_regexes(sources: List[CopilotHooks]) -> None:
    entries = [entry for hooks in sources for entry in _matcher_entries(hooks)]
    if not entries:
        return
    node_path = shutil.which("node")
    if node_path is None:
        raise FileNotFoundError(
            "Node.js runtime is required to validate GitHub Copilot hook matchers"
        )
    try:
        result = subprocess.run(  # nosec B603
            [node_path, "--input-type=module", "--eval", _REGEX_VALIDATOR],
            input=json.dumps(entries),
            text=True,
            capture_output=True,
            check=False,
            timeout=_REGEX_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise TimeoutError(
            "GitHub Copilot hook matcher validation timed out after "
            f"{_REGEX_TIMEOUT_SECONDS} seconds"
        ) from error
    except OSError as error:
        raise OSError(f"Run Node.js Copilot matcher validator: {error}") from error
    if result.returncode == 0:
        return
    message = (
        result.stderr.strip()
        or result.stdout.strip()
        or f"Node.js exited with code {result.returncode}"
    )
    raise ValueError(
        "GitHub Copilot matcher must be a valid JavaScript regular expression: "
        f"{message}"
    )
