"""GitHub Copilot CLI hook ownership and rendering."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import re
import shlex
import sys
from typing import Any, Dict, List, Optional, Tuple

from ._managed_files import FileSnapshot
from ._strict_json import parse_json_object
from .copilot_schema import CopilotHooks, validate_hooks


AGENT_KEY = "copilot"
GUARD_SCRIPT = "guard.py"
AUDIT_SCRIPT = "hook.py"
CONFIG_FILE = "elydora-audit.json"
HOOK_TIMEOUT_SECONDS = 10

JsonObject = Dict[str, Any]
MANAGED_EVENTS: Tuple[Tuple[str, str], ...] = (
    ("preToolUse", GUARD_SCRIPT),
    ("postToolUse", AUDIT_SCRIPT),
    ("postToolUseFailure", AUDIT_SCRIPT),
)


@dataclass(frozen=True)
class CopilotDocument:
    exists: bool
    file_path: str
    root: JsonObject
    hooks: CopilotHooks
    hooks_disabled: bool
    raw: Optional[str] = None
    snapshot: Optional[FileSnapshot] = None


@dataclass(frozen=True)
class SourcePrecondition:
    file_path: str
    label: str
    snapshot: Optional[FileSnapshot]


@dataclass(frozen=True)
class CopilotSources:
    user: CopilotDocument
    legacy: Optional[CopilotDocument]
    disabled_by: Optional[str]
    settings_preconditions: Tuple[SourcePrecondition, ...]


@dataclass(frozen=True)
class RenderedDocument:
    document: CopilotDocument
    changed: bool
    next_source: Optional[str] = None


@dataclass(frozen=True)
class RuntimeContract:
    agent_id: str
    guard_path: str
    audit_path: str


@dataclass(frozen=True)
class _ParsedArgument:
    value: str
    next_index: int


@dataclass(frozen=True)
class _ManagedEntry:
    agent_id: str
    script_path: str


def runtime_root() -> str:
    return os.path.join(os.path.expanduser("~"), ".elydora")


def same_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(
        os.path.abspath(right)
    )


def same_agent_id(left: str, right: str) -> bool:
    return os.path.normcase(left) == os.path.normcase(right)


def _quote_posix(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _quote_powershell(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def build_handler(script_path: str) -> JsonObject:
    return {
        "type": "command",
        "bash": f"{_quote_posix(sys.executable)} {_quote_posix(script_path)}",
        "powershell": (
            f"& {_quote_powershell(sys.executable)} "
            f"{_quote_powershell(script_path)}; exit $LASTEXITCODE"
        ),
        "timeoutSec": HOOK_TIMEOUT_SECONDS,
    }


def _read_posix_argument(command: str, start: int) -> Optional[_ParsedArgument]:
    if start >= len(command) or command[start] != "'":
        return None
    apostrophe = "'\"'\"'"
    value = ""
    index = start + 1
    while index < len(command):
        if command.startswith(apostrophe, index):
            value += "'"
            index += len(apostrophe)
            continue
        if command[index] == "'":
            return _ParsedArgument(value, index + 1)
        value += command[index]
        index += 1
    return None


def _parse_generated_bash(command: Any) -> Optional[Tuple[str, str]]:
    if not isinstance(command, str):
        return None
    executable = _read_posix_argument(command, 0)
    if executable is None or command[executable.next_index:executable.next_index + 1] != " ":
        return None
    script = _read_posix_argument(command, executable.next_index + 1)
    if script is None or script.next_index != len(command):
        return None
    return executable.value, script.value


def _read_powershell_argument(
    command: str, start: int
) -> Optional[_ParsedArgument]:
    if start >= len(command) or command[start] != "'":
        return None
    value = ""
    index = start + 1
    while index < len(command):
        if command[index] != "'":
            value += command[index]
            index += 1
            continue
        if index + 1 < len(command) and command[index + 1] == "'":
            value += "'"
            index += 2
            continue
        return _ParsedArgument(value, index + 1)
    return None


def _parse_generated_powershell(command: Any) -> Optional[Tuple[str, str]]:
    if not isinstance(command, str) or not command.startswith("& "):
        return None
    executable = _read_powershell_argument(command, 2)
    if executable is None or command[executable.next_index:executable.next_index + 1] != " ":
        return None
    script = _read_powershell_argument(command, executable.next_index + 1)
    if script is None or command[script.next_index:] != "; exit $LASTEXITCODE":
        return None
    return executable.value, script.value


def _exact_handler_keys(handler: JsonObject) -> bool:
    return set(handler) == {"type", "bash", "powershell", "timeoutSec"}


def _is_python_executable(file_path: str) -> bool:
    return os.path.isabs(file_path) and re.fullmatch(
        r"(?:python|pypy)(?:[0-9]+(?:\.[0-9]+)*)?(?:\.exe)?",
        os.path.basename(file_path),
        re.IGNORECASE,
    ) is not None


def _current_script_path(handler: JsonObject) -> Optional[str]:
    if (
        not _exact_handler_keys(handler)
        or handler.get("type") != "command"
        or handler.get("timeoutSec") != HOOK_TIMEOUT_SECONDS
    ):
        return None
    bash = _parse_generated_bash(handler.get("bash"))
    powershell = _parse_generated_powershell(handler.get("powershell"))
    if (
        bash is None
        or powershell is None
        or not _is_python_executable(bash[0])
        or not same_path(bash[0], powershell[0])
        or not same_path(bash[1], powershell[1])
    ):
        return None
    return bash[1]


def _prior_script_path(handler: JsonObject) -> Optional[str]:
    if (
        not _exact_handler_keys(handler)
        or handler.get("type") != "command"
        or handler.get("timeoutSec") != HOOK_TIMEOUT_SECONDS
        or not isinstance(handler.get("bash"), str)
    ):
        return None
    bash_command = str(handler["bash"])
    try:
        arguments = shlex.split(bash_command)
    except ValueError:
        return None
    powershell = _parse_generated_powershell(handler.get("powershell"))
    if (
        len(arguments) != 2
        or shlex.join(arguments) != bash_command
        or powershell is None
        or not _is_python_executable(arguments[0])
        or not same_path(arguments[0], powershell[0])
        or not same_path(arguments[1], powershell[1])
    ):
        return None
    return arguments[1]


def _legacy_script_path(handler: JsonObject) -> Optional[str]:
    if (
        not _exact_handler_keys(handler)
        or handler.get("type") != "command"
        or handler.get("timeoutSec") != 5
        or not isinstance(handler.get("bash"), str)
        or handler.get("bash") != handler.get("powershell")
    ):
        return None
    command = str(handler["bash"])
    match = re.fullmatch(r'"[^"\r\n]+"\s+(.+)', command)
    return match.group(1) if match else command


def _managed_entry(
    handler: JsonObject, script_name: str
) -> Optional[_ManagedEntry]:
    script_path = (
        _current_script_path(handler)
        or _prior_script_path(handler)
        or _legacy_script_path(handler)
    )
    if (
        not script_path
        or os.path.normcase(os.path.basename(script_path))
        != os.path.normcase(script_name)
    ):
        return None
    agent_directory = os.path.dirname(script_path)
    if not same_path(os.path.dirname(agent_directory), runtime_root()):
        return None
    agent_id = os.path.basename(agent_directory)
    if agent_id in ("", ".", ".."):
        return None
    return _ManagedEntry(agent_id, script_path)


def parse_document(
    file_path: str,
    snapshot: FileSnapshot,
    label: str,
) -> CopilotDocument:
    document_label = f"{label} at {file_path}"
    root = parse_json_object(snapshot.contents, document_label)
    version = root.get("version")
    if isinstance(version, bool) or version != 1:
        raise ValueError(f"{document_label} must declare version 1")
    if "disableAllHooks" in root and not isinstance(
        root["disableAllHooks"], bool
    ):
        raise ValueError(
            f'{document_label} field "disableAllHooks" must be a boolean'
        )
    hooks = validate_hooks(root["hooks"], document_label) if "hooks" in root else {}
    return CopilotDocument(
        True,
        file_path,
        root,
        hooks,
        root.get("disableAllHooks") is True,
        snapshot.contents,
        snapshot,
    )


def create_document(file_path: str) -> CopilotDocument:
    return CopilotDocument(False, file_path, {}, {}, False)


def remove_managed_hooks(
    hooks: CopilotHooks, agent_id: str = ""
) -> CopilotHooks:
    result = {event: list(handlers) for event, handlers in hooks.items()}
    for event, script_name in MANAGED_EVENTS:
        handlers = []
        for handler in result.get(event, []):
            managed = _managed_entry(handler, script_name)
            remove = managed is not None and (
                not agent_id or same_agent_id(managed.agent_id, agent_id)
            )
            if not remove:
                handlers.append(handler)
        if handlers:
            result[event] = handlers
        else:
            result.pop(event, None)
    return result


def _empty_owned_document(root: JsonObject, hooks: CopilotHooks) -> bool:
    return not hooks and all(key in ("version", "hooks") for key in root)


def render_document(
    document: CopilotDocument,
    hooks: CopilotHooks,
) -> RenderedDocument:
    if not document.exists and not hooks:
        return RenderedDocument(document, False)
    if document.exists and _empty_owned_document(document.root, hooks):
        return RenderedDocument(document, True)
    root = {**document.root, "version": 1}
    if hooks:
        root["hooks"] = hooks
    else:
        root.pop("hooks", None)
    next_source = json.dumps(root, indent=2, ensure_ascii=False) + "\n"
    parse_document(
        document.file_path,
        FileSnapshot(next_source, 0, 0, 0),
        "GitHub Copilot rendered hooks",
    )
    return RenderedDocument(
        document,
        next_source != document.raw,
        next_source,
    )


def _managed_entries(
    handlers: List[JsonObject], script_name: str
) -> Dict[str, List[_ManagedEntry]]:
    result: Dict[str, List[_ManagedEntry]] = {}
    for handler in handlers:
        entry = _managed_entry(handler, script_name)
        if entry is not None:
            result.setdefault(os.path.normcase(entry.agent_id), []).append(entry)
    return result


def runtime_contracts(hooks: CopilotHooks) -> List[RuntimeContract]:
    guards = _managed_entries(hooks.get("preToolUse", []), GUARD_SCRIPT)
    successes = _managed_entries(hooks.get("postToolUse", []), AUDIT_SCRIPT)
    failures = _managed_entries(
        hooks.get("postToolUseFailure", []), AUDIT_SCRIPT
    )
    contracts = []
    for key, guard in guards.items():
        success = successes.get(key, [])
        failure = failures.get(key, [])
        if len(guard) != 1 or len(success) != 1 or len(failure) != 1:
            continue
        if not same_path(success[0].script_path, failure[0].script_path):
            continue
        contracts.append(RuntimeContract(
            guard[0].agent_id,
            guard[0].script_path,
            success[0].script_path,
        ))
    return contracts
