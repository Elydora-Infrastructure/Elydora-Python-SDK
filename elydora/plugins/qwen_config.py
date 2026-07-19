"""Qwen Code settings parsing and source-preserving rendering."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from ._jsonc import JsoncEditor
from .qwen_contract import (
    TOOL_EVENTS,
    JsonObject,
    QwenHookSettings,
    managed_removals,
    read_hook_settings,
)


OWNED_FILE_MARKER = "// Managed by Elydora"


@dataclass(frozen=True)
class QwenDocument:
    file_path: str
    exists: bool
    raw: str
    root: JsonObject
    hooks: QwenHookSettings
    has_hooks_container: bool
    hooks_disabled: bool
    owned_file: bool


@dataclass(frozen=True)
class RenderedDocument:
    document: QwenDocument
    changed: bool
    next_source: Optional[str]


def _label(file_path: str) -> str:
    return f"Qwen Code settings at {file_path}"


def parse_document(
    *,
    exists: bool,
    file_path: str,
    raw: str,
) -> QwenDocument:
    label = _label(file_path)
    editor = JsoncEditor(
        raw,
        label,
        allow_trailing_commas=False,
    )
    if not isinstance(editor.value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    root = editor.value
    disabled = root.get("disableAllHooks")
    if "disableAllHooks" in root and not isinstance(disabled, bool):
        raise ValueError(f'{label} field "disableAllHooks" must be a boolean')
    has_container = "hooks" in root
    hooks = (
        read_hook_settings(root["hooks"], f'{label} field "hooks"')
        if has_container
        else {}
    )
    return QwenDocument(
        file_path,
        exists,
        raw,
        root,
        hooks,
        has_container,
        disabled is True,
        raw.startswith(OWNED_FILE_MARKER),
    )


def create_owned_document(file_path: str) -> QwenDocument:
    return parse_document(
        exists=False,
        file_path=file_path,
        raw=f"{OWNED_FILE_MARKER}\n{{}}\n",
    )


def _settings_from_editor(
    editor: JsoncEditor,
    document: QwenDocument,
) -> QwenHookSettings:
    root = editor.value
    if not isinstance(root, dict):
        raise ValueError(f"{_label(document.file_path)} must contain a JSON object")
    if "hooks" not in root:
        return {}
    return read_hook_settings(
        root["hooks"],
        f'{_label(document.file_path)} field "hooks"',
    )


def _remove_managed(
    editor: JsoncEditor,
    document: QwenDocument,
    agent_id: Optional[str],
) -> None:
    removals = managed_removals(document.hooks, agent_id)
    for event in TOOL_EVENTS:
        event_removals = sorted(
            (item for item in removals if item.event == event),
            key=lambda item: item.group_index,
            reverse=True,
        )
        for removal in event_removals:
            group_path = ("hooks", event, removal.group_index)
            if removal.remove_group:
                editor.delete(group_path)
                continue
            for handler_index in sorted(removal.handler_indexes, reverse=True):
                editor.delete((*group_path, "hooks", handler_index))
        if event_removals:
            current = _settings_from_editor(editor, document)
            if event in current and not current[event]:
                editor.delete(("hooks", event))
    root = editor.value
    if isinstance(root, dict) and "hooks" in root:
        current = _settings_from_editor(editor, document)
        if not current:
            editor.delete(("hooks",))


def _append_group(
    editor: JsoncEditor,
    document: QwenDocument,
    event: str,
    group: JsonObject,
) -> None:
    root = editor.value
    if not isinstance(root, dict):
        raise ValueError(f"{_label(document.file_path)} must contain a JSON object")
    if "hooks" not in root:
        editor.add_property((), "hooks", {event: [group]})
        return
    current = _settings_from_editor(editor, document)
    if event in current:
        editor.append(("hooks", event), group)
    else:
        editor.add_property(("hooks",), event, [group])


def render_document(
    document: QwenDocument,
    agent_id: Optional[str],
    additions: Dict[str, JsonObject],
) -> RenderedDocument:
    editor = JsoncEditor(
        document.raw,
        _label(document.file_path),
        allow_trailing_commas=False,
    )
    _remove_managed(editor, document, agent_id)
    for event in TOOL_EVENTS:
        group = additions.get(event)
        if group is not None:
            _append_group(editor, document, event, group)
    next_document = parse_document(
        exists=document.exists,
        file_path=document.file_path,
        raw=editor.raw,
    )
    if not additions and document.owned_file and not next_document.root:
        return RenderedDocument(document, True, None)
    return RenderedDocument(
        document,
        editor.raw != document.raw,
        editor.raw,
    )
