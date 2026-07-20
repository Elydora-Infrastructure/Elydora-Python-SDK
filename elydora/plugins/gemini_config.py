"""Gemini CLI JSONC parsing and source-preserving hook edits."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from ._jsonc import JsoncEditor
from .gemini_contract import (
    MANAGED_EVENTS,
    GeminiHookControls,
    GeminiHooks,
    JsonObject,
    managed_gemini_removals,
    read_gemini_hook_controls,
    read_gemini_hooks,
)


OWNED_FILE_MARKER = "// Managed by Elydora"


@dataclass(frozen=True)
class GeminiDocument:
    file_path: str
    exists: bool
    raw: str
    root: JsonObject
    hooks: GeminiHooks
    hook_controls: GeminiHookControls
    has_hooks_container: bool
    owned_file: bool


@dataclass(frozen=True)
class RenderedGeminiDocument:
    document: GeminiDocument
    changed: bool
    next_source: Optional[str]


def _label(file_path: str) -> str:
    return f"Gemini CLI user settings at {file_path}"


def parse_gemini_document(
    *, exists: bool, file_path: str, raw: str
) -> GeminiDocument:
    editor = JsoncEditor(
        raw,
        _label(file_path),
        allow_trailing_commas=False,
    )
    if not isinstance(editor.value, dict):
        raise ValueError(f"{_label(file_path)} must contain a JSON object")
    root = editor.value
    return GeminiDocument(
        file_path=file_path,
        exists=exists,
        raw=raw,
        root=root,
        hooks=(read_gemini_hooks(root["hooks"]) if "hooks" in root else {}),
        hook_controls=(
            read_gemini_hook_controls(root["hooksConfig"])
            if "hooksConfig" in root
            else GeminiHookControls(True, ())
        ),
        has_hooks_container="hooks" in root,
        owned_file=raw.startswith(OWNED_FILE_MARKER),
    )


def create_gemini_document(file_path: str) -> GeminiDocument:
    return parse_gemini_document(
        exists=False,
        file_path=file_path,
        raw=f"{OWNED_FILE_MARKER}\n{{}}\n",
    )


def _current_document(
    document: GeminiDocument, editor: JsoncEditor
) -> GeminiDocument:
    return parse_gemini_document(
        exists=document.exists,
        file_path=document.file_path,
        raw=editor.raw,
    )


def _remove_managed(
    editor: JsoncEditor,
    document: GeminiDocument,
    agent_id: Optional[str],
) -> None:
    removals = managed_gemini_removals(document.hooks, agent_id)
    for event in MANAGED_EVENTS:
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
            for handler_index in sorted(
                removal.handler_indexes, reverse=True
            ):
                editor.delete((*group_path, "hooks", handler_index))
        if event_removals:
            current = _current_document(document, editor)
            if event in current.hooks and not current.hooks[event]:
                editor.delete(("hooks", event))
    current = _current_document(document, editor)
    if current.has_hooks_container and not current.hooks:
        editor.delete(("hooks",))


def _append_group(
    editor: JsoncEditor,
    document: GeminiDocument,
    event: str,
    group: JsonObject,
) -> None:
    current = _current_document(document, editor)
    if not current.has_hooks_container:
        editor.add_property((), "hooks", {event: [group]})
    elif event in current.hooks:
        editor.append(("hooks", event), group)
    else:
        editor.add_property(("hooks",), event, [group])


def _already_installed(
    document: GeminiDocument, additions: Dict[str, JsonObject]
) -> bool:
    if set(additions) != set(MANAGED_EVENTS):
        return False
    removals = managed_gemini_removals(document.hooks)
    for event in MANAGED_EVENTS:
        expected = additions[event]
        event_removals = [item for item in removals if item.event == event]
        exact_groups = [
            group for group in document.hooks.get(event, []) if group == expected
        ]
        if (
            len(event_removals) != 1
            or not event_removals[0].remove_group
            or len(exact_groups) != 1
        ):
            return False
    return True


def render_gemini_document(
    document: GeminiDocument,
    agent_id: Optional[str],
    additions: Dict[str, JsonObject],
) -> RenderedGeminiDocument:
    if agent_id is None and _already_installed(document, additions):
        return RenderedGeminiDocument(document, False, document.raw)
    editor = JsoncEditor(
        document.raw,
        _label(document.file_path),
        allow_trailing_commas=False,
    )
    _remove_managed(editor, document, agent_id)
    for event in MANAGED_EVENTS:
        group = additions.get(event)
        if group is not None:
            _append_group(editor, document, event, group)
    current = _current_document(document, editor)
    if not additions and document.owned_file and not current.root:
        return RenderedGeminiDocument(document, True, None)
    return RenderedGeminiDocument(
        document,
        editor.raw != document.raw,
        editor.raw,
    )
