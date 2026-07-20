"""Strict Letta Code settings parsing and source-preserving edits."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from ._jsonc import JsoncEditor
from ._managed_files import FileSnapshot
from ._strict_json import parse_json_object
from .letta_contract import (
    MANAGED_EVENTS,
    JsonObject,
    LettaHooks,
    managed_letta_removals,
    read_letta_hooks,
)


@dataclass(frozen=True)
class LettaDocument:
    kind: str
    file_path: str
    exists: bool
    raw: str
    snapshot: Optional[FileSnapshot]
    root: JsonObject
    hooks: LettaHooks
    has_hooks_container: bool


@dataclass(frozen=True)
class RenderedLettaDocument:
    document: LettaDocument
    changed: bool
    next_source: Optional[str]


def letta_source_label(kind: str) -> str:
    labels = {
        "global": "Letta Code global settings",
        "project": "Letta Code project settings",
        "project-local": "Letta Code project-local settings",
    }
    try:
        return labels[kind]
    except KeyError as error:
        raise ValueError(f"Unsupported Letta Code document kind: {kind}") from error


def letta_document_label(document: LettaDocument) -> str:
    return letta_source_label(document.kind)


def parse_letta_document(
    *,
    kind: str,
    exists: bool,
    file_path: str,
    raw: str,
    snapshot: Optional[FileSnapshot] = None,
) -> LettaDocument:
    label = f"{letta_source_label(kind)} at {file_path}"
    root = parse_json_object(raw, label)
    return LettaDocument(
        kind,
        file_path,
        exists,
        raw,
        snapshot,
        root,
        read_letta_hooks(root["hooks"]) if "hooks" in root else {},
        "hooks" in root,
    )


def create_letta_document(kind: str, file_path: str) -> LettaDocument:
    return parse_letta_document(
        kind=kind,
        exists=False,
        file_path=file_path,
        raw="{}\n",
    )


def _current_document(
    document: LettaDocument, editor: JsoncEditor
) -> LettaDocument:
    return parse_letta_document(
        kind=document.kind,
        exists=document.exists,
        file_path=document.file_path,
        raw=editor.raw,
        snapshot=document.snapshot,
    )


def _event_groups(hooks: LettaHooks, event: str) -> list[JsonObject]:
    value = hooks.get(event)
    return value if isinstance(value, list) else []


def _remove_managed(
    editor: JsoncEditor,
    document: LettaDocument,
    agent_id: Optional[str],
) -> None:
    removals = managed_letta_removals(document.hooks, agent_id)
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
            for handler_index in sorted(removal.handler_indexes, reverse=True):
                editor.delete((*group_path, "hooks", handler_index))
        if event_removals:
            current = _current_document(document, editor)
            if event in current.hooks and not _event_groups(current.hooks, event):
                editor.delete(("hooks", event))
    current = _current_document(document, editor)
    if current.has_hooks_container and not current.hooks:
        editor.delete(("hooks",))


def _append_group(
    editor: JsoncEditor,
    document: LettaDocument,
    event: str,
    group: JsonObject,
) -> None:
    current = _current_document(document, editor)
    groups = _event_groups(current.hooks, event)
    if not current.has_hooks_container:
        editor.add_property((), "hooks", {event: [group]})
    elif groups:
        editor.append(("hooks", event), group)
    elif event in current.hooks:
        editor.append(("hooks", event), group)
    else:
        editor.add_property(("hooks",), event, [group])


def _already_installed(
    document: LettaDocument, additions: Dict[str, JsonObject]
) -> bool:
    if set(additions) != set(MANAGED_EVENTS):
        return False
    removals = managed_letta_removals(document.hooks)
    for event in MANAGED_EVENTS:
        expected = additions[event]
        event_removals = [item for item in removals if item.event == event]
        exact_groups = [
            group for group in _event_groups(document.hooks, event)
            if group == expected
        ]
        if (
            len(event_removals) != 1
            or not event_removals[0].remove_group
            or len(exact_groups) != 1
        ):
            return False
    return True


def render_letta_document(
    document: LettaDocument,
    agent_id: Optional[str],
    additions: Dict[str, JsonObject],
) -> RenderedLettaDocument:
    if agent_id is None and _already_installed(document, additions):
        return RenderedLettaDocument(document, False, document.raw)
    editor = JsoncEditor(
        document.raw,
        f"{letta_document_label(document)} at {document.file_path}",
        allow_trailing_commas=False,
    )
    _remove_managed(editor, document, agent_id)
    for event in MANAGED_EVENTS:
        group = additions.get(event)
        if group is not None:
            _append_group(editor, document, event, group)
    current = _current_document(document, editor)
    if not additions and not current.root:
        return RenderedLettaDocument(document, True, None)
    return RenderedLettaDocument(
        document,
        editor.raw != document.raw,
        editor.raw,
    )
