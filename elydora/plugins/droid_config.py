"""Factory Droid source selection and source-preserving rendering."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from .droid_contract import (
    TOOL_EVENTS,
    DroidHookSettings,
    JsonObject,
    has_own,
    managed_removals,
    read_hook_settings,
)
from .droid_jsonc import JsonPathPart, JsoncEditor


OWNED_FILE_MARKER = "// Managed by Elydora"


@dataclass(frozen=True)
class DroidDocument:
    kind: str
    file_path: str
    exists: bool
    raw: str
    root: JsonObject
    hooks: DroidHookSettings
    base_path: Tuple[JsonPathPart, ...]
    has_hooks_container: bool
    owned_file: bool


@dataclass(frozen=True)
class DroidSources:
    root_path: str
    primary: Optional[DroidDocument]
    settings: DroidDocument


@dataclass(frozen=True)
class InstallationTargets:
    targets: Dict[str, DroidDocument]
    created_root: Optional[DroidDocument]


@dataclass(frozen=True)
class RenderedDocument:
    document: DroidDocument
    changed: bool
    next_source: Optional[str]


def _label(kind: str, file_path: str) -> str:
    if kind == "settings":
        return f"Factory Droid settings at {file_path}"
    if kind == "legacy":
        return f"Factory Droid legacy hooks at {file_path}"
    return f"Factory Droid hooks at {file_path}"


def parse_document(
    *,
    exists: bool,
    file_path: str,
    kind: str,
    raw: str,
) -> DroidDocument:
    label = _label(kind, file_path)
    editor = JsoncEditor(raw, label)
    if not isinstance(editor.value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    root = editor.value
    if kind == "settings":
        has_container = has_own(root, "hooks")
        hooks = (
            read_hook_settings(root["hooks"], f'{label} field "hooks"')
            if has_container
            else {}
        )
        return DroidDocument(
            kind,
            file_path,
            exists,
            raw,
            root,
            hooks,
            ("hooks",),
            has_container,
            False,
        )
    return DroidDocument(
        kind,
        file_path,
        exists,
        raw,
        root,
        read_hook_settings(root, label),
        (),
        True,
        raw.startswith(OWNED_FILE_MARKER),
    )


def create_settings_document(file_path: str) -> DroidDocument:
    return parse_document(
        exists=False,
        file_path=file_path,
        kind="settings",
        raw="{}\n",
    )


def create_owned_hook_document(file_path: str) -> DroidDocument:
    return parse_document(
        exists=False,
        file_path=file_path,
        kind="hooks",
        raw=f"{OWNED_FILE_MARKER}\n{{}}\n",
    )


def _hooks_from_editor(
    editor: JsoncEditor,
    document: DroidDocument,
) -> DroidHookSettings:
    root = editor.value
    if not isinstance(root, dict):
        raise ValueError(f"{_label(document.kind, document.file_path)} must be an object")
    if document.kind == "settings":
        hooks = root.get("hooks")
        return read_hook_settings(
            hooks,
            f'{_label(document.kind, document.file_path)} field "hooks"',
        )
    return read_hook_settings(root, _label(document.kind, document.file_path))


def _event_path(document: DroidDocument, event: str) -> Tuple[JsonPathPart, ...]:
    return (*document.base_path, event)


def _remove_managed(
    editor: JsoncEditor,
    document: DroidDocument,
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
            group_path = (*_event_path(document, event), removal.group_index)
            if removal.remove_group:
                editor.delete(group_path)
                continue
            for handler_index in sorted(removal.handler_indexes, reverse=True):
                editor.delete((*group_path, "hooks", handler_index))
        current = _hooks_from_editor(editor, document)
        if document.owned_file and event in current and not current[event]:
            editor.delete(_event_path(document, event))


def render_document(
    document: DroidDocument,
    agent_id: Optional[str],
    additions: Dict[str, JsonObject],
) -> RenderedDocument:
    editor = JsoncEditor(
        document.raw,
        _label(document.kind, document.file_path),
    )
    _remove_managed(editor, document, agent_id)
    for event in TOOL_EVENTS:
        group = additions.get(event)
        if group is None:
            continue
        current = _hooks_from_editor(editor, document)
        if event in current:
            editor.append(_event_path(document, event), group)
        else:
            editor.add_property(document.base_path, event, [group])
    next_document = parse_document(
        exists=document.exists,
        file_path=document.file_path,
        kind=document.kind,
        raw=editor.raw,
    )
    if (
        not additions
        and document.owned_file
        and document.kind != "settings"
        and not next_document.hooks
    ):
        return RenderedDocument(document, True, None)
    return RenderedDocument(
        document,
        editor.raw != document.raw,
        editor.raw,
    )


def _event_target(
    event: str,
    sources: DroidSources,
    create_root: "_RootFactory",
) -> DroidDocument:
    if sources.primary is not None and event in sources.primary.hooks:
        return sources.primary
    if sources.settings.has_hooks_container and event in sources.settings.hooks:
        return sources.settings
    if sources.primary is not None:
        return sources.primary
    if sources.settings.has_hooks_container:
        return sources.settings
    return create_root.get()


class _RootFactory:
    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.document: Optional[DroidDocument] = None

    def get(self) -> DroidDocument:
        if self.document is None:
            self.document = create_owned_hook_document(self.file_path)
        return self.document


def installation_targets(sources: DroidSources) -> InstallationTargets:
    root = _RootFactory(sources.root_path)
    targets = {
        event: _event_target(event, sources, root)
        for event in TOOL_EVENTS
    }
    return InstallationTargets(targets, root.document)


def additions_for(
    document: DroidDocument,
    targets: Dict[str, DroidDocument],
    groups: Dict[str, JsonObject],
) -> Dict[str, JsonObject]:
    return {
        event: groups[event]
        for event in TOOL_EVENTS
        if targets[event].file_path == document.file_path
    }


def unique_documents(
    documents: Sequence[Optional[DroidDocument]],
) -> List[DroidDocument]:
    unique: Dict[str, DroidDocument] = {}
    for document in documents:
        if document is not None:
            unique[document.file_path] = document
    return list(unique.values())
