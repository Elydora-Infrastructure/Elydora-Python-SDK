"""Factory Droid source selection and source-preserving rendering."""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Dict, List, Optional, Tuple

from ._jsonc import JsonPathPart, JsoncEditor
from ._managed_files import FileSnapshot
from .droid_contract import (
    TOOL_EVENTS,
    DroidHookMap,
    JsonObject,
    managed_removals,
    read_hook_map,
    same_path,
)
from .droid_policy import DroidPolicyState


OWNED_FILE_MARKER = "// Managed by Elydora"


@dataclass(frozen=True)
class DroidDocument:
    kind: str
    file_path: str
    exists: bool
    raw: str
    snapshot: Optional[FileSnapshot]
    root: JsonObject
    hooks: DroidHookMap
    base_path: Tuple[JsonPathPart, ...]
    has_hooks_container: bool
    hooks_disabled: Optional[bool]
    show_hook_output: Optional[bool]
    owned_file: bool


@dataclass(frozen=True)
class DroidSources:
    root: DroidDocument
    legacy: DroidDocument
    settings: DroidDocument
    local_settings: DroidDocument
    policy: DroidPolicyState


@dataclass(frozen=True)
class RenderedDocument:
    document: DroidDocument
    changed: bool
    next_source: Optional[str]


@dataclass(frozen=True)
class DroidHookBlock:
    field: str
    file_path: str
    label: str


def _label(kind: str, file_path: str) -> str:
    if kind == "settings":
        return f"Factory Droid settings at {file_path}"
    if kind == "local-settings":
        return f"Factory Droid local settings at {file_path}"
    if kind == "legacy":
        return f"Factory Droid legacy hooks at {file_path}"
    return f"Factory Droid hooks at {file_path}"


def _optional_boolean(root: JsonObject, field: str, label: str) -> Optional[bool]:
    value = root.get(field)
    if field in root and not isinstance(value, bool):
        raise ValueError(f'{label} field "{field}" must be a boolean')
    return value


def _legacy_direct_hooks(
    root: JsonObject,
    label: str,
) -> Tuple[DroidHookMap, Optional[bool], Optional[bool]]:
    hooks_disabled = _optional_boolean(root, "hooksDisabled", label)
    show_hook_output = _optional_boolean(root, "showHookOutput", label)
    entries = {
        key: value
        for key, value in root.items()
        if key not in {"hooksDisabled", "showHookOutput"}
    }
    return (
        read_hook_map(entries, label),
        hooks_disabled,
        show_hook_output,
    )


def parse_document(
    *,
    exists: bool,
    file_path: str,
    kind: str,
    raw: str,
    snapshot: Optional[FileSnapshot] = None,
) -> DroidDocument:
    label = _label(kind, file_path)
    editor = JsoncEditor(raw, label)
    if not isinstance(editor.value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    root = editor.value
    if kind in {"settings", "local-settings"}:
        has_container = "hooks" in root
        hooks = (
            read_hook_map(root["hooks"], f'{label} field "hooks"')
            if has_container
            else {}
        )
        return DroidDocument(
            kind,
            file_path,
            exists,
            raw,
            snapshot,
            root,
            hooks,
            ("hooks",),
            has_container,
            _optional_boolean(root, "hooksDisabled", label),
            _optional_boolean(root, "showHookOutput", label),
            False,
        )
    if "hooks" in root:
        hooks = read_hook_map(root["hooks"], f'{label} field "hooks"')
        return DroidDocument(
            kind,
            file_path,
            exists,
            raw,
            snapshot,
            root,
            hooks,
            ("hooks",),
            True,
            None,
            None,
            raw.startswith(OWNED_FILE_MARKER),
        )
    hooks, hooks_disabled, show_hook_output = _legacy_direct_hooks(root, label)
    return DroidDocument(
        kind,
        file_path,
        exists,
        raw,
        snapshot,
        root,
        hooks,
        (),
        False,
        hooks_disabled,
        show_hook_output,
        raw.startswith(OWNED_FILE_MARKER),
    )


def create_settings_document(
    file_path: str,
    kind: str = "settings",
) -> DroidDocument:
    return parse_document(
        exists=False,
        file_path=file_path,
        kind=kind,
        raw="{}\n",
    )


def create_legacy_hook_document(file_path: str) -> DroidDocument:
    return parse_document(
        exists=False,
        file_path=file_path,
        kind="legacy",
        raw="{}\n",
    )


def create_owned_hook_document(file_path: str) -> DroidDocument:
    return parse_document(
        exists=False,
        file_path=file_path,
        kind="hooks",
        raw=f'{OWNED_FILE_MARKER}\n{{\n  "hooks": {{}}\n}}\n',
    )


def _hooks_from_editor(
    editor: JsoncEditor,
    document: DroidDocument,
) -> DroidHookMap:
    root = editor.value
    label = _label(document.kind, document.file_path)
    if not isinstance(root, dict):
        raise ValueError(f"{label} must contain a JSON object")
    if document.kind in {"settings", "local-settings"} or "hooks" in root:
        return read_hook_map(root.get("hooks"), f'{label} field "hooks"')
    return _legacy_direct_hooks(root, label)[0]


def _event_path(document: DroidDocument, event: str) -> Tuple[JsonPathPart, ...]:
    return (*document.base_path, event)


def _current_document(
    document: DroidDocument,
    raw: str,
) -> DroidDocument:
    return parse_document(
        exists=document.exists,
        file_path=document.file_path,
        kind=document.kind,
        raw=raw,
        snapshot=document.snapshot,
    )


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
        if event_removals:
            current = _hooks_from_editor(editor, document)
            if not current.get(event):
                editor.delete(_event_path(document, event))


def _append_group(
    editor: JsoncEditor,
    document: DroidDocument,
    event: str,
    group: JsonObject,
) -> None:
    current = _hooks_from_editor(editor, document)
    if event in current:
        editor.append(_event_path(document, event), group)
    else:
        editor.add_property(document.base_path, event, [group])


def _hook_file_is_empty(
    document: DroidDocument,
    raw: str,
) -> bool:
    if document.kind in {"settings", "local-settings"}:
        return False
    current = _current_document(document, raw)
    remaining_root_fields = [key for key in current.root if key != "hooks"]
    return not current.hooks and not remaining_root_fields


def _has_exact_installation(
    document: DroidDocument,
    additions: Dict[str, JsonObject],
) -> bool:
    if set(additions) != set(TOOL_EVENTS):
        return False
    removals = managed_removals(document.hooks)
    if len(removals) != len(TOOL_EVENTS):
        return False
    for event in TOOL_EVENTS:
        matches = [item for item in removals if item.event == event]
        if len(matches) != 1 or not matches[0].remove_group:
            return False
        group = document.hooks[event][matches[0].group_index]
        if group != additions[event]:
            return False
    return True


def render_document(
    document: DroidDocument,
    agent_id: Optional[str],
    additions: Dict[str, JsonObject],
) -> RenderedDocument:
    if additions and _has_exact_installation(document, additions):
        return RenderedDocument(document, False, document.raw)
    editor = JsoncEditor(document.raw, _label(document.kind, document.file_path))
    _remove_managed(editor, document, agent_id)
    for event in TOOL_EVENTS:
        group = additions.get(event)
        if group is not None:
            _append_group(editor, document, event, group)
    _current_document(document, editor.raw)
    if (
        not additions
        and document.exists
        and document.owned_file
        and _hook_file_is_empty(document, editor.raw)
    ):
        return RenderedDocument(document, True, None)
    return RenderedDocument(document, editor.raw != document.raw, editor.raw)


def active_document(sources: DroidSources) -> DroidDocument:
    if sources.root.exists:
        return sources.root
    if sources.legacy.exists:
        return sources.legacy
    if sources.local_settings.has_hooks_container:
        return sources.local_settings
    if sources.settings.has_hooks_container:
        return sources.settings
    return sources.root


def effective_hooks(sources: DroidSources) -> DroidHookMap:
    return active_document(sources).hooks


def hook_block(sources: DroidSources) -> Optional[DroidHookBlock]:
    managed = sources.policy.allow_managed_hooks_only_by
    if managed is not None:
        return DroidHookBlock(
            "allowManagedHooksOnly",
            managed.file_path,
            managed.label,
        )
    if sources.policy.hooks_disabled is not None:
        if sources.policy.hooks_disabled:
            origin = sources.policy.hooks_disabled_by
            if origin is None:
                raise RuntimeError("Factory Droid policy origin is missing")
            return DroidHookBlock(
                "hooksDisabled",
                origin.file_path,
                origin.label,
            )
        return None
    selected = (
        sources.local_settings
        if sources.local_settings.hooks_disabled is not None
        else sources.settings
    )
    if selected.hooks_disabled is True:
        return DroidHookBlock(
            "hooksDisabled",
            selected.file_path,
            _label(selected.kind, selected.file_path),
        )
    active = active_document(sources)
    if active.hooks_disabled is True:
        return DroidHookBlock(
            "hooksDisabled",
            active.file_path,
            _label(active.kind, active.file_path),
        )
    return None


def source_documents(sources: DroidSources) -> List[DroidDocument]:
    return [
        sources.root,
        sources.legacy,
        sources.settings,
        sources.local_settings,
    ]


def installation_documents(sources: DroidSources) -> List[DroidDocument]:
    target = active_document(sources)
    candidates = [
        sources.root if sources.root.exists or target is sources.root else None,
        sources.legacy if sources.legacy.exists else None,
        sources.settings if sources.settings.has_hooks_container else None,
        (
            sources.local_settings
            if sources.local_settings.has_hooks_container
            else None
        ),
    ]
    unique: Dict[str, DroidDocument] = {}
    for document in candidates:
        if document is not None:
            unique[os.path.normcase(os.path.abspath(document.file_path))] = document
    return list(unique.values())


def additions_for_target(
    document: DroidDocument,
    target: DroidDocument,
    groups: Dict[str, JsonObject],
) -> Dict[str, JsonObject]:
    return groups if same_path(document.file_path, target.file_path) else {}
