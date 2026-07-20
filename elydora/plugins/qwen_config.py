"""Qwen Code JSONC parsing and source-preserving hook edits."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from ._jsonc import JsoncEditor
from ._managed_files import FileSnapshot
from .qwen_contract import (
    MANAGED_EVENTS,
    JsonObject,
    QwenHooks,
    managed_qwen_removals,
    read_qwen_hooks,
)


OWNED_FILE_MARKER = "// Managed by Elydora"


@dataclass(frozen=True)
class QwenDocument:
    kind: str
    file_path: str
    exists: bool
    raw: str
    snapshot: Optional[FileSnapshot]
    root: JsonObject
    hooks: QwenHooks
    has_hooks_container: bool
    disable_all_hooks: Optional[bool]
    folder_trust_enabled: Optional[bool]
    owned_file: bool


@dataclass(frozen=True)
class RenderedQwenDocument:
    document: QwenDocument
    changed: bool
    next_source: Optional[str]


def qwen_source_label(kind: str) -> str:
    labels = {
        "system-defaults": "Qwen Code system defaults",
        "user": "Qwen Code user settings",
        "workspace": "Qwen Code workspace settings",
        "system": "Qwen Code system override settings",
    }
    try:
        return labels[kind]
    except KeyError as error:
        raise ValueError(f"Unsupported Qwen Code document kind: {kind}") from error


def qwen_document_label(document: QwenDocument) -> str:
    return qwen_source_label(document.kind)


def parse_qwen_jsonc_object(raw: str, label: str) -> JsonObject:
    editor = JsoncEditor(raw, label, allow_trailing_commas=False)
    if not isinstance(editor.value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return editor.value


def _folder_trust_enabled(
    root: JsonObject, label: str
) -> Optional[bool]:
    if "security" not in root:
        return None
    security = root["security"]
    if not isinstance(security, dict):
        raise ValueError(f'{label} field "security" must be an object')
    if "folderTrust" not in security:
        return None
    folder_trust = security["folderTrust"]
    if not isinstance(folder_trust, dict):
        raise ValueError(
            f'{label} field "security.folderTrust" must be an object'
        )
    enabled = folder_trust.get("enabled")
    if enabled is not None and not isinstance(enabled, bool):
        raise ValueError(
            f'{label} field "security.folderTrust.enabled" must be a boolean'
        )
    return enabled


def parse_qwen_document(
    *,
    kind: str,
    exists: bool,
    file_path: str,
    raw: str,
    snapshot: Optional[FileSnapshot] = None,
) -> QwenDocument:
    label = f"{qwen_source_label(kind)} at {file_path}"
    root = parse_qwen_jsonc_object(raw, label)
    disabled = root.get("disableAllHooks")
    if "disableAllHooks" in root and not isinstance(disabled, bool):
        raise ValueError(f'{label} field "disableAllHooks" must be a boolean')
    has_hooks = "hooks" in root
    return QwenDocument(
        kind=kind,
        file_path=file_path,
        exists=exists,
        raw=raw,
        snapshot=snapshot,
        root=root,
        hooks=read_qwen_hooks(root["hooks"]) if has_hooks else {},
        has_hooks_container=has_hooks,
        disable_all_hooks=disabled if isinstance(disabled, bool) else None,
        folder_trust_enabled=_folder_trust_enabled(root, label),
        owned_file=kind == "user" and raw.startswith(OWNED_FILE_MARKER),
    )


def create_qwen_document(kind: str, file_path: str) -> QwenDocument:
    raw = f"{OWNED_FILE_MARKER}\n{{}}\n" if kind == "user" else "{}\n"
    return parse_qwen_document(
        kind=kind,
        exists=False,
        file_path=file_path,
        raw=raw,
    )


def _current_document(
    document: QwenDocument, editor: JsoncEditor
) -> QwenDocument:
    return parse_qwen_document(
        kind=document.kind,
        exists=document.exists,
        file_path=document.file_path,
        raw=editor.raw,
        snapshot=document.snapshot,
    )


def _remove_managed(
    editor: JsoncEditor,
    document: QwenDocument,
    agent_id: Optional[str],
) -> None:
    removals = managed_qwen_removals(document.hooks, agent_id)
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
            if event in current.hooks and not current.hooks[event]:
                editor.delete(("hooks", event))
    current = _current_document(document, editor)
    if current.has_hooks_container and not current.hooks:
        editor.delete(("hooks",))


def _append_group(
    editor: JsoncEditor,
    document: QwenDocument,
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
    document: QwenDocument, additions: Dict[str, JsonObject]
) -> bool:
    if set(additions) != set(MANAGED_EVENTS):
        return False
    removals = managed_qwen_removals(document.hooks)
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


def render_qwen_document(
    document: QwenDocument,
    agent_id: Optional[str],
    additions: Dict[str, JsonObject],
) -> RenderedQwenDocument:
    if agent_id is None and _already_installed(document, additions):
        return RenderedQwenDocument(document, False, document.raw)
    editor = JsoncEditor(
        document.raw,
        f"{qwen_document_label(document)} at {document.file_path}",
        allow_trailing_commas=False,
    )
    _remove_managed(editor, document, agent_id)
    for event in MANAGED_EVENTS:
        group = additions.get(event)
        if group is not None:
            _append_group(editor, document, event, group)
    current = _current_document(document, editor)
    if not additions and document.owned_file and not current.root:
        return RenderedQwenDocument(document, True, None)
    return RenderedQwenDocument(
        document,
        editor.raw != document.raw,
        editor.raw,
    )
