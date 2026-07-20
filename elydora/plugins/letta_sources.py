"""Letta Code 0.28 settings discovery and effective hook controls."""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Dict, Optional, Tuple

from ._managed_files import (
    MAX_SOURCE_BYTES,
    physical_directory_exists,
    read_physical_file,
)
from ._transaction import FilePrecondition
from .letta_command import same_letta_path
from .letta_config import (
    LettaDocument,
    create_letta_document,
    letta_document_label,
    letta_source_label,
    parse_letta_document,
)


@dataclass(frozen=True)
class LettaDisableControl:
    disabled: bool
    source: Optional[LettaDocument]


@dataclass(frozen=True)
class LettaSources:
    home_directory: str
    global_settings: LettaDocument
    project: LettaDocument
    project_local: LettaDocument
    project_active: bool
    disable_control: LettaDisableControl
    preconditions: Tuple[FilePrecondition, ...]


def _home_directory() -> str:
    home = os.environ.get("HOME") or os.path.expanduser("~")
    return os.path.abspath(home)


def _comparison_path(file_path: str) -> str:
    return os.path.normcase(os.path.abspath(file_path))


def _canonical_path(file_path: str) -> str:
    return os.path.realpath(file_path)


def _read_document(kind: str, file_path: str) -> LettaDocument:
    snapshot = read_physical_file(
        file_path, letta_source_label(kind), MAX_SOURCE_BYTES
    )
    if snapshot is None:
        return create_letta_document(kind, file_path)
    return parse_letta_document(
        kind=kind,
        exists=True,
        file_path=file_path,
        raw=snapshot.contents,
        snapshot=snapshot,
    )


def _source_precondition(document: LettaDocument) -> FilePrecondition:
    return FilePrecondition(
        document.file_path,
        letta_document_label(document),
        document.snapshot,
        MAX_SOURCE_BYTES,
    )


def _deduplicate_preconditions(
    values: list[FilePrecondition],
) -> Tuple[FilePrecondition, ...]:
    result: Dict[str, FilePrecondition] = {}
    for value in values:
        result.setdefault(_comparison_path(value.file_path), value)
    return tuple(result.values())


def _effective_disable(
    global_settings: LettaDocument,
    project: LettaDocument,
    project_local: LettaDocument,
    project_active: bool,
) -> LettaDisableControl:
    if global_settings.hooks.get("disabled") is False:
        return LettaDisableControl(False, global_settings)
    if global_settings.hooks.get("disabled") is True:
        return LettaDisableControl(True, global_settings)
    if project_active and project.hooks.get("disabled") is True:
        return LettaDisableControl(True, project)
    if project_local.hooks.get("disabled") is True:
        return LettaDisableControl(True, project_local)
    return LettaDisableControl(False, None)


def read_letta_sources() -> LettaSources:
    home_directory = _home_directory()
    workspace = os.path.abspath(os.getcwd())
    global_directory = os.path.join(home_directory, ".letta")
    project_directory = os.path.join(workspace, ".letta")
    physical_directory_exists(home_directory, "Letta Code home directory")
    physical_directory_exists(
        global_directory, "Letta Code global configuration directory"
    )
    if not same_letta_path(project_directory, global_directory):
        physical_directory_exists(
            project_directory, "Letta Code project configuration directory"
        )
    global_path = os.path.join(global_directory, "settings.json")
    project_path = os.path.join(project_directory, "settings.json")
    local_path = os.path.join(project_directory, "settings.local.json")
    project_active = _comparison_path(_canonical_path(workspace)) != _comparison_path(
        _canonical_path(home_directory)
    )
    global_settings = _read_document("global", global_path)
    project = (
        _read_document("project", project_path)
        if project_active
        else create_letta_document("project", project_path)
    )
    project_local = _read_document("project-local", local_path)
    preconditions = [_source_precondition(global_settings)]
    if project_active:
        preconditions.append(_source_precondition(project))
    preconditions.append(_source_precondition(project_local))
    return LettaSources(
        home_directory,
        global_settings,
        project,
        project_local,
        project_active,
        _effective_disable(
            global_settings, project, project_local, project_active
        ),
        _deduplicate_preconditions(preconditions),
    )


def require_letta_hooks_enabled(sources: LettaSources) -> None:
    if not sources.disable_control.disabled:
        return
    source = sources.disable_control.source
    location = (
        f"{letta_document_label(source)} at {source.file_path}"
        if source is not None
        else "effective settings"
    )
    raise ValueError(
        f"Letta Code hooks are disabled by hooks.disabled in {location}"
    )
