"""Factory Droid read-only hierarchy and organization policy resolution."""

from __future__ import annotations

from dataclasses import dataclass
import os
import stat
import sys
from typing import List, Optional, Tuple

from ._jsonc import JsoncEditor
from ._managed_files import (
    FileSnapshot,
    MAX_SOURCE_BYTES,
    physical_directory_exists,
    read_physical_file,
)
from ._transaction import FilePrecondition


@dataclass(frozen=True)
class PolicyLocation:
    file_path: str
    label: str


@dataclass(frozen=True)
class PolicyLayer:
    file_path: str
    label: str
    snapshot: Optional[FileSnapshot]
    hooks_disabled: Optional[bool]
    allow_managed_hooks_only: Optional[bool]
    show_hook_output: Optional[bool]


@dataclass(frozen=True)
class PolicyOrigin:
    file_path: str
    label: str


@dataclass(frozen=True)
class DroidPolicyState:
    allow_managed_hooks_only_by: Optional[PolicyOrigin]
    hooks_disabled: Optional[bool]
    hooks_disabled_by: Optional[PolicyOrigin]
    preconditions: Tuple[FilePrecondition, ...]


def _optional_boolean(root: dict, field: str, label: str) -> Optional[bool]:
    value = root.get(field)
    if field in root and not isinstance(value, bool):
        raise ValueError(f'{label} field "{field}" must be a boolean')
    return value


def _managed_settings_path() -> str:
    if sys.platform == "darwin":
        return "/Library/Application Support/Factory/settings.json"
    if os.name == "nt":
        program_files = os.environ.get("ProgramFiles") or r"C:\Program Files"
        return os.path.join(program_files, "Factory", "settings.json")
    return "/etc/factory/settings.json"


def _read_layer(location: PolicyLocation) -> PolicyLayer:
    physical_directory_exists(
        os.path.dirname(location.file_path),
        f"{location.label} directory",
    )
    snapshot = read_physical_file(
        location.file_path,
        location.label,
        MAX_SOURCE_BYTES,
    )
    if snapshot is None:
        return PolicyLayer(
            location.file_path,
            location.label,
            None,
            None,
            None,
            None,
        )
    editor = JsoncEditor(
        snapshot.contents,
        f"{location.label} at {location.file_path}",
    )
    root = editor.value
    if not isinstance(root, dict):
        raise ValueError(
            f"{location.label} at {location.file_path} "
            "must contain a JSON object"
        )
    return PolicyLayer(
        location.file_path,
        location.label,
        snapshot,
        _optional_boolean(root, "hooksDisabled", location.label),
        _optional_boolean(root, "allowManagedHooksOnly", location.label),
        _optional_boolean(root, "showHookOutput", location.label),
    )


def _git_root(start: str) -> Optional[str]:
    current = os.path.abspath(start)
    while True:
        marker = os.path.join(current, ".git")
        try:
            metadata = os.lstat(marker)
        except (FileNotFoundError, NotADirectoryError):
            pass
        except OSError as error:
            raise OSError(
                f"Inspect Factory Droid project marker at {marker}: {error}"
            ) from error
        else:
            if stat.S_ISLNK(metadata.st_mode) or not (
                stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)
            ):
                raise OSError(
                    f"Factory Droid project marker is not physical: {marker}"
                )
            return current
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent


def _project_directories(root: str, current: str) -> List[str]:
    directories = [root]
    try:
        relative = os.path.relpath(current, root)
    except ValueError:
        return directories
    if relative in {"", "."} or relative == os.pardir:
        return directories
    if relative.startswith(os.pardir + os.sep) or os.path.isabs(relative):
        return directories
    directory = root
    for segment in relative.split(os.sep):
        if not segment:
            continue
        directory = os.path.join(directory, segment)
        directories.append(directory)
    return directories


def _project_locations() -> List[Tuple[PolicyLocation, PolicyLocation]]:
    current = os.path.abspath(os.getcwd())
    root = _git_root(current) or current
    locations = []
    for index, directory in enumerate(_project_directories(root, current)):
        factory = os.path.join(directory, ".factory")
        scope = "project" if index == 0 else f"folder {directory}"
        locations.append((
            PolicyLocation(
                os.path.join(factory, "settings.json"),
                f"Factory Droid {scope} settings",
            ),
            PolicyLocation(
                os.path.join(factory, "settings.local.json"),
                f"Factory Droid {scope} local settings",
            ),
        ))
    return locations


def _scope_value(layers: Tuple[PolicyLayer, PolicyLayer]) -> Optional[PolicyLayer]:
    settings, local = layers
    if local.hooks_disabled is not None:
        return local
    if settings.hooks_disabled is not None:
        return settings
    return None


def read_droid_policy() -> DroidPolicyState:
    managed = _read_layer(PolicyLocation(
        _managed_settings_path(),
        "Factory Droid system-managed settings",
    ))
    project_layers = [
        (_read_layer(scope[0]), _read_layer(scope[1]))
        for scope in _project_locations()
    ]
    allow_managed = (
        PolicyOrigin(managed.file_path, managed.label)
        if managed.allow_managed_hooks_only is True
        else None
    )
    selected = next(
        (
            layer
            for layer in (
                managed,
                *(_scope_value(scope) for scope in project_layers),
            )
            if layer is not None and layer.hooks_disabled is not None
        ),
        None,
    )
    flattened = [managed]
    for scope in project_layers:
        flattened.extend(scope)
    return DroidPolicyState(
        allow_managed,
        selected.hooks_disabled if selected is not None else None,
        (
            PolicyOrigin(selected.file_path, selected.label)
            if selected is not None
            else None
        ),
        tuple(
            FilePrecondition(
                layer.file_path,
                layer.label,
                layer.snapshot,
                MAX_SOURCE_BYTES,
            )
            for layer in flattened
        ),
    )
