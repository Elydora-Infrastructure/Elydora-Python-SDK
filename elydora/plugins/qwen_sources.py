"""Qwen Code 0.20 settings discovery, trust, and effective controls."""

from __future__ import annotations

from dataclasses import dataclass
import os
import re
import sys
import tempfile
from typing import Dict, List, Optional, Set, Tuple

from ._dotenv import parse_dotenv
from ._managed_files import MAX_SOURCE_BYTES, FileSnapshot, read_physical_file
from ._transaction import FilePrecondition
from .qwen_command import same_qwen_path
from .qwen_config import (
    QwenDocument,
    create_qwen_document,
    parse_qwen_document,
    parse_qwen_jsonc_object,
    qwen_document_label,
    qwen_source_label,
)
from .qwen_contract import validate_javascript_matchers


_HOME_ENV_KEYS = ("QWEN_HOME", "QWEN_RUNTIME_DIR")


@dataclass(frozen=True)
class QwenDisableControl:
    disabled: bool
    source: Optional[QwenDocument]


@dataclass(frozen=True)
class QwenSources:
    qwen_home: str
    system_defaults: QwenDocument
    user: QwenDocument
    workspace: QwenDocument
    system: QwenDocument
    workspace_active: bool
    workspace_trusted: bool
    disable_control: QwenDisableControl
    preconditions: Tuple[FilePrecondition, ...]


@dataclass(frozen=True)
class _RoutingResult:
    qwen_home: str
    preconditions: Tuple[FilePrecondition, ...]


def _default_qwen_home() -> str:
    home = os.path.expanduser("~")
    if not home or home == "~":
        home = tempfile.gettempdir()
    return os.path.join(home, ".qwen")


def _resolve_config_path(value: str) -> str:
    resolved = value
    if value == "~":
        resolved = os.path.expanduser("~")
    elif value.startswith(("~/", "~\\")):
        segments = [item for item in re.split(r"[/\\]+", value[2:]) if item]
        resolved = os.path.join(os.path.expanduser("~"), *segments)
    return resolved if os.path.isabs(resolved) else os.path.abspath(resolved)


def _environment_value(key: str) -> Tuple[bool, Optional[str]]:
    return key in os.environ, os.environ.get(key)


def _resolve_qwen_routing() -> _RoutingResult:
    values: Dict[str, Optional[str]] = {}
    owned: Set[str] = set()
    for key in _HOME_ENV_KEYS:
        present, value = _environment_value(key)
        values[key] = value
        if present:
            owned.add(key)
    if all(values.get(key) for key in _HOME_ENV_KEYS):
        return _RoutingResult(
            _resolve_config_path(values["QWEN_HOME"] or ""), ()
        )

    initial_qwen_home = values.get("QWEN_HOME")
    initial_directory = (
        _resolve_config_path(initial_qwen_home)
        if initial_qwen_home
        else _default_qwen_home()
    )
    candidates = [os.path.join(initial_directory, ".env")]
    if not initial_qwen_home:
        candidates.append(os.path.join(os.path.dirname(initial_directory), ".env"))
    preconditions: List[FilePrecondition] = []
    visited: Set[str] = set()

    def read_candidate(file_path: str) -> None:
        resolved = os.path.abspath(file_path)
        key = os.path.normcase(resolved)
        if key in visited:
            return
        visited.add(key)
        snapshot = read_physical_file(
            resolved, "Qwen Code home environment", MAX_SOURCE_BYTES
        )
        preconditions.append(FilePrecondition(
            resolved,
            "Qwen Code home environment",
            snapshot,
            MAX_SOURCE_BYTES,
        ))
        if snapshot is None:
            return
        parsed = parse_dotenv(snapshot.contents)
        for env_key in _HOME_ENV_KEYS:
            value = parsed.get(env_key)
            if value and env_key not in owned:
                values[env_key] = value
                owned.add(env_key)

    for candidate in candidates:
        read_candidate(candidate)
    discovered_home = values.get("QWEN_HOME")
    if discovered_home and discovered_home != initial_qwen_home:
        discovered_directory = _resolve_config_path(discovered_home)
        if not same_qwen_path(discovered_directory, initial_directory):
            read_candidate(os.path.join(discovered_directory, ".env"))
    resolved_home = values.get("QWEN_HOME")
    return _RoutingResult(
        _resolve_config_path(resolved_home) if resolved_home else _default_qwen_home(),
        tuple(preconditions),
    )


def resolve_qwen_home() -> str:
    return _resolve_qwen_routing().qwen_home


def _system_settings_path() -> str:
    configured = os.environ.get("QWEN_CODE_SYSTEM_SETTINGS_PATH")
    if configured:
        return os.path.abspath(configured)
    if sys.platform == "darwin":
        return "/Library/Application Support/QwenCode/settings.json"
    if os.name == "nt":
        return r"C:\ProgramData\qwen-code\settings.json"
    return "/etc/qwen-code/settings.json"


def _system_defaults_path(system_path: str) -> str:
    configured = os.environ.get("QWEN_CODE_SYSTEM_DEFAULTS_PATH")
    return (
        os.path.abspath(configured)
        if configured
        else os.path.join(os.path.dirname(system_path), "system-defaults.json")
    )


def _read_document(kind: str, file_path: str) -> QwenDocument:
    snapshot = read_physical_file(
        file_path, qwen_source_label(kind), MAX_SOURCE_BYTES
    )
    if snapshot is None:
        return create_qwen_document(kind, file_path)
    return parse_qwen_document(
        kind=kind,
        exists=True,
        file_path=file_path,
        raw=snapshot.contents,
        snapshot=snapshot,
    )


def _canonical_path(file_path: str) -> str:
    try:
        return os.path.realpath(file_path)
    except OSError:
        return os.path.abspath(file_path)


def _comparison_path(file_path: str) -> str:
    return os.path.normcase(os.path.abspath(file_path))


def _is_within(child: str, parent: str) -> bool:
    try:
        relative = os.path.relpath(_comparison_path(child), _comparison_path(parent))
    except ValueError:
        return False
    return relative == "." or (
        relative != ".."
        and not relative.startswith(".." + os.sep)
        and not os.path.isabs(relative)
    )


def _workspace_trust(
    system: QwenDocument,
    user: QwenDocument,
    qwen_home: str,
    workspace_path: str,
) -> Tuple[bool, Optional[FilePrecondition]]:
    enabled = (
        user.folder_trust_enabled
        if user.folder_trust_enabled is not None
        else system.folder_trust_enabled
    )
    if enabled is not True:
        return True, None
    configured = os.environ.get("QWEN_CODE_TRUSTED_FOLDERS_PATH")
    file_path = (
        os.path.abspath(configured)
        if configured
        else os.path.join(qwen_home, "trustedFolders.json")
    )
    snapshot = read_physical_file(
        file_path, "Qwen Code trusted folders", MAX_SOURCE_BYTES
    )
    precondition = FilePrecondition(
        file_path,
        "Qwen Code trusted folders",
        snapshot,
        MAX_SOURCE_BYTES,
    )
    if snapshot is None:
        return True, precondition
    rules = parse_qwen_jsonc_object(
        snapshot.contents, f"Qwen Code trusted folders at {file_path}"
    )
    allowed_levels = {"TRUST_FOLDER", "TRUST_PARENT", "DO_NOT_TRUST"}
    for rule_path, level in rules.items():
        if level not in allowed_levels:
            raise ValueError(
                "Qwen Code trusted folders has invalid trust level for "
                f'"{rule_path}"'
            )
    workspace = _canonical_path(workspace_path)
    for rule_path, level in rules.items():
        canonical_rule = _canonical_path(rule_path)
        trust_root = (
            os.path.dirname(canonical_rule)
            if level == "TRUST_PARENT"
            else canonical_rule
        )
        if level in {"TRUST_FOLDER", "TRUST_PARENT"} and _is_within(
            workspace, trust_root
        ):
            return True, precondition
    for rule_path, level in rules.items():
        if level == "DO_NOT_TRUST" and _comparison_path(
            workspace
        ) == _comparison_path(_canonical_path(rule_path)):
            return False, precondition
    return True, precondition


def _effective_disable(
    system_defaults: QwenDocument,
    user: QwenDocument,
    workspace: QwenDocument,
    system: QwenDocument,
    use_workspace: bool,
) -> QwenDisableControl:
    disabled = False
    source: Optional[QwenDocument] = None
    documents = [system_defaults, user]
    if use_workspace:
        documents.append(workspace)
    documents.append(system)
    for document in documents:
        if document.disable_all_hooks is None:
            continue
        disabled = document.disable_all_hooks
        source = document
    return QwenDisableControl(disabled, source)


def _source_precondition(document: QwenDocument) -> FilePrecondition:
    return FilePrecondition(
        document.file_path,
        qwen_document_label(document),
        document.snapshot,
        MAX_SOURCE_BYTES,
    )


def _deduplicate_preconditions(
    values: List[FilePrecondition],
) -> Tuple[FilePrecondition, ...]:
    result: Dict[str, FilePrecondition] = {}
    for value in values:
        result.setdefault(_comparison_path(value.file_path), value)
    return tuple(result.values())


def read_qwen_sources() -> QwenSources:
    routing = _resolve_qwen_routing()
    system_path = _system_settings_path()
    workspace_path = os.path.join(os.getcwd(), ".qwen", "settings.json")
    system = _read_document("system", system_path)
    system_defaults = _read_document(
        "system-defaults", _system_defaults_path(system_path)
    )
    user = _read_document(
        "user", os.path.join(routing.qwen_home, "settings.json")
    )
    canonical_workspace = _canonical_path(os.getcwd())
    canonical_home = _canonical_path(os.path.expanduser("~"))
    workspace_active = _comparison_path(canonical_workspace) != _comparison_path(
        canonical_home
    )
    workspace = (
        _read_document("workspace", workspace_path)
        if workspace_active
        else create_qwen_document("workspace", workspace_path)
    )
    if workspace_active:
        workspace_trusted, trust_precondition = _workspace_trust(
            system, user, routing.qwen_home, canonical_workspace
        )
    else:
        workspace_trusted, trust_precondition = False, None
    validate_javascript_matchers([
        system_defaults.hooks,
        user.hooks,
        workspace.hooks,
        system.hooks,
    ])
    preconditions = list(routing.preconditions)
    preconditions.extend([
        _source_precondition(system_defaults),
        _source_precondition(user),
    ])
    if workspace_active:
        preconditions.append(_source_precondition(workspace))
    preconditions.append(_source_precondition(system))
    if trust_precondition is not None:
        preconditions.append(trust_precondition)
    return QwenSources(
        qwen_home=routing.qwen_home,
        system_defaults=system_defaults,
        user=user,
        workspace=workspace,
        system=system,
        workspace_active=workspace_active,
        workspace_trusted=workspace_trusted,
        disable_control=_effective_disable(
            system_defaults,
            user,
            workspace,
            system,
            workspace_active and workspace_trusted,
        ),
        preconditions=_deduplicate_preconditions(preconditions),
    )


def require_qwen_hooks_enabled(sources: QwenSources) -> None:
    if not sources.disable_control.disabled:
        return
    source = sources.disable_control.source
    location = (
        f"{qwen_document_label(source)} at {source.file_path}"
        if source is not None
        else "effective settings"
    )
    raise ValueError(
        f"Qwen Code hooks are disabled by disableAllHooks in {location}"
    )
