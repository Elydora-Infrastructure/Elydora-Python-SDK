"""Factory Droid source discovery and transactional multi-file I/O."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import stat
import tempfile
from typing import List, Optional, Sequence
from uuid import uuid4

from .droid_config import (
    DroidSources,
    RenderedDocument,
    create_settings_document,
    parse_document,
)
from .droid_contract import AGENT_KEY, JsonObject, RuntimeContract, same_agent_id


@dataclass(frozen=True)
class FileChange:
    file_path: str
    label: str
    original: Optional[str]
    next_source: Optional[str]
    mode: int
    original_mode: Optional[int]


@dataclass
class StagedChange:
    change: FileChange
    temporary_path: Optional[str]
    rollback_path: Optional[str]
    committed: bool = False


def _factory_paths() -> tuple[str, str, str]:
    directory = os.path.join(os.path.expanduser("~"), ".factory")
    return (
        os.path.join(directory, "hooks.json"),
        os.path.join(directory, "hooks", "hooks.json"),
        os.path.join(directory, "settings.json"),
    )


def _read_optional(file_path: str, label: str) -> Optional[str]:
    try:
        with open(file_path, "r", encoding="utf-8", newline="") as file:
            return file.read()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise OSError(f"Read {label} at {file_path}: {error}") from error


def read_sources() -> DroidSources:
    root_path, legacy_path, settings_path = _factory_paths()
    root_raw = _read_optional(root_path, "Factory Droid hooks")
    settings_raw = _read_optional(settings_path, "Factory Droid settings")
    primary = None
    if root_raw is not None:
        primary = parse_document(
            exists=True,
            file_path=root_path,
            kind="hooks",
            raw=root_raw,
        )
    else:
        legacy_raw = _read_optional(legacy_path, "Factory Droid legacy hooks")
        if legacy_raw is not None:
            primary = parse_document(
                exists=True,
                file_path=legacy_path,
                kind="legacy",
                raw=legacy_raw,
            )
    settings = (
        create_settings_document(settings_path)
        if settings_raw is None
        else parse_document(
            exists=True,
            file_path=settings_path,
            kind="settings",
            raw=settings_raw,
        )
    )
    return DroidSources(root_path, primary, settings)


def _existing_mode(file_path: str) -> Optional[int]:
    try:
        return stat.S_IMODE(os.stat(file_path).st_mode)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise OSError(f"Read file mode at {file_path}: {error}") from error


def file_change(
    file_path: str,
    label: str,
    next_source: Optional[str],
    mode: int,
) -> Optional[FileChange]:
    original = _read_optional(file_path, label)
    if original == next_source:
        return None
    return FileChange(
        file_path,
        label,
        original,
        next_source,
        mode,
        _existing_mode(file_path),
    )


def rendered_change(rendered: RenderedDocument) -> Optional[FileChange]:
    if not rendered.changed:
        return None
    if rendered.document.kind == "settings":
        label = "Factory Droid settings"
    elif rendered.document.kind == "legacy":
        label = "Factory Droid legacy hooks"
    else:
        label = "Factory Droid hooks"
    return FileChange(
        rendered.document.file_path,
        label,
        rendered.document.raw if rendered.document.exists else None,
        rendered.next_source,
        0o600,
        _existing_mode(rendered.document.file_path),
    )


def _remove_optional(file_path: Optional[str]) -> None:
    if not file_path:
        return
    try:
        os.remove(file_path)
    except FileNotFoundError:
        return


def _cleanup_paths(paths: Sequence[Optional[str]]) -> List[str]:
    errors = []
    for path in paths:
        try:
            _remove_optional(path)
        except OSError as error:
            errors.append(str(error))
    return errors


def _write_staged(
    directory: str,
    basename: str,
    suffix: str,
    content: str,
    mode: int,
    label: str,
) -> str:
    descriptor = -1
    temporary_path = ""
    try:
        descriptor, temporary_path = tempfile.mkstemp(
            prefix=f".{basename}.",
            suffix=suffix,
            dir=directory,
            text=True,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as file:
            descriptor = -1
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        os.chmod(temporary_path, mode)
        return temporary_path
    except Exception as error:
        failures = []
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as close_error:
                failures.append(f"close failed: {close_error}")
        failures.extend(_cleanup_paths((temporary_path,)))
        suffix = f"; cleanup failed: {'; '.join(failures)}" if failures else ""
        raise OSError(f"Stage {label}: {error}{suffix}") from error


def _assert_unchanged(change: FileChange) -> None:
    current = _read_optional(change.file_path, change.label)
    if current != change.original:
        raise OSError(f"{change.label} changed during installation: {change.file_path}")


def _stage(change: FileChange) -> StagedChange:
    _assert_unchanged(change)
    directory = os.path.dirname(change.file_path)
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    except OSError as error:
        raise OSError(f"Create directory for {change.label} at {directory}: {error}") from error
    basename = os.path.basename(change.file_path)
    temporary_path = None
    rollback_path = None
    try:
        if change.next_source is not None:
            temporary_path = _write_staged(
                directory,
                basename,
                ".tmp",
                change.next_source,
                change.mode,
                change.label,
            )
        if change.original is not None and change.next_source is not None:
            rollback_path = _write_staged(
                directory,
                basename,
                ".rollback",
                change.original,
                change.original_mode or change.mode,
                f"{change.label} rollback",
            )
        elif change.original is not None:
            rollback_path = os.path.join(
                directory,
                f".{basename}.{uuid4().hex}.rollback",
            )
            if os.path.lexists(rollback_path):
                raise FileExistsError(f"Rollback path already exists: {rollback_path}")
        return StagedChange(change, temporary_path, rollback_path)
    except Exception as error:
        failures = _cleanup_paths((temporary_path, rollback_path))
        suffix = f"; cleanup failed: {'; '.join(failures)}" if failures else ""
        raise OSError(f"Stage {change.label}: {error}{suffix}") from error


def _commit(staged: StagedChange) -> None:
    _assert_unchanged(staged.change)
    if staged.change.next_source is None:
        if staged.rollback_path is None:
            raise OSError(f"Missing rollback path for {staged.change.label}")
        os.replace(staged.change.file_path, staged.rollback_path)
    else:
        if staged.temporary_path is None:
            raise OSError(f"Missing staged file for {staged.change.label}")
        os.replace(staged.temporary_path, staged.change.file_path)
    staged.committed = True


def _rollback(staged: StagedChange) -> None:
    if not staged.committed:
        return
    if staged.change.original is None:
        _remove_optional(staged.change.file_path)
        return
    if staged.rollback_path is None:
        raise OSError(f"Missing rollback data for {staged.change.label}")
    os.replace(staged.rollback_path, staged.change.file_path)


def _cleanup(staged: StagedChange) -> None:
    _remove_optional(staged.temporary_path)
    _remove_optional(staged.rollback_path)


def write_changes(changes: Sequence[FileChange], label: str) -> None:
    filtered = [change for change in changes if change.original != change.next_source]
    if not filtered:
        return
    paths = [os.path.normcase(os.path.abspath(change.file_path)) for change in filtered]
    if len(paths) != len(set(paths)):
        raise ValueError(f"{label} contains duplicate file targets")
    staged: List[StagedChange] = []
    try:
        for change in filtered:
            staged.append(_stage(change))
        for item in staged:
            _commit(item)
    except Exception as error:
        recovery_errors = []
        for item in reversed(staged):
            try:
                _rollback(item)
            except OSError as rollback_error:
                recovery_errors.append(str(rollback_error))
        for item in staged:
            try:
                _cleanup(item)
            except OSError as cleanup_error:
                recovery_errors.append(str(cleanup_error))
        suffix = (
            f"; recovery failed: {'; '.join(recovery_errors)}"
            if recovery_errors
            else ""
        )
        raise OSError(f"{label}: {error}{suffix}") from error
    cleanup_errors = []
    for item in staged:
        try:
            _cleanup(item)
        except OSError as error:
            cleanup_errors.append(str(error))
    if cleanup_errors:
        raise OSError(f"{label} cleanup failed: {'; '.join(cleanup_errors)}")


def regular_file_exists(file_path: str, label: str) -> bool:
    try:
        return stat.S_ISREG(os.stat(file_path).st_mode)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise OSError(f"Read {label} at {file_path}: {error}") from error


def require_runtime(file_path: str, label: str) -> None:
    if not file_path:
        raise ValueError(f"{label} path is required")
    if not regular_file_exists(file_path, label):
        raise FileNotFoundError(f"{label} is missing: {file_path}")


def _read_runtime_config(file_path: str) -> Optional[JsonObject]:
    raw = _read_optional(file_path, "Elydora runtime config")
    if raw is None:
        return None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError(
            f"Failed to parse Elydora runtime config at {file_path}: {error}"
        ) from error
    if not isinstance(value, dict):
        raise ValueError(
            f"Elydora runtime config at {file_path} must contain a JSON object"
        )
    return value


def runtime_files_exist(contracts: Sequence[RuntimeContract]) -> bool:
    for contract in contracts:
        agent_directory = os.path.dirname(contract.guard_path)
        config = _read_runtime_config(os.path.join(agent_directory, "config.json"))
        config_agent_id = config.get("agent_id") if config else None
        if (
            config is None
            or config.get("agent_name") != AGENT_KEY
            or not isinstance(config_agent_id, str)
            or not same_agent_id(config_agent_id, contract.agent_id)
        ):
            continue
        if regular_file_exists(
            contract.guard_path, "Elydora guard runtime"
        ) and regular_file_exists(contract.audit_path, "Elydora audit runtime"):
            return True
    return False


def display_config_path(sources: DroidSources) -> str:
    if sources.primary is not None:
        return sources.primary.file_path
    if sources.settings.exists and sources.settings.has_hooks_container:
        return sources.settings.file_path
    return sources.root_path
