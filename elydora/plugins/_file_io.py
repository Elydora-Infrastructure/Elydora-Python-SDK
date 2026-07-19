"""Fail-fast, atomic file helpers shared by hook adapters."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from typing import Any, Dict, Optional


JsonObject = Dict[str, Any]


def _cleanup_failed_write(path: str, label: str, cause: Exception) -> None:
    if not path:
        return
    try:
        os.remove(path)
    except FileNotFoundError:
        return
    except OSError as cleanup_error:
        raise OSError(
            f"Write {label} failed: {cause}; cleanup of {path} failed: {cleanup_error}"
        ) from cause


def write_text_atomic(path: str, content: str, mode: int, label: str) -> None:
    directory = os.path.dirname(path)
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    except OSError as error:
        raise OSError(f"Create directory for {label} at {directory}: {error}") from error

    descriptor = -1
    temporary_path = ""
    try:
        descriptor, temporary_path = tempfile.mkstemp(
            prefix=f".{os.path.basename(path)}.",
            suffix=".tmp",
            dir=directory,
            text=True,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as file:
            descriptor = -1
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, path)
    except Exception as error:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as close_error:
                _cleanup_failed_write(temporary_path, label, close_error)
                raise OSError(
                    f"Write {label} at {path} failed: {error}; "
                    f"close failed: {close_error}"
                ) from error
        _cleanup_failed_write(temporary_path, label, error)
        raise OSError(f"Write {label} at {path}: {error}") from error


def write_json_atomic(path: str, value: JsonObject, mode: int, label: str) -> None:
    write_text_atomic(path, json.dumps(value, indent=2) + "\n", mode, label)


def remove_file(path: str, label: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        return
    except OSError as error:
        raise OSError(f"Remove {label} at {path}: {error}") from error


def regular_file_exists(path: str, label: str) -> bool:
    try:
        metadata = os.stat(path)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise OSError(f"Read {label} at {path}: {error}") from error
    return stat.S_ISREG(metadata.st_mode)


def require_runtime(path: str, label: str) -> None:
    if not path:
        raise ValueError(f"{label} path is required")
    if not regular_file_exists(path, label):
        raise FileNotFoundError(f"{label} is missing: {path}")


def read_json(path: str, label: str) -> Optional[JsonObject]:
    try:
        with open(path, "r", encoding="utf-8") as file:
            raw = file.read()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise OSError(f"Read {label} at {path}: {error}") from error
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError(f"Failed to parse {label} at {path}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} at {path} must contain a JSON object")
    return value
