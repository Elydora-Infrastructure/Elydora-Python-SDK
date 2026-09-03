"""Fail-fast, atomic file helpers shared by hook adapters."""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict


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
