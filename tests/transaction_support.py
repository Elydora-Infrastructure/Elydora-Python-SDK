from __future__ import annotations

import os
from pathlib import Path


from elydora.plugins import _transaction


def write_source(path: Path, source: str) -> None:
    path.write_bytes(source.encode("utf-8"))


def make_change(
    path: Path,
    original: str | None,
    next_source: str | None,
    mode: int = 0o600,
    enforce_mode: bool = False,
) -> _transaction.FileChange:
    change = _transaction.source_change(
        str(path),
        path.name,
        original,
        next_source,
        mode,
        enforce_mode=enforce_mode,
    )
    assert change is not None
    return change


def transaction_subprocess_environment(home: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["HOME"] = str(home)
    environment["USERPROFILE"] = str(home)
    return environment


def swap_directory(parent: Path, backup: Path, redirected: Path) -> None:
    parent.rename(backup)
    redirected.rename(parent)
