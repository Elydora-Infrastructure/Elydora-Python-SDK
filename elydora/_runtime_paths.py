"""Validated local runtime paths for agent installations."""

from __future__ import annotations

import os
import re
import stat


_INVALID_FILENAME_CHARACTERS = re.compile(r'[<>:"|?*\x00-\x1f]')
_WINDOWS_DEVICE_NAME = re.compile(
    r"^(?:con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³])(?:\.|$)",
    re.IGNORECASE,
)


def runtime_root() -> str:
    """Return the shared per-user root for Elydora agent runtimes."""
    return os.path.join(os.path.expanduser("~"), ".elydora")


def resolve_agent_directory(root: str, agent_id: str) -> str:
    """Resolve one cross-platform-safe agent directory directly under *root*."""
    if (
        not agent_id
        or _INVALID_FILENAME_CHARACTERS.search(agent_id)
        or "/" in agent_id
        or "\\" in agent_id
        or agent_id in {".", ".."}
        or agent_id.startswith(" ")
        or agent_id.endswith((".", " "))
        or _WINDOWS_DEVICE_NAME.match(agent_id)
    ):
        raise ValueError(f"Invalid agent ID for local storage: {agent_id!r}")

    resolved_root = os.path.abspath(root)
    candidate = os.path.abspath(os.path.join(resolved_root, agent_id))
    try:
        relative = os.path.relpath(candidate, resolved_root)
    except ValueError as error:
        raise ValueError(
            f"Agent ID escapes the local storage directory: {agent_id!r}"
        ) from error
    if (
        relative in {"", ".", ".."}
        or os.path.isabs(relative)
        or relative.startswith(f"..{os.sep}")
        or os.sep in relative
    ):
        raise ValueError(
            f"Agent ID escapes the local storage directory: {agent_id!r}"
        )
    return candidate


def ensure_private_directory(path: str) -> None:
    """Create an owner-only directory and reject symbolic-link targets."""
    os.makedirs(path, mode=0o700, exist_ok=True)
    metadata = os.lstat(path)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise OSError(f"Private directory path is not a physical directory: {path}")
    if os.name != "nt":
        os.chmod(path, 0o700)


def require_physical_directory(path: str) -> bool:
    """Return whether a path is an existing physical directory."""
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return False
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise OSError(f"Agent runtime path is not a physical directory: {path}")
    return True


def require_physical_file(path: str) -> bool:
    """Return whether a path is an existing physical regular file."""
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise OSError(f"Agent runtime config is not a physical file: {path}")
    return True
