"""Secure credential input for the Elydora CLI."""

from __future__ import annotations

import getpass
import os
import stat
import sys
import warnings
from typing import NamedTuple, Optional, Protocol


MAX_SECRET_FILE_BYTES = 64 * 1024


class InstallSecrets(NamedTuple):
    private_key: str
    token: Optional[str]


class SecretTerminal(Protocol):
    @property
    def interactive(self) -> bool:
        ...

    def read_hidden(self, prompt: str) -> str:
        ...


class _DefaultTerminal:
    @property
    def interactive(self) -> bool:
        return sys.stdin.isatty() and sys.stderr.isatty()

    def read_hidden(self, prompt: str) -> str:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                return getpass.getpass(prompt=prompt, stream=sys.stderr)
        except getpass.GetPassWarning as error:
            raise RuntimeError(
                "hidden input requires an interactive terminal"
            ) from error
        except (EOFError, KeyboardInterrupt) as error:
            raise RuntimeError("secret input cancelled") from error


def _parse_single_line_secret(raw: str, label: str, allow_empty: bool) -> str:
    if len(raw.encode("utf-8")) > MAX_SECRET_FILE_BYTES:
        raise ValueError(f"{label} exceeds {MAX_SECRET_FILE_BYTES} bytes")
    if raw.endswith("\r\n"):
        value = raw[:-2]
    elif raw.endswith("\n"):
        value = raw[:-1]
    else:
        value = raw
    if not allow_empty and not value:
        raise ValueError(f"{label} is empty")
    if "\r" in value or "\n" in value or "\0" in value:
        raise ValueError(f"{label} must contain exactly one line")
    return value


def _validate_secret_file(
    metadata: os.stat_result,
    path: str,
    label: str,
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} file is not a regular file: {path}")
    if metadata.st_size > MAX_SECRET_FILE_BYTES:
        raise ValueError(
            f"{label} file exceeds {MAX_SECRET_FILE_BYTES} bytes: {path}"
        )
    if os.name != "nt" and metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError(
            f"{label} file must be accessible only by its owner: {path}"
        )


def _read_secret_file(path: str, label: str) -> str:
    before = os.lstat(path)
    _validate_secret_file(before, path, label)

    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        file = os.fdopen(descriptor, "rb")
        descriptor = -1
        with file:
            after = os.fstat(file.fileno())
            _validate_secret_file(after, path, label)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise OSError(f"{label} file changed while opening: {path}")
            encoded = file.read(MAX_SECRET_FILE_BYTES + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    if len(encoded) > MAX_SECRET_FILE_BYTES:
        raise ValueError(
            f"{label} file exceeds {MAX_SECRET_FILE_BYTES} bytes: {path}"
        )
    try:
        raw = encoded.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{label} file must contain UTF-8 text: {path}") from error
    return _parse_single_line_secret(raw, label, False)


def resolve_install_secrets(
    *,
    private_key_file: Optional[str],
    token_file: Optional[str],
    terminal: Optional[SecretTerminal] = None,
) -> InstallSecrets:
    active_terminal = terminal if terminal is not None else _DefaultTerminal()

    if private_key_file:
        private_key = _read_secret_file(private_key_file, "private key")
    elif active_terminal.interactive:
        private_key = _parse_single_line_secret(
            active_terminal.read_hidden("Private key: "),
            "private key",
            False,
        )
    else:
        raise RuntimeError(
            "private key input requires an interactive terminal or "
            "--private_key_file <path>"
        )

    token: Optional[str]
    if token_file:
        token = _read_secret_file(token_file, "API token")
    elif active_terminal.interactive:
        token = (
            _parse_single_line_secret(
                active_terminal.read_hidden("API token (optional): "),
                "API token",
                True,
            )
            or None
        )
    else:
        token = None

    return InstallSecrets(private_key=private_key, token=token)
