from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from elydora import cli


AGENT_ID = "agent-1"
AGENT_NAME = "opencode"
PRIVATE_KEY = base64.urlsafe_b64encode(bytes([19]) * 32).rstrip(b"=").decode()


def set_home(monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def write_secret(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o600)


def write_error_log(path: Path, chunks: int = 1) -> str:
    digest = hashlib.sha256()
    block = b"opaque historical error\n" * 4096
    with path.open("wb") as file:
        for _index in range(chunks):
            file.write(block)
            digest.update(block)
    if os.name != "nt":
        path.chmod(0o600)
    return digest.hexdigest()


def stream_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def prepare_runtime(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    agent_name: str = AGENT_NAME,
) -> tuple[Path, Path]:
    home = tmp_path / "home"
    root = home / ".elydora"
    agent = root / AGENT_ID
    set_home(monkeypatch, home)
    write_json(
        agent / "config.json",
        {"agent_id": AGENT_ID, "agent_name": agent_name},
    )
    return root, agent


def uninstall_args(agent_name: str = AGENT_NAME) -> argparse.Namespace:
    return cli.build_parser().parse_args(
        [
            "uninstall",
            "--agent",
            agent_name,
            "--agent_id",
            AGENT_ID,
        ]
    )
