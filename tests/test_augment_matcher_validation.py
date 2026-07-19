from __future__ import annotations

import subprocess
from typing import NoReturn

import pytest

from elydora.plugins import augment


MATCHER_HOOKS = {
    "PreToolUse": [
        {
            "matcher": "(?<tool>launch-process)",
            "hooks": [],
        }
    ]
}


def test_matcher_validation_requires_node(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(augment.shutil, "which", lambda _: None)

    with pytest.raises(FileNotFoundError, match="Node.js runtime is required"):
        augment._validate_matchers(MATCHER_HOOKS)


def test_matcher_validation_skips_node_without_matchers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_lookup(_: str) -> NoReturn:
        raise AssertionError("Node.js lookup must be skipped")

    monkeypatch.setattr(augment.shutil, "which", fail_lookup)

    augment._validate_matchers({"SessionStart": [{"hooks": []}]})


def test_matcher_validation_surfaces_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def time_out(*args: object, **kwargs: object) -> NoReturn:
        raise subprocess.TimeoutExpired(cmd="node", timeout=10)

    monkeypatch.setattr(augment.shutil, "which", lambda _: "node")
    monkeypatch.setattr(augment.subprocess, "run", time_out)

    with pytest.raises(TimeoutError, match="timed out after 10 seconds"):
        augment._validate_matchers(MATCHER_HOOKS)
