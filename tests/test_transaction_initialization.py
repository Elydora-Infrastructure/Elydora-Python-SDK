from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest

from elydora.plugins import _transaction


def _subprocess_environment(home: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["HOME"] = str(home)
    environment["USERPROFILE"] = str(home)
    return environment


def test_process_exit_after_secret_staging_recovers_owned_artifact(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    target = tmp_path / "target.txt"
    target.write_bytes(b"old\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    script = """
import os
import sys
from elydora.plugins import _transaction, _transaction_staging

target = sys.argv[1]
change = _transaction.source_change(target, "target", "old\\n", "secret-new\\n", 0o600)
assert change is not None
real_write_staged = _transaction_staging.write_staged

def terminate_after_secret_staging(*args, **kwargs):
    real_write_staged(*args, **kwargs)
    os._exit(78)

_transaction_staging.write_staged = terminate_after_secret_staging
_transaction.write_changes([change], "initialization crash recovery")
"""

    completed = subprocess.run(
        [sys.executable, "-c", script, str(target)],
        cwd=Path(__file__).resolve().parents[1],
        env=_subprocess_environment(home),
        check=False,
    )

    assert completed.returncode == 78
    staged = list(tmp_path.glob(".target.txt.*.tmp"))
    assert len(staged) == 1
    assert staged[0].read_text(encoding="utf-8") == "secret-new\n"
    try:
        _transaction.recover_pending_transactions()
        assert target.read_text(encoding="utf-8") == "old\n"
        assert list(tmp_path.glob(".target.txt.*.tmp")) == []
    finally:
        for artifact in tmp_path.glob(".target.txt.*.tmp"):
            artifact.unlink()
