from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import sys

from elydora.plugins.hook_template import generate_hook_script


MAX_ERROR_LOG_BYTES = 2 * 1024 * 1024
LOG_RUNNER = """
import sys

namespace = {"__name__": "elydora_generated_hook_test"}
with open(sys.argv[1], encoding="utf-8") as source:
    exec(compile(source.read(), sys.argv[1], "exec"), namespace)
namespace["log_error"](RuntimeError(sys.argv[2]))
"""
LARGE_LOG_RUNNER = """
import sys

namespace = {"__name__": "elydora_generated_hook_test"}
with open(sys.argv[1], encoding="utf-8") as source:
    exec(compile(source.read(), sys.argv[1], "exec"), namespace)
namespace["log_error"](RuntimeError("x" * (128 * 1024)))
"""


def prepare_hook(tmp_path: Path) -> tuple[Path, Path, dict[str, str]]:
    agent_directory = tmp_path / ".elydora" / "agent-1"
    agent_directory.mkdir(parents=True)
    script_path = tmp_path / "hook.py"
    script_path.write_text(
        generate_hook_script(
            org_id="org-1",
            agent_id="agent-1",
            kid="kid-1",
            base_url="https://api.elydora.test",
        ),
        encoding="utf-8",
    )
    environment = {
        **os.environ,
        "HOME": str(tmp_path),
        "USERPROFILE": str(tmp_path),
    }
    return script_path, agent_directory / "error.log", environment


def run_log_error(
    script_path: Path,
    environment: dict[str, str],
    message: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", LOG_RUNNER, str(script_path), message],
        capture_output=True,
        check=False,
        env=environment,
        text=True,
    )


def write_private_log(path: Path, contents: bytes) -> None:
    path.write_bytes(contents)
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def test_error_log_truncates_at_the_limit_and_records_the_current_error(
    tmp_path: Path,
) -> None:
    script_path, error_log, environment = prepare_hook(tmp_path)
    write_private_log(error_log, b"old error\n" + b"x" * MAX_ERROR_LOG_BYTES)

    result = run_log_error(script_path, environment, "current-delivery-error")

    assert result.returncode == 0
    assert result.stderr == ""
    contents = error_log.read_bytes()
    assert len(contents) <= MAX_ERROR_LOG_BYTES
    assert b"old error" not in contents
    assert b"Error log truncated at the 2097152-byte limit" in contents
    assert b"current-delivery-error" in contents


def test_error_log_rolls_over_before_a_new_entry_would_cross_the_limit(
    tmp_path: Path,
) -> None:
    script_path, error_log, environment = prepare_hook(tmp_path)
    write_private_log(error_log, b"x" * (MAX_ERROR_LOG_BYTES - 8))

    result = run_log_error(script_path, environment, "newest-error")

    assert result.returncode == 0
    assert result.stderr == ""
    contents = error_log.read_bytes()
    assert len(contents) <= MAX_ERROR_LOG_BYTES
    assert contents.startswith(b"[")
    assert b"Error log truncated at the 2097152-byte limit" in contents
    assert b"newest-error" in contents


def test_concurrent_error_writers_keep_the_log_bounded(tmp_path: Path) -> None:
    script_path, error_log, environment = prepare_hook(tmp_path)
    write_private_log(error_log, b"x" * (MAX_ERROR_LOG_BYTES - 64))
    processes = [
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                LOG_RUNNER,
                str(script_path),
                f"concurrent-error-{index}",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            text=True,
        )
        for index in range(12)
    ]

    results = [process.communicate(timeout=15) for process in processes]

    assert all(process.returncode == 0 for process in processes)
    assert all(stderr == "" for _stdout, stderr in results)
    contents = error_log.read_bytes()
    assert len(contents) <= MAX_ERROR_LOG_BYTES
    assert b"Error log truncated at the 2097152-byte limit" in contents
    for index in range(12):
        assert f"concurrent-error-{index}".encode() in contents


def test_single_error_entry_is_truncated_to_a_bounded_utf8_record(
    tmp_path: Path,
) -> None:
    script_path, error_log, environment = prepare_hook(tmp_path)

    result = subprocess.run(
        [sys.executable, "-c", LARGE_LOG_RUNNER, str(script_path)],
        capture_output=True,
        check=False,
        env=environment,
        text=True,
    )

    assert result.returncode == 0
    assert result.stderr == ""
    contents = error_log.read_bytes()
    assert len(contents) == 64 * 1024
    assert contents.decode("utf-8").endswith("... [error entry truncated]\n")
