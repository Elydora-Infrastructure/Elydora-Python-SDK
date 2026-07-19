from importlib.metadata import version

import pytest

from elydora import __version__
from elydora.cli import build_parser


def test_runtime_version_matches_distribution_metadata() -> None:
    assert __version__ == version("elydora")


def test_cli_reports_the_canonical_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        build_parser().parse_args(["--version"])

    assert exc_info.value.code == 0
    assert capsys.readouterr().out == f"elydora {__version__}\n"
