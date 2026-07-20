from pathlib import Path

from packaging.requirements import Requirement
from packaging.version import Version
import tomlkit


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _pyproject() -> dict[str, object]:
    return tomlkit.parse((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _project_metadata() -> dict[str, object]:
    return _pyproject()["project"]


def _requirements(entries: object) -> dict[str, Requirement]:
    assert isinstance(entries, list)
    requirements = (Requirement(str(entry)) for entry in entries)
    return {requirement.name: requirement for requirement in requirements}


def _assert_safe_floor(
    requirement: Requirement,
    vulnerable: str,
    fixed: str,
) -> None:
    assert Version(vulnerable) not in requirement.specifier
    assert Version(fixed) in requirement.specifier


def test_python_support_matches_maintained_runtime_line() -> None:
    project = _project_metadata()

    assert project["requires-python"] == ">=3.10"
    assert "Programming Language :: Python :: 3.9" not in project["classifiers"]
    assert "Programming Language :: Python :: 3.14" in project["classifiers"]


def test_license_uses_current_packaging_metadata() -> None:
    document = _pyproject()
    project = document["project"]
    assert isinstance(project, dict)
    build_system = document["build-system"]
    assert isinstance(build_system, dict)
    build_requirements = _requirements(build_system["requires"])

    assert project["license"] == "MIT"
    assert all(
        not str(classifier).startswith("License ::")
        for classifier in project["classifiers"]
    )
    assert Version("77.0.3") in build_requirements["setuptools"].specifier


def test_dependency_floors_exclude_known_vulnerable_releases() -> None:
    project = _project_metadata()
    runtime = _requirements(project["dependencies"])
    optional = project["optional-dependencies"]
    assert isinstance(optional, dict)
    development = _requirements(optional["dev"])

    _assert_safe_floor(runtime["requests"], "2.32.5", "2.33.0")
    _assert_safe_floor(runtime["aiohttp"], "3.13.5", "3.14.1")
    _assert_safe_floor(runtime["urllib3"], "2.6.3", "2.7.0")
    _assert_safe_floor(runtime["cryptography"], "41.0.0", "48.0.1")
    _assert_safe_floor(development["pytest"], "8.4.2", "9.0.3")


def test_async_test_runner_supports_pytest_nine() -> None:
    project = _project_metadata()
    optional = project["optional-dependencies"]
    assert isinstance(optional, dict)
    development = _requirements(optional["dev"])

    requirement = development["pytest-asyncio"]
    assert Version("1.3.0") not in requirement.specifier
    assert Version("1.4.0") in requirement.specifier
