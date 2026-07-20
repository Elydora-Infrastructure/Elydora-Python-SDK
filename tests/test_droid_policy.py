from __future__ import annotations

from pathlib import Path

import pytest

from droid_support import DroidFixture, write_json


def test_user_settings_disable_before_runtime_creation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = DroidFixture(
        monkeypatch,
        tmp_path,
        settings={"hooksDisabled": True},
    )
    with pytest.raises(ValueError, match="hooksDisabled"):
        fixture.install()
    assert not fixture.runtime_config.exists()
    assert not fixture.root_path.exists()


def test_user_local_settings_override_base_settings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = DroidFixture(
        monkeypatch,
        tmp_path,
        settings={"hooksDisabled": True},
        local_settings={"hooksDisabled": False},
    )
    fixture.install()
    assert fixture.runtime_config.exists()


def test_legacy_direct_flags_remain_safety_compatible(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = DroidFixture(
        monkeypatch,
        tmp_path,
        legacy_config={"hooksDisabled": True, "PreToolUse": []},
        settings={"hooksDisabled": False},
    )
    with pytest.raises(ValueError, match="legacy hooks"):
        fixture.install()
    assert not fixture.runtime_config.exists()


def test_project_policy_has_extension_only_precedence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    blocked = DroidFixture(
        monkeypatch,
        tmp_path / "blocked",
        settings={"hooksDisabled": False},
        project_settings={"hooksDisabled": True},
    )
    with pytest.raises(ValueError, match="project settings"):
        blocked.install()
    assert not blocked.runtime_config.exists()

    allowed = DroidFixture(
        monkeypatch,
        tmp_path / "allowed",
        settings={"hooksDisabled": True},
        project_settings={"hooksDisabled": False},
    )
    allowed.install()
    assert allowed.runtime_config.exists()


def test_project_local_settings_override_matching_base(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = DroidFixture(
        monkeypatch,
        tmp_path,
        project_settings={"hooksDisabled": False},
        project_local_settings={"hooksDisabled": True},
    )
    with pytest.raises(ValueError, match="project local settings"):
        fixture.install()


def test_project_value_precedes_deeper_folder_value(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = DroidFixture(
        monkeypatch,
        tmp_path,
        project_settings={"hooksDisabled": False},
    )
    child = fixture.workspace_dir / "packages" / "console"
    child.mkdir(parents=True)
    write_json(
        child / ".factory" / "settings.json",
        {"hooksDisabled": True},
    )
    monkeypatch.chdir(child)
    fixture.install()
    assert fixture.runtime_config.exists()


def test_system_managed_policy_blocks_user_hooks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = DroidFixture(monkeypatch, tmp_path)
    fixture.write_system_settings({"allowManagedHooksOnly": True})
    with pytest.raises(ValueError, match="allowManagedHooksOnly"):
        fixture.install()
    assert not fixture.runtime_config.exists()


def test_malformed_read_only_project_policy_is_preserved(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = DroidFixture(
        monkeypatch,
        tmp_path,
        project_settings="{ malformed",
    )
    before = fixture.project_settings_path.read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="project settings"):
        fixture.install()
    assert fixture.project_settings_path.read_text(encoding="utf-8") == before
    assert not fixture.runtime_config.exists()
    assert not fixture.root_path.exists()
