from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from tomlkit import dumps, parse

from elydora import cli
from elydora.plugins import kimi
from elydora.plugins.registry import SUPPORTED_AGENTS
from kimi_support import (
    AGENT_ID,
    MISSING,
    assert_managed_triple,
    assert_no_transaction_files,
    legacy_command,
    parsed_hooks,
    prepare_fixture,
)


STABLE_USER_CONFIG = (
    '# stable user config\ndefault_model = "kimi-code/k3"\n\n'
    '[[hooks]]\nevent = "SessionStart"\ncommand = "existing-stable"\n'
    "timeout = 30 # keep stable hook\n"
)
LEGACY_USER_CONFIG = (
    "# legacy user config\ntelemetry = false\n\n"
    '[[hooks]]\nevent = "SessionEnd"\ncommand = "existing-legacy"\n'
)


def test_kimi_is_registered_in_sdk_and_cli() -> None:
    assert SUPPORTED_AGENTS["kimi"] == {
        "name": "Kimi Code",
        "hook_event": "PreToolUse/PostToolUse/PostToolUseFailure",
        "config_path": "~/.kimi-code/config.toml",
    }
    assert cli.PLUGIN_MAP["kimi"] is kimi.KimiPlugin


def test_install_writes_exact_triples_to_both_configs_and_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        stable_config=STABLE_USER_CONFIG,
        legacy_config=LEGACY_USER_CONFIG,
    )

    fixture.install()
    first_sources = {
        path: path.read_text(encoding="utf-8")
        for path in (fixture.stable_path, fixture.legacy_path)
    }
    fixture.install()

    assert "Kimi Code and kimi-cli" in capsys.readouterr().out
    for path, comment, command in (
        (fixture.stable_path, "# stable user config", "existing-stable"),
        (fixture.legacy_path, "# legacy user config", "existing-legacy"),
    ):
        raw = path.read_text(encoding="utf-8")
        hooks = parsed_hooks(path)
        assert raw == first_sources[path]
        assert comment in raw
        assert any(hook.get("command") == command for hook in hooks)
        assert len(hooks) == 4
        assert_managed_triple(hooks)
    assert not (fixture.home_dir / ".kimi-code" / "config.toml").exists()


def test_install_preserves_inline_hook_array_style(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = (
        '# inline user hook\nhooks = [{ event = "SessionStart", '
        'command = "existing-inline" }] # keep array\n'
    )
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        stable_config=source,
        legacy_detected=False,
    )

    fixture.install()
    fixture.install()

    raw = fixture.stable_path.read_text(encoding="utf-8")
    assert "# inline user hook" in raw
    assert "# keep array" in raw
    assert "hooks = [" in raw
    hooks = parsed_hooks(fixture.stable_path)
    assert len(hooks) == 4
    assert_managed_triple(hooks)


def test_uninstall_preserves_user_owned_empty_inline_hook_array(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = "# user container\nhooks = [] # keep empty array\n"
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        stable_config=source,
        legacy_detected=False,
    )
    fixture.install()
    fixture.plugin.uninstall(AGENT_ID)

    raw = fixture.stable_path.read_text(encoding="utf-8")
    assert "# user container" in raw
    assert "# keep empty array" in raw
    assert parse(raw)["hooks"].unwrap() == []


def test_fresh_stable_install_leaves_legacy_source_absent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, legacy_detected=False)
    fixture.install()

    hooks = parsed_hooks(fixture.stable_path)
    assert len(hooks) == 3
    assert_managed_triple(hooks)
    assert not fixture.legacy_path.exists()


def test_empty_home_override_uses_documented_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        explicit_kimi_home=False,
        legacy_detected=False,
    )
    fixture.install()
    monkeypatch.setenv("KIMI_CODE_HOME", "")

    assert fixture.plugin.status()["installed"] is True
    assert_managed_triple(parsed_hooks(fixture.stable_path))


def test_legacy_only_install_leaves_stable_target_absent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        explicit_kimi_home=False,
        stable_detected=False,
    )
    fixture.install()

    assert_managed_triple(parsed_hooks(fixture.legacy_path))
    assert not fixture.stable_path.exists()
    assert fixture.plugin.status()["installed"] is True


def test_install_parses_every_selected_config_before_runtime_writes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        stable_config=STABLE_USER_CONFIG,
        legacy_config="[malformed",
    )

    with pytest.raises(ValueError, match="parse kimi-cli legacy hooks config"):
        fixture.install()

    assert fixture.stable_path.read_text(encoding="utf-8") == STABLE_USER_CONFIG
    assert fixture.legacy_path.read_text(encoding="utf-8") == "[malformed"
    assert not fixture.agent_dir.exists()


@pytest.mark.parametrize(
    ("stable_config", "legacy_config", "pattern"),
    [
        (
            '[[hooks]]\nevent = "PreToolUse"\ncommand = "existing"\n'
            'cwd = "/tmp"\n',
            None,
            'unsupported field "cwd"',
        ),
        (
            None,
            '[[hooks]]\nevent = "Interrupt"\ncommand = "existing"\n',
            'unsupported event "Interrupt"',
        ),
        (
            '[[hooks]]\nevent = "PreToolUse"\ncommand = "existing"\n'
            "timeout = 601\n",
            None,
            "integer from 1 to 600",
        ),
    ],
)
def test_install_rejects_fields_and_events_outside_each_contract(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    stable_config: str | None,
    legacy_config: str | None,
    pattern: str,
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        stable_config=stable_config if stable_config is not None else MISSING,
        legacy_config=legacy_config if legacy_config is not None else MISSING,
    )

    with pytest.raises(ValueError, match=pattern):
        fixture.install()

    assert not fixture.agent_dir.exists()


def test_install_migrates_exact_legacy_commands_and_preserves_lookalikes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, legacy_detected=False)
    lookalike = f"{legacy_command(fixture.guard_path)} --inspect"
    source = (
        '[[hooks]]\nevent = "PreToolUse"\n'
        f"command = {json.dumps(legacy_command(fixture.guard_path))}\n"
        "timeout = 10\n\n"
        '[[hooks]]\nevent = "PostToolUse"\n'
        f"command = {json.dumps(legacy_command(fixture.hook_path))}\n"
        "timeout = 10\n\n"
        '[[hooks]]\nevent = "PreToolUse"\n'
        f"command = {json.dumps(lookalike)}\ntimeout = 10\n"
    )
    fixture.stable_path.parent.mkdir(parents=True, exist_ok=True)
    fixture.stable_path.write_text(source, encoding="utf-8")

    fixture.install()

    hooks = parsed_hooks(fixture.stable_path)
    assert len(hooks) == 4
    assert any(hook.get("command") == lookalike for hook in hooks)
    assert_managed_triple(hooks)

    fixture.plugin.uninstall(AGENT_ID)
    assert parsed_hooks(fixture.stable_path) == [
        {"event": "PreToolUse", "command": lookalike, "timeout": 10}
    ]


def test_uninstall_preserves_user_configs_and_removes_managed_configs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(
        monkeypatch,
        tmp_path,
        stable_config=STABLE_USER_CONFIG,
        legacy_config=LEGACY_USER_CONFIG,
    )
    fixture.install()
    fixture.plugin.uninstall(AGENT_ID)

    assert "# keep stable hook" in fixture.stable_path.read_text(encoding="utf-8")
    assert "# legacy user config" in fixture.legacy_path.read_text(encoding="utf-8")
    assert [hook["command"] for hook in parsed_hooks(fixture.stable_path)] == [
        "existing-stable"
    ]
    assert [hook["command"] for hook in parsed_hooks(fixture.legacy_path)] == [
        "existing-legacy"
    ]

    managed = prepare_fixture(
        monkeypatch,
        tmp_path / "managed",
    )
    managed.install()
    managed.plugin.uninstall(AGENT_ID)
    assert not managed.stable_path.exists()
    assert not managed.legacy_path.exists()


def test_status_requires_complete_triple_runtime_identity_and_private_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, legacy_detected=False)
    fixture.install()
    assert fixture.plugin.status()["installed"] is True

    document = parse(fixture.stable_path.read_text(encoding="utf-8"))
    hooks = document["hooks"]
    for index in range(len(hooks) - 1, -1, -1):
        if hooks[index]["event"] == "PostToolUseFailure":
            del hooks[index]
    fixture.stable_path.write_text(dumps(document), encoding="utf-8")
    assert fixture.plugin.status()["installed"] is False

    fixture.install()
    fixture.private_key_path.write_text("invalid", encoding="utf-8")
    with pytest.raises(ValueError, match="private key.*canonical 32-byte"):
        fixture.plugin.status()


@pytest.mark.parametrize(
    "runtime_name",
    ["guard.py", "hook.py", "config.json", "private.key"],
)
def test_status_requires_every_runtime_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    runtime_name: str,
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path, legacy_detected=False)
    fixture.install()
    (fixture.agent_dir / runtime_name).unlink()

    assert fixture.plugin.status()["installed"] is False


def test_installation_leaves_no_transaction_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture = prepare_fixture(monkeypatch, tmp_path)
    fixture.install()

    assert_no_transaction_files(fixture.home_dir)
    if os.name != "nt":
        for path in (
            fixture.stable_path,
            fixture.legacy_path,
            fixture.runtime_config_path,
            fixture.private_key_path,
        ):
            assert path.stat().st_mode & 0o777 == 0o600
