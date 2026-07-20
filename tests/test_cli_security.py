from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import List

import pytest

from elydora import _cli_secrets, cli
from elydora._cli_secrets import (
    MAX_SECRET_FILE_BYTES,
    InstallSecrets,
    resolve_install_secrets,
)
from elydora.plugins._file_io import write_text_atomic
from elydora.plugins import (
    copilot,
    cursor,
    kiroide,
    opencode,
)
from elydora.plugins.hook_template import generate_hook_script
from elydora.utils import base64url_decode


PRIVATE_KEY = base64.urlsafe_b64encode(bytes([7]) * 32).rstrip(b"=").decode()
API_TOKEN = "ely_test_token"


class FakeTerminal:
    def __init__(self, *, interactive: bool, answers: List[str]) -> None:
        self.interactive = interactive
        self.answers = answers
        self.prompts: List[str] = []

    def read_hidden(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self.answers:
            raise AssertionError("unexpected hidden prompt")
        return self.answers.pop(0)


def write_secret(path: Path, value: str) -> None:
    path.write_bytes(value.encode("utf-8"))
    if os.name != "nt":
        path.chmod(0o600)


def test_install_secrets_resolve_from_hidden_prompts() -> None:
    terminal = FakeTerminal(
        interactive=True,
        answers=[PRIVATE_KEY, API_TOKEN],
    )

    secrets = resolve_install_secrets(
        private_key_file=None,
        token_file=None,
        terminal=terminal,
    )

    assert secrets == InstallSecrets(PRIVATE_KEY, API_TOKEN)
    assert terminal.prompts == ["Private key: ", "API token (optional): "]


def test_noninteractive_install_requires_private_key_file() -> None:
    terminal = FakeTerminal(interactive=False, answers=[])

    with pytest.raises(RuntimeError, match="--private_key_file <path>"):
        resolve_install_secrets(
            private_key_file=None,
            token_file=None,
            terminal=terminal,
        )

    assert terminal.prompts == []


def test_hidden_prompt_rejects_getpass_echo_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fallback_getpass(prompt: str, stream: object) -> str:
        _cli_secrets.warnings.warn(
            "terminal echo is active",
            _cli_secrets.getpass.GetPassWarning,
        )
        return PRIVATE_KEY

    monkeypatch.setattr(_cli_secrets.getpass, "getpass", fallback_getpass)

    with pytest.raises(RuntimeError, match="interactive terminal"):
        _cli_secrets._DefaultTerminal().read_hidden("Private key: ")


def test_secret_files_allow_one_trailing_line_ending(tmp_path: Path) -> None:
    private_key_file = tmp_path / "private.key"
    token_file = tmp_path / "token"
    write_secret(private_key_file, PRIVATE_KEY + "\r\n")
    write_secret(token_file, API_TOKEN + "\n")

    secrets = resolve_install_secrets(
        private_key_file=str(private_key_file),
        token_file=str(token_file),
        terminal=FakeTerminal(interactive=False, answers=[]),
    )

    assert secrets == InstallSecrets(PRIVATE_KEY, API_TOKEN)


@pytest.mark.parametrize(
    "content, message",
    [
        (PRIVATE_KEY + "\nsecond-line\n", "exactly one line"),
        ("", "private key is empty"),
        ("key\0value", "exactly one line"),
    ],
)
def test_private_key_file_rejects_invalid_content(
    tmp_path: Path,
    content: str,
    message: str,
) -> None:
    private_key_file = tmp_path / "private.key"
    write_secret(private_key_file, content)

    with pytest.raises(ValueError, match=message):
        resolve_install_secrets(
            private_key_file=str(private_key_file),
            token_file=None,
            terminal=FakeTerminal(interactive=False, answers=[]),
        )


def test_private_key_file_rejects_oversized_content(tmp_path: Path) -> None:
    private_key_file = tmp_path / "private.key"
    write_secret(private_key_file, "a" * (MAX_SECRET_FILE_BYTES + 1))

    with pytest.raises(ValueError, match="exceeds"):
        resolve_install_secrets(
            private_key_file=str(private_key_file),
            token_file=None,
            terminal=FakeTerminal(interactive=False, answers=[]),
        )


def test_private_key_file_rejects_symbolic_links(tmp_path: Path) -> None:
    target = tmp_path / "target.key"
    write_secret(target, PRIVATE_KEY)
    link = tmp_path / "linked.key"
    try:
        link.symlink_to(target)
    except OSError as error:
        pytest.skip(f"File symbolic links are unavailable: {error}")

    with pytest.raises(ValueError, match="regular file"):
        resolve_install_secrets(
            private_key_file=str(link),
            token_file=None,
            terminal=FakeTerminal(interactive=False, answers=[]),
        )


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission contract")
def test_private_key_file_requires_owner_only_permissions(tmp_path: Path) -> None:
    private_key_file = tmp_path / "private.key"
    write_secret(private_key_file, PRIVATE_KEY)
    private_key_file.chmod(0o640)

    with pytest.raises(ValueError, match="accessible only by its owner"):
        resolve_install_secrets(
            private_key_file=str(private_key_file),
            token_file=None,
            terminal=FakeTerminal(interactive=False, answers=[]),
        )


def test_secret_file_identity_is_stable_while_opening(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    private_key_file = tmp_path / "private.key"
    replacement = tmp_path / "replacement.key"
    write_secret(private_key_file, PRIVATE_KEY)
    write_secret(replacement, PRIVATE_KEY)
    original_open = os.open
    swapped = False

    def replace_then_open(path: str, flags: int) -> int:
        nonlocal swapped
        if path == str(private_key_file) and not swapped:
            os.replace(replacement, private_key_file)
            swapped = True
        return original_open(path, flags)

    monkeypatch.setattr(os, "open", replace_then_open)

    with pytest.raises(OSError, match="changed while opening"):
        resolve_install_secrets(
            private_key_file=str(private_key_file),
            token_file=None,
            terminal=FakeTerminal(interactive=False, answers=[]),
        )


@pytest.mark.parametrize(
    "option, replacement",
    [
        ("--private_key", "--private_key_file"),
        ("--token", "--token_file"),
    ],
)
def test_cli_rejects_legacy_secret_arguments_without_echoing_values(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    option: str,
    replacement: str,
) -> None:
    secret = "must-not-appear"
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setattr(
        "sys.argv",
        ["elydora", "install", option, secret],
    )

    with pytest.raises(SystemExit) as exc_info:
        cli.main()

    assert exc_info.value.code == 1
    error = capsys.readouterr().err
    assert replacement in error
    assert secret not in error
    assert not (tmp_path / ".elydora").exists()


def test_cli_reads_credentials_from_files_before_installing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    private_key_file = tmp_path / "private.key"
    token_file = tmp_path / "token"
    write_secret(private_key_file, PRIVATE_KEY)
    write_secret(token_file, API_TOKEN)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    installed: list[dict[str, str]] = []

    class Plugin:
        manages_guard_runtime = False

        def preflight_install(self, config: dict[str, str]) -> None:
            assert Path(config["guard_script_path"]).exists() is False

        def install(self, config: dict[str, str]) -> None:
            assert Path(config["guard_script_path"]).is_file()
            installed.append(config)

    monkeypatch.setattr(cli, "_get_plugin", lambda _name: Plugin())
    args = cli.build_parser().parse_args(
        [
            "install",
            "--agent",
            "opencode",
            "--org_id",
            "org-1",
            "--agent_id",
            "agent-1",
            "--private_key_file",
            str(private_key_file),
            "--token_file",
            str(token_file),
            "--kid",
            "key-1",
        ]
    )

    cli.cmd_install(args)

    assert installed[0]["private_key"] == PRIVATE_KEY
    assert installed[0]["token"] == API_TOKEN
    guard_path = tmp_path / ".elydora" / "agent-1" / "guard.py"
    assert guard_path.is_file()
    if os.name != "nt":
        assert guard_path.stat().st_mode & 0o777 == 0o700


def test_cursor_cli_preflight_rejects_config_before_runtime_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    private_key_file = tmp_path / "private.key"
    write_secret(private_key_file, PRIVATE_KEY)
    home_dir = tmp_path / "home"
    config_path = home_dir / ".cursor" / "hooks.json"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("{ malformed", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("USERPROFILE", str(home_dir))
    args = cli.build_parser().parse_args(
        [
            "install",
            "--agent",
            "cursor",
            "--org_id",
            "org-1",
            "--agent_id",
            "agent-1",
            "--private_key_file",
            str(private_key_file),
            "--kid",
            "key-1",
        ]
    )

    with pytest.raises(ValueError, match="parse Cursor user hooks"):
        cli.cmd_install(args)

    assert config_path.read_text(encoding="utf-8") == "{ malformed"
    assert (home_dir / ".elydora").exists() is False


def test_generated_hook_reads_private_key_from_private_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    key_path = tmp_path / ".elydora" / "agent-1" / "private.key"
    key_path.parent.mkdir(parents=True)
    write_secret(key_path, PRIVATE_KEY)
    script = generate_hook_script(
        org_id="org-1",
        agent_id="agent-1",
        kid="key-1",
        base_url="https://api.elydora.com",
    )
    namespace = {"__name__": "test_hook"}

    exec(compile(script, "hook.py", "exec"), namespace)

    assert namespace["read_private_key"]() == base64url_decode(PRIVATE_KEY)
    assert PRIVATE_KEY not in script
    assert "PRIVATE_KEY_PATH" in script


def test_atomic_secret_write_preserves_existing_file_on_replace_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    destination = tmp_path / "private.key"
    destination.write_text("original", encoding="utf-8")

    def fail_replace(_source: str, _destination: str) -> None:
        raise OSError("replace failed")

    monkeypatch.setattr(os, "replace", fail_replace)

    with pytest.raises(OSError, match="replace failed"):
        write_text_atomic(
            str(destination),
            "replacement",
            0o600,
            "Elydora private key",
        )

    assert destination.read_text(encoding="utf-8") == "original"
    assert list(tmp_path.glob(".private.key.*.tmp")) == []


@pytest.mark.parametrize(
    "module, plugin_type, agent_name",
    [
        (copilot, copilot.CopilotPlugin, "copilot"),
        (cursor, cursor.CursorPlugin, "cursor"),
        (kiroide, kiroide.KiroIdePlugin, "kiroide"),
        (opencode, opencode.OpenCodePlugin, "opencode"),
    ],
)
def test_legacy_plugins_persist_one_owner_only_private_key(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    module: object,
    plugin_type: type,
    agent_name: str,
) -> None:
    case_root = tmp_path / agent_name
    runtime_root = case_root / ".elydora"
    guard_path = runtime_root / "agent-1" / "guard.py"
    guard_path.parent.mkdir(parents=True)
    if module not in (cursor, copilot):
        guard_path.write_text("pass\n", encoding="utf-8")
    if module in (cursor, copilot):
        monkeypatch.setenv("HOME", str(case_root))
        monkeypatch.setenv("USERPROFILE", str(case_root))
    else:
        monkeypatch.setattr(module, "ELYDORA_DIR", str(runtime_root))

    if hasattr(module, "SETTINGS_PATH"):
        monkeypatch.setattr(
            module,
            "SETTINGS_PATH",
            str(case_root / "provider" / "settings.json"),
        )
    elif module is kiroide:
        monkeypatch.setattr(module, "KIRO_HOOK_DIR", str(case_root / "kiro-hooks"))
    elif module is opencode:
        monkeypatch.setattr(module, "PLUGIN_DIR", str(case_root / "plugins"))
    elif module is copilot:
        case_root.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv("COPILOT_HOME", str(case_root / ".copilot"))
        monkeypatch.chdir(case_root)

    plugin_type().install(
        {
            "org_id": "org-1",
            "agent_id": "agent-1",
            "agent_name": agent_name,
            "private_key": PRIVATE_KEY,
            "kid": "key-1",
            "token": API_TOKEN,
            "base_url": "https://api.elydora.com",
            "guard_script_path": str(guard_path),
        }
    )

    private_key_path = runtime_root / "agent-1" / "private.key"
    hook_path = runtime_root / "agent-1" / "hook.py"
    assert private_key_path.read_text(encoding="utf-8") == PRIVATE_KEY
    assert PRIVATE_KEY not in hook_path.read_text(encoding="utf-8")
    if os.name != "nt":
        assert private_key_path.stat().st_mode & 0o777 == 0o600
        assert hook_path.stat().st_mode & 0o777 == 0o700
