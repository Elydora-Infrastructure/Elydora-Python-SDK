from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess  # nosec B404

import pytest

from letta_support import (
    ElydoraApiHandler,
    managed_handler,
    prepare_fixture,
    server_base_url,
    start_api_server,
)


SOURCE_ROOT = os.environ.get("ELYDORA_LETTA_SOURCE")
BUN_BINARY = os.environ.get("ELYDORA_BUN_BINARY") or shutil.which("bun")


def _module_url(relative_path: str) -> str:
    if SOURCE_ROOT is None:
        raise RuntimeError("ELYDORA_LETTA_SOURCE is required")
    return (Path(SOURCE_ROOT) / relative_path).resolve().as_uri()


def _result_json(stdout: str) -> dict:
    return json.loads(stdout.strip().splitlines()[-1])


def _run_official_probe(fixture: object, mode: str) -> subprocess.CompletedProcess[str]:
    if SOURCE_ROOT is None or BUN_BINARY is None:
        raise RuntimeError("official Letta source and Bun are required")
    global_path = getattr(fixture, "global_path")
    settings = json.loads(Path(global_path).read_text(encoding="utf-8"))
    commands = {
        "guard": managed_handler(settings, "PreToolUse")["command"],
        "audit": managed_handler(settings, "PostToolUse")["command"],
        "failure": managed_handler(settings, "PostToolUseFailure")["command"],
    }
    source = f"""
import {{ settingsManager }} from {json.dumps(_module_url('src/settings-manager.ts'))};
import {{ getHooksForEvent }} from {json.dumps(_module_url('src/hooks/loader.ts'))};
import {{ executeCommandHook }} from {json.dumps(_module_url('src/hooks/executor.ts'))};
import {{ runPostToolUseHooks }} from {json.dumps(_module_url('src/hooks/index.ts'))};
const workspace = process.env.ELYDORA_OFFICIAL_WORKSPACE;
const commands = JSON.parse(process.env.ELYDORA_OFFICIAL_COMMANDS);
await settingsManager.initialize();
await settingsManager.loadProjectSettings(workspace);
await settingsManager.loadLocalProjectSettings(workspace);
const pre = await getHooksForEvent('PreToolUse', 'Bash', workspace);
const post = await getHooksForEvent('PostToolUse', 'Bash', workspace);
const failure = await getHooksForEvent('PostToolUseFailure', 'Bash', workspace);
const managed = (hooks, command) => hooks.find((hook) => (
  hook.type === 'command' && hook.command === command
));
if (process.env.ELYDORA_OFFICIAL_MODE === 'active') {{
  const guardResult = await executeCommandHook(
    managed(pre, commands.guard),
    {{
      event_type: 'PreToolUse',
      working_directory: workspace,
      tool_name: 'Bash',
      tool_input: {{ command: 'echo official' }},
      tool_call_id: 'official-pre',
      agent_id: 'letta-agent',
    }},
    workspace,
  );
  const postResult = await executeCommandHook(
    managed(post, commands.audit),
    {{
      event_type: 'PostToolUse',
      working_directory: workspace,
      tool_name: 'Bash',
      tool_input: {{ command: 'echo official' }},
      tool_result: {{ status: 'success', output: 'official' }},
      tool_call_id: 'official-post',
    }},
    workspace,
  );
  const failureResult = await executeCommandHook(
    managed(failure, commands.failure),
    {{
      event_type: 'PostToolUseFailure',
      working_directory: workspace,
      tool_name: 'Bash',
      tool_input: {{ command: 'exit 1' }},
      error_message: 'official failure',
      error_type: 'ProcessError',
      tool_call_id: 'official-failure',
    }},
    workspace,
  );
  console.log(JSON.stringify({{
    counts: [pre.length, post.length, failure.length],
    exits: [guardResult.exitCode, postResult.exitCode, failureResult.exitCode],
  }}));
}} else {{
  const result = await runPostToolUseHooks(
    'Bash',
    {{ command: 'echo unavailable' }},
    {{ status: 'success', output: 'unavailable' }},
    'official-post-error',
    workspace,
  );
  console.log(JSON.stringify({{
    blocked: result.blocked,
    errored: result.errored,
    exits: result.results.map((entry) => entry.exitCode),
  }}));
}}
await settingsManager.flush();
"""
    environment = {
        **os.environ,
        "HOME": str(getattr(fixture, "home_dir")),
        "USERPROFILE": str(getattr(fixture, "home_dir")),
        "LETTA_SKIP_KEYCHAIN_CHECK": "1",
        "ELYDORA_OFFICIAL_COMMANDS": json.dumps(commands),
        "ELYDORA_OFFICIAL_MODE": mode,
        "ELYDORA_OFFICIAL_WORKSPACE": str(getattr(fixture, "project_dir")),
    }
    return subprocess.run(  # nosec B603
        [BUN_BINARY, "--silent", "--eval", source],
        text=True,
        capture_output=True,
        check=False,
        cwd=SOURCE_ROOT,
        env=environment,
        timeout=60,
    )


@pytest.mark.skipif(
    SOURCE_ROOT is None or BUN_BINARY is None,
    reason="official Letta source and Bun are required",
)
def test_official_letta_code_loads_and_executes_all_managed_hooks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    assert SOURCE_ROOT is not None
    manifest = json.loads(
        (Path(SOURCE_ROOT) / "package.json").read_text(encoding="utf-8")
    )
    assert manifest["version"] == "0.28.13"
    server = start_api_server()
    fixture = prepare_fixture(
        monkeypatch, tmp_path, base_url=server_base_url(server)
    )
    server_closed = False
    try:
        fixture.install()
        active = _run_official_probe(fixture, "active")
        assert active.returncode == 0, active.stderr
        assert _result_json(active.stdout) == {
            "counts": [1, 1, 1],
            "exits": [0, 0, 0],
        }
        assert len([
            request for request in ElydoraApiHandler.requests
            if request["method"] == "POST"
        ]) == 2
        server.shutdown()
        server.server_close()
        server_closed = True
        unavailable = _run_official_probe(fixture, "unavailable")
        assert unavailable.returncode == 0, unavailable.stderr
        assert _result_json(unavailable.stdout) == {
            "blocked": False,
            "errored": True,
            "exits": [1],
        }
    finally:
        if not server_closed:
            server.shutdown()
            server.server_close()
