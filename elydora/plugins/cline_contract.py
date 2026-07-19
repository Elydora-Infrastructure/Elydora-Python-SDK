"""Cline file-hook contract and exact Elydora ownership metadata."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import json
import os
from typing import Any, Dict, Optional


AGENT_KEY = "cline"
GUARD_FILE_NAME = "PreToolUse.mjs"
AUDIT_FILE_NAME = "PostToolUse.mjs"
GUARD_SCRIPT = "guard.py"
AUDIT_SCRIPT = "hook.py"

_METADATA_MARKER = "// @elydora-cline-hook "
_METADATA_VERSION = 1

JsonObject = Dict[str, Any]


@dataclass(frozen=True)
class HookMetadata:
    version: int
    kind: str
    agent_id: str
    runtime_path: str


@dataclass(frozen=True)
class HookFile:
    exists: bool
    file_path: str
    source: Optional[str] = None
    metadata: Optional[HookMetadata] = None


@dataclass(frozen=True)
class HookPaths:
    hooks_directory: str
    guard_path: str
    audit_path: str


@dataclass(frozen=True)
class RuntimeContract:
    agent_id: str
    agent_directory: str
    guard_path: str
    audit_path: str


def home_dir() -> str:
    return os.path.expanduser("~")


def elydora_dir() -> str:
    return os.path.join(home_dir(), ".elydora")


def same_agent_id(left: str, right: str) -> bool:
    return os.path.normcase(left) == os.path.normcase(right)


def _same_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(
        os.path.abspath(right)
    )


def resolve_hooks_directory() -> str:
    configured = os.environ.get("CLINE_DIR", "").strip()
    cline_directory = (
        os.path.abspath(configured)
        if configured
        else os.path.join(home_dir(), ".cline")
    )
    return os.path.join(cline_directory, "hooks")


def resolve_hook_files() -> HookPaths:
    hooks_directory = resolve_hooks_directory()
    return HookPaths(
        hooks_directory=hooks_directory,
        guard_path=os.path.join(hooks_directory, GUARD_FILE_NAME),
        audit_path=os.path.join(hooks_directory, AUDIT_FILE_NAME),
    )


def build_metadata(kind: str, agent_id: str, runtime_path: str) -> HookMetadata:
    if kind not in {"guard", "audit"}:
        raise ValueError('Cline hook kind must be "guard" or "audit"')
    if not agent_id:
        raise ValueError("agent_id is required")
    if not os.path.isabs(runtime_path):
        raise ValueError(f"Cline {kind} runtime path must be absolute")
    return HookMetadata(_METADATA_VERSION, kind, agent_id, runtime_path)


def _metadata_object(metadata: HookMetadata) -> JsonObject:
    return {
        "version": metadata.version,
        "kind": metadata.kind,
        "agentId": metadata.agent_id,
        "runtimePath": metadata.runtime_path,
    }


def _encode_metadata(metadata: HookMetadata) -> str:
    raw = json.dumps(_metadata_object(metadata), separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode("utf-8")).rstrip(b"=").decode("ascii")


def build_wrapper(metadata: HookMetadata) -> str:
    template = """#!/usr/bin/env node
__METADATA_MARKER____METADATA__
import { spawn } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import { isAbsolute } from 'node:path';

const hookKind = __HOOK_KIND__;
const runtimePath = __RUNTIME_PATH__;

function resolveRuntimeExecutable() {
  const firstLine = readFileSync(runtimePath, 'utf-8').split(/\\r?\\n/, 1)[0] ?? '';
  if (!firstLine.startsWith('#!')) throw new Error('runtime is missing an absolute shebang');
  const executable = firstLine.slice(2).trim();
  if (!isAbsolute(executable)) throw new Error('runtime shebang executable must be absolute');
  try {
    if (!statSync(executable).isFile()) throw new Error('path is not a file');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error('runtime shebang executable is unavailable: ' + message, { cause: error });
  }
  return executable;
}

function runRuntime(input) {
  return new Promise((resolve, reject) => {
    const child = spawn(resolveRuntimeExecutable(), [runtimePath], {
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    const stdout = [];
    const stderr = [];
    let stdinError;
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.stdin.on('error', (error) => {
      if (error?.code !== 'EPIPE') stdinError = error;
    });
    child.once('error', reject);
    child.once('close', (code, signal) => {
      if (stdinError) {
        reject(stdinError);
        return;
      }
      resolve({
        code,
        signal,
        stdout: Buffer.concat(stdout).toString('utf-8'),
        stderr: Buffer.concat(stderr).toString('utf-8'),
      });
    });
    child.stdin.end(input);
  });
}

async function main() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const result = await runRuntime(Buffer.concat(chunks));
  if (result.stdout) process.stderr.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);

  if (hookKind === 'guard' && result.code === 2) {
    const errorMessage = result.stderr.trim() || 'Agent is frozen by Elydora.';
    process.stdout.write('HOOK_CONTROL\\t' + JSON.stringify({ cancel: true, errorMessage }) + '\\n');
    return;
  }
  if (result.signal) throw new Error('runtime terminated by signal ' + result.signal);
  if (result.code !== 0) throw new Error('runtime exited with code ' + result.code);
}

main().catch((error) => {
  const message = error instanceof Error ? error.stack || error.message : String(error);
  process.stderr.write('Elydora Cline ' + hookKind + ' wrapper failed: ' + message + '\\n');
  process.exitCode = 1;
});
"""
    return (
        template.replace("__METADATA_MARKER__", _METADATA_MARKER)
        .replace("__METADATA__", _encode_metadata(metadata))
        .replace("__HOOK_KIND__", json.dumps(metadata.kind))
        .replace("__RUNTIME_PATH__", json.dumps(metadata.runtime_path))
    )


def _decode_metadata(encoded: str) -> JsonObject:
    padding = "=" * (-len(encoded) % 4)
    try:
        raw = base64.urlsafe_b64decode((encoded + padding).encode("ascii"))
        value = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid encoded metadata: {error}") from error
    if not isinstance(value, dict):
        raise ValueError("metadata must be an object")
    return value


def _validate_metadata(value: JsonObject) -> HookMetadata:
    if set(value) != {"version", "kind", "agentId", "runtimePath"}:
        raise ValueError("metadata contains an unexpected field set")
    version = value["version"]
    kind = value["kind"]
    agent_id = value["agentId"]
    runtime_path = value["runtimePath"]
    if isinstance(version, bool) or version != _METADATA_VERSION:
        raise ValueError("metadata version must be 1")
    if kind not in {"guard", "audit"}:
        raise ValueError('metadata kind must be "guard" or "audit"')
    if not isinstance(agent_id, str) or not agent_id:
        raise ValueError("metadata agentId must be a non-empty string")
    if not isinstance(runtime_path, str) or not os.path.isabs(runtime_path):
        raise ValueError("metadata runtimePath must be an absolute path")
    return HookMetadata(version, kind, agent_id, runtime_path)


def parse_metadata(file_path: str, source: str) -> Optional[HookMetadata]:
    lines = source.splitlines()
    marker_line = lines[1] if len(lines) > 1 else ""
    if not marker_line.startswith(_METADATA_MARKER):
        return None
    try:
        encoded = marker_line[len(_METADATA_MARKER):]
        return _validate_metadata(_decode_metadata(encoded))
    except ValueError as error:
        raise ValueError(
            f"Failed to parse Elydora Cline hook metadata at {file_path}: {error}"
        ) from error


def assert_wrapper_integrity(file: HookFile) -> None:
    if file.metadata is None or file.source is None:
        return
    if file.source != build_wrapper(file.metadata):
        raise ValueError(
            f"Elydora Cline hook at {file.file_path} does not match the managed template"
        )


def _validate_agent_segment(agent_id: str) -> None:
    if agent_id in {".", ".."} or os.path.basename(agent_id) != agent_id:
        raise ValueError("Elydora Cline hook metadata contains an invalid agentId")


def runtime_contract(
    guard_file: HookFile,
    audit_file: HookFile,
) -> Optional[RuntimeContract]:
    if guard_file.metadata is None or audit_file.metadata is None:
        return None
    assert_wrapper_integrity(guard_file)
    assert_wrapper_integrity(audit_file)
    guard = guard_file.metadata
    audit = audit_file.metadata
    if guard.kind != "guard" or audit.kind != "audit":
        raise ValueError("Elydora Cline hook files contain mismatched event metadata")
    if not same_agent_id(guard.agent_id, audit.agent_id):
        raise ValueError("Elydora Cline hook files reference different agents")
    _validate_agent_segment(guard.agent_id)
    agent_directory = os.path.join(elydora_dir(), guard.agent_id)
    expected_guard = os.path.join(agent_directory, GUARD_SCRIPT)
    expected_audit = os.path.join(agent_directory, AUDIT_SCRIPT)
    if not _same_path(guard.runtime_path, expected_guard) or not _same_path(
        audit.runtime_path, expected_audit
    ):
        raise ValueError(
            "Elydora Cline hook metadata references an unexpected runtime path"
        )
    return RuntimeContract(
        agent_id=guard.agent_id,
        agent_directory=agent_directory,
        guard_path=expected_guard,
        audit_path=expected_audit,
    )
