"""OpenCode plugin — writes .opencode/plugins/elydora-audit.js (JS plugin)."""

from __future__ import annotations

import json
import os
import stat
import sys

from .base import AgentPlugin, InstallConfig, PluginStatus


PLUGIN_DIR = os.path.join(os.path.expanduser("~"), ".config", "opencode", "plugins")
PLUGIN_FILENAME = "elydora-audit.mjs"
ELYDORA_DIR = os.path.join(os.path.expanduser("~"), ".elydora")


class OpenCodePlugin(AgentPlugin):
    """Install/uninstall Elydora audit hook for OpenCode.

    OpenCode expects JavaScript plugins, so this generates a self-contained
    JS file that performs the same audit flow using Node.js built-ins.
    """

    def _plugin_path(self) -> str:
        return os.path.join(PLUGIN_DIR, PLUGIN_FILENAME)

    def install(self, config: InstallConfig) -> None:
        agent_id = config.get("agent_id", "")
        agent_name = config.get("agent_name", "")
        org_id = config.get("org_id", "")
        private_key = config.get("private_key", "")
        kid = config.get("kid", "")
        base_url = config.get("base_url", "https://api.elydora.com")
        guard_script_path = config.get("guard_script_path", "")

        # Create per-agent directory
        agent_dir = os.path.join(ELYDORA_DIR, agent_id)
        os.makedirs(agent_dir, exist_ok=True)

        # Write config.json
        config_data = {
            "org_id": org_id,
            "agent_id": agent_id,
            "kid": kid,
            "base_url": base_url,
            "token": config.get("token", ""),
            "agent_name": agent_name,
        }
        config_path = os.path.join(agent_dir, "config.json")
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2)
            f.write("\n")

        # Write private key
        private_key_path = os.path.join(agent_dir, "private.key")
        with open(private_key_path, "w", encoding="utf-8") as f:
            f.write(private_key)
        try:
            os.chmod(private_key_path, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass  # chmod may fail on Windows

        js_content = _generate_js_plugin(
            agent_id=agent_id,
            guard_script_path=guard_script_path,
        )

        os.makedirs(PLUGIN_DIR, exist_ok=True)
        plugin_path = self._plugin_path()
        with open(plugin_path, "w", encoding="utf-8") as f:
            f.write(js_content)
        try:
            os.chmod(plugin_path, stat.S_IRWXU)
        except Exception:
            pass  # chmod may fail on Windows

        print(f"Elydora hook installed for OpenCode.")
        print(f"  Plugin: {plugin_path}")

    def uninstall(self, agent_id: str = "") -> None:
        plugin_path = self._plugin_path()
        if os.path.exists(plugin_path):
            os.remove(plugin_path)
        # Hook script removal is handled by cli.py cmd_uninstall (rmtree of agent dir)
        print("Elydora hook uninstalled from OpenCode.")

    def status(self) -> PluginStatus:
        plugin_path = self._plugin_path()
        installed = os.path.exists(plugin_path)
        if installed:
            details = f"Plugin: {plugin_path}"
        else:
            details = "Not installed"
        return PluginStatus(installed=installed, agent="opencode", details=details)


def _generate_js_plugin(
    *,
    agent_id: str,
    guard_script_path: str = "",
) -> str:
    guard_path_escaped = guard_script_path.replace("\\", "\\\\") if guard_script_path else ""
    python_exe_escaped = sys.executable.replace("\\", "\\\\")
    return f'''// Elydora audit plugin for OpenCode — auto-generated, do not edit.
"use strict";

const crypto = require("crypto");
const https = require("https");
const http = require("http");
const fs = require("fs");
const path = require("path");
const os = require("os");
const {{ spawnSync }} = require("child_process");

const CONFIG_DIR = path.join(os.homedir(), ".elydora", {_js_str(agent_id)});
const CONFIG = JSON.parse(fs.readFileSync(path.join(CONFIG_DIR, "config.json"), "utf-8"));
const PRIVATE_KEY = fs.readFileSync(path.join(CONFIG_DIR, "private.key"), "utf-8").trim();
const ORG_ID = CONFIG.org_id;
const AGENT_ID = CONFIG.agent_id;
const KID = CONFIG.kid;
const BASE_URL = CONFIG.base_url;

const CHAIN_STATE_PATH = path.join(CONFIG_DIR, "chain-state.json");

function base64urlEncode(buf) {{
  return Buffer.from(buf).toString("base64url");
}}

function base64urlDecode(s) {{
  return Buffer.from(s, "base64url");
}}

function sha256Base64url(data) {{
  if (typeof data === "string") data = Buffer.from(data, "utf-8");
  return base64urlEncode(crypto.createHash("sha256").update(data).digest());
}}

function jcsCanonicalize(value) {{
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {{
    if (!isFinite(value)) return "null";
    if (Object.is(value, -0)) return "0";
    return JSON.stringify(value);
  }}
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(jcsCanonicalize).join(",") + "]";
  if (typeof value === "object") {{
    const keys = Object.keys(value).sort();
    const pairs = keys.map(k => JSON.stringify(k) + ":" + jcsCanonicalize(value[k]));
    return "{{" + pairs.join(",") + "}}";
  }}
  return JSON.stringify(value);
}}

function computePayloadHash(payload) {{
  return sha256Base64url(jcsCanonicalize(payload));
}}

function computeChainHash(prev, payloadHash, opId, issuedAt) {{
  return sha256Base64url(`${{prev}}|${{payloadHash}}|${{opId}}|${{issuedAt}}`);
}}

function signEd25519(privKeyB64url, data) {{
  const seed = base64urlDecode(privKeyB64url);
  const key = crypto.createPrivateKey({{
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
    format: "der",
    type: "pkcs8",
  }});
  return base64urlEncode(crypto.sign(null, Buffer.from(data, "utf-8"), key));
}}

function generateUuidv7() {{
  const ts = Date.now();
  const buf = Buffer.alloc(16);
  buf.writeUIntBE(ts, 0, 6);
  const rand = crypto.randomBytes(10);
  rand.copy(buf, 6);
  buf[6] = (buf[6] & 0x0f) | 0x70;
  buf[8] = (buf[8] & 0x3f) | 0x80;
  const h = buf.toString("hex");
  return `${{h.slice(0,8)}}-${{h.slice(8,12)}}-${{h.slice(12,16)}}-${{h.slice(16,20)}}-${{h.slice(20)}}`;
}}

function generateNonce() {{
  return base64urlEncode(crypto.randomBytes(16));
}}

function loadChainState() {{
  try {{
    return JSON.parse(fs.readFileSync(CHAIN_STATE_PATH, "utf-8"));
  }} catch {{
    return {{ prev_chain_hash: "" }};
  }}
}}

function saveChainState(state) {{
  const dir = path.dirname(CHAIN_STATE_PATH);
  fs.mkdirSync(dir, {{ recursive: true }});
  const tmp = CHAIN_STATE_PATH + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(state));
  fs.renameSync(tmp, CHAIN_STATE_PATH);
}}

const PYTHON_EXE = "{python_exe_escaped}";
const GUARD_SCRIPT_PATH = "{guard_path_escaped}";

module.exports = {{
  name: "elydora-audit",
  version: "1.0.0",
  description: "Sends tool-use events to the Elydora tamper-evident audit platform",

  hooks: {{
    preToolUse(context) {{
      // Synchronous guard — blocks tool if agent is frozen
      if (GUARD_SCRIPT_PATH) {{
        try {{
          const result = spawnSync(PYTHON_EXE, [GUARD_SCRIPT_PATH], {{
            timeout: 5000,
            stdio: ["pipe", "ignore", "pipe"],
          }});
          if (result.status !== 0) {{
            const msg = result.stderr ? result.stderr.toString().trim() : "Agent is frozen by Elydora.";
            return {{ blocked: true, reason: msg }};
          }}
        }} catch {{
          // Fail-open — allow if guard can't run
        }}
      }}
    }},

    postToolUse(context) {{
      const event = context || {{}};
      try {{
        const toolName = event.tool_name || event.toolName || event.name || "";
        const toolInput = event.tool_input || event.toolInput || event.input || {{}};
        const toolOutput = event.tool_output || event.toolOutput || event.output || {{}};

        const operationId = generateUuidv7();
        const issuedAt = Date.now();
        const nonce = generateNonce();
        const payload = {{ tool_name: toolName, tool_input: toolInput, tool_output: toolOutput }};
        const payloadHash = computePayloadHash(payload);

        const chainState = loadChainState();
        const prevChainHash = chainState.prev_chain_hash || "";
        const chainHash = computeChainHash(prevChainHash, payloadHash, operationId, issuedAt);

        const eor = {{
          op_version: "1.0",
          operation_id: operationId,
          org_id: ORG_ID,
          agent_id: AGENT_ID,
          issued_at: issuedAt,
          ttl_ms: 30000,
          nonce: nonce,
          operation_type: "ai.tool_use",
          subject: {{ type: "tool", id: toolName }},
          action: {{ type: "execute", tool: toolName }},
          payload: payload,
          payload_hash: payloadHash,
          prev_chain_hash: prevChainHash,
          agent_pubkey_kid: KID,
          signature: "",
        }};

        const signable = Object.fromEntries(Object.entries(eor).filter(([k]) => k !== "signature"));
        eor.signature = signEd25519(PRIVATE_KEY, jcsCanonicalize(signable));

        // POST to API — only save chain state on 2xx response
        const url = new URL(BASE_URL.replace(/\\/$/, "") + "/v1/operations");
        const body = JSON.stringify(eor);
        const mod = url.protocol === "https:" ? https : http;
        const req = mod.request(url, {{
          method: "POST",
          headers: {{ "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) }},
          timeout: 5000,
        }}, (res) => {{
          if (res.statusCode >= 200 && res.statusCode < 300) {{
            saveChainState({{ prev_chain_hash: chainHash }});
          }}
          res.resume();
        }});
        req.on("error", () => {{}});
        req.write(body);
        req.end();
      }} catch (e) {{
        // Never block the host agent
        console.error("[elydora]", e.message);
      }}
    }},
  }},
}};
'''


def _js_str(s: str) -> str:
    """Escape a Python string for embedding as a JS string literal."""
    import json
    return json.dumps(s)
