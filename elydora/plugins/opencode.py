"""OpenCode plugin — writes .opencode/plugins/elydora-audit.js (JS plugin)."""

from __future__ import annotations

import os
import stat

from .base import AgentPlugin, InstallConfig, PluginStatus


PLUGIN_DIR = os.path.join(os.path.expanduser("~"), ".opencode", "plugins")
PLUGIN_FILENAME = "elydora-audit.js"


class OpenCodePlugin(AgentPlugin):
    """Install/uninstall Elydora audit hook for OpenCode.

    OpenCode expects JavaScript plugins, so this generates a self-contained
    JS file that performs the same audit flow using Node.js built-ins.
    """

    def _plugin_path(self) -> str:
        return os.path.join(PLUGIN_DIR, PLUGIN_FILENAME)

    def install(self, config: InstallConfig) -> None:
        org_id = config.get("org_id", "")
        agent_id = config.get("agent_id", "")
        private_key = config.get("private_key", "")
        kid = config.get("kid", "")
        base_url = config.get("base_url", "https://api.elydora.com")
        guard_script_path = config.get("guard_script_path", "")

        js_content = _generate_js_plugin(
            org_id=org_id,
            agent_id=agent_id,
            private_key=private_key,
            kid=kid,
            base_url=base_url,
            guard_script_path=guard_script_path,
        )

        os.makedirs(PLUGIN_DIR, exist_ok=True)
        plugin_path = self._plugin_path()
        with open(plugin_path, "w", encoding="utf-8") as f:
            f.write(js_content)
        os.chmod(plugin_path, stat.S_IRWXU)

        print(f"Elydora hook installed for OpenCode.")
        print(f"  Plugin: {plugin_path}")

    def uninstall(self) -> None:
        plugin_path = self._plugin_path()
        if os.path.exists(plugin_path):
            os.remove(plugin_path)
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
    org_id: str,
    agent_id: str,
    private_key: str,
    kid: str,
    base_url: str,
    guard_script_path: str = "",
) -> str:
    guard_path_escaped = guard_script_path.replace("\\", "\\\\") if guard_script_path else ""
    return f'''// Elydora audit plugin for OpenCode — auto-generated, do not edit.
"use strict";

const crypto = require("crypto");
const https = require("https");
const http = require("http");
const fs = require("fs");
const path = require("path");
const os = require("os");
const {{ spawnSync }} = require("child_process");

const ORG_ID = {_js_str(org_id)};
const AGENT_ID = {_js_str(agent_id)};
const PRIVATE_KEY = {_js_str(private_key)};
const KID = {_js_str(kid)};
const BASE_URL = {_js_str(base_url)};

const CHAIN_STATE_PATH = path.join(os.homedir(), ".elydora", "chain-state.json");

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
          const result = spawnSync("python3", [GUARD_SCRIPT_PATH], {{
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
          operation_type: "tool_use",
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

        saveChainState({{ prev_chain_hash: chainHash }});

        // Fire-and-forget POST
        const url = new URL(BASE_URL.replace(/\\/$/, "") + "/v1/operations");
        const body = JSON.stringify(eor);
        const mod = url.protocol === "https:" ? https : http;
        const req = mod.request(url, {{
          method: "POST",
          headers: {{ "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) }},
          timeout: 5000,
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
