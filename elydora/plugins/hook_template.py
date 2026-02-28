"""Generates self-contained Python hook scripts for AI agent integrations.

The generated script contains all crypto and networking inline so it has zero
import dependencies beyond the Python stdlib + cryptography (already an
Elydora SDK dependency).
"""

from __future__ import annotations

import sys


def generate_hook_script(
    *,
    org_id: str,
    agent_id: str,
    private_key: str,
    kid: str,
    base_url: str,
) -> str:
    """Return a complete, self-contained Python hook script as a string.

    The script:
      1. Reads JSON from stdin (tool-use event)
      2. Constructs an Elydora Operation Record (EOR)
      3. Signs it with Ed25519
      4. POSTs it fire-and-forget to the Elydora API
      5. Always exits 0 (never blocks the host agent)

    Chain state is persisted in ~/.elydora/chain-state.json.
    """
    shebang = sys.executable
    return f'''#!{shebang}
"""Elydora audit hook — auto-generated, do not edit."""

import base64
import hashlib
import json
import math
import os
import struct
import sys
import time

# ---------------------------------------------------------------------------
# Configuration (baked at install time)
# ---------------------------------------------------------------------------
ORG_ID = {org_id!r}
AGENT_ID = {agent_id!r}
PRIVATE_KEY = {private_key!r}
KID = {kid!r}
BASE_URL = {base_url!r}

CHAIN_STATE_PATH = os.path.join(os.path.expanduser("~"), ".elydora", "chain-state.json")
ERROR_LOG_PATH = os.path.join(os.path.expanduser("~"), ".elydora", "error.log")
ZERO_CHAIN_HASH = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

# ---------------------------------------------------------------------------
# Base64url helpers
# ---------------------------------------------------------------------------

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def base64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)

# ---------------------------------------------------------------------------
# SHA-256
# ---------------------------------------------------------------------------

def sha256_base64url(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64url_encode(hashlib.sha256(data).digest())

# ---------------------------------------------------------------------------
# JCS canonicalization (RFC 8785)
# ---------------------------------------------------------------------------

def _jcs_number(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if math.isnan(value) or math.isinf(value):
        return "null"
    if value == 0.0:
        return "0"
    return json.dumps(value)

def jcs_canonicalize(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _jcs_number(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(jcs_canonicalize(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value.keys())
        pairs = []
        for k in keys:
            pairs.append(json.dumps(k, ensure_ascii=False) + ":" + jcs_canonicalize(value[k]))
        return "{{" + ",".join(pairs) + "}}"
    return json.dumps(value)

# ---------------------------------------------------------------------------
# Hash helpers
# ---------------------------------------------------------------------------

def compute_payload_hash(payload):
    return sha256_base64url(jcs_canonicalize(payload))

def compute_chain_hash(prev_chain_hash, payload_hash, operation_id, issued_at):
    input_str = f"{{prev_chain_hash}}|{{payload_hash}}|{{operation_id}}|{{issued_at}}"
    return sha256_base64url(input_str)

# ---------------------------------------------------------------------------
# Ed25519 signing (uses cryptography library)
# ---------------------------------------------------------------------------

def sign_ed25519(private_key_b64url, data):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    seed = base64url_decode(private_key_b64url)
    key = Ed25519PrivateKey.from_private_bytes(seed)
    return base64url_encode(key.sign(data))

# ---------------------------------------------------------------------------
# UUIDv7
# ---------------------------------------------------------------------------

def generate_uuidv7():
    timestamp_ms = int(time.time() * 1000)
    ts_bytes = struct.pack(">Q", timestamp_ms)[2:]
    rand_a = struct.unpack(">H", os.urandom(2))[0]
    rand_a = (rand_a & 0x0FFF) | 0x7000
    rand_b = bytearray(os.urandom(8))
    rand_b[0] = (rand_b[0] & 0x3F) | 0x80
    uuid_bytes = ts_bytes + struct.pack(">H", rand_a) + bytes(rand_b)
    h = uuid_bytes.hex()
    return f"{{h[0:8]}}-{{h[8:12]}}-{{h[12:16]}}-{{h[16:20]}}-{{h[20:32]}}"

def generate_nonce():
    return base64url_encode(os.urandom(16))

# ---------------------------------------------------------------------------
# Chain state persistence
# ---------------------------------------------------------------------------

def read_chain_state():
    try:
        with open(CHAIN_STATE_PATH, "r") as f:
            state = json.load(f)
            return state.get("prev_chain_hash", ZERO_CHAIN_HASH) or ZERO_CHAIN_HASH
    except (FileNotFoundError, json.JSONDecodeError):
        return ZERO_CHAIN_HASH

def write_chain_state(chain_hash):
    os.makedirs(os.path.dirname(CHAIN_STATE_PATH), exist_ok=True)
    tmp_path = CHAIN_STATE_PATH + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump({{"prev_chain_hash": chain_hash}}, f)
    try:
        os.replace(tmp_path, CHAIN_STATE_PATH)
    except OSError:
        import shutil
        shutil.move(tmp_path, CHAIN_STATE_PATH)

def log_error(err):
    try:
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        msg = f"{{ts}} [elydora-hook] {{err}}\\n"
        os.makedirs(os.path.dirname(ERROR_LOG_PATH), exist_ok=True)
        with open(ERROR_LOG_PATH, "a") as f:
            f.write(msg)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Main hook logic
# ---------------------------------------------------------------------------

def main():
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return

        try:
            event = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return

        # Extract tool event data
        tool_name = "unknown"
        tool_input = {{}}
        session_id = "unknown"

        if isinstance(event, dict):
            tool_name = event.get("tool_name", event.get("toolName", event.get("name", "unknown")))
            tool_input = event.get("tool_input", event.get("toolInput", event.get("input", {{}})))
            session_id = event.get("session_id", event.get("sessionId", event.get("session", "unknown")))

        # Read chain state
        prev_chain_hash = read_chain_state()

        # Build the EOR
        operation_id = generate_uuidv7()
        issued_at = int(time.time() * 1000)
        nonce = generate_nonce()

        payload = {{
            "tool_name": tool_name,
            "tool_input": tool_input,
            "session_id": session_id,
        }}

        payload_hash = compute_payload_hash(payload)
        chain_hash = compute_chain_hash(prev_chain_hash, payload_hash, operation_id, issued_at)

        eor_without_sig = {{
            "op_version": "1.0",
            "operation_id": operation_id,
            "org_id": ORG_ID,
            "agent_id": AGENT_ID,
            "issued_at": issued_at,
            "ttl_ms": 30000,
            "nonce": nonce,
            "operation_type": "ai.tool_use",
            "subject": {{"session_id": session_id}},
            "action": {{"tool": tool_name}},
            "payload": payload,
            "payload_hash": payload_hash,
            "prev_chain_hash": prev_chain_hash,
            "agent_pubkey_kid": KID,
        }}

        canonical = jcs_canonicalize(eor_without_sig)
        signature = sign_ed25519(PRIVATE_KEY, canonical.encode("utf-8"))

        eor = dict(eor_without_sig)
        eor["chain_hash"] = chain_hash
        eor["signature"] = signature

        # POST to /v1/operations (5s timeout)
        # Only update local chain state on success to prevent desync
        try:
            import urllib.request
            import urllib.error
            url = BASE_URL.rstrip("/") + "/v1/operations"
            body = json.dumps(eor).encode("utf-8")
            headers = {{"Content-Type": "application/json", "Accept": "application/json"}}
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            resp = urllib.request.urlopen(req, timeout=5)
            # Server accepted (2xx) — safe to advance local chain state
            write_chain_state(chain_hash)
        except urllib.error.HTTPError as http_err:
            if http_err.code == 400:
                # Possible chain hash mismatch — try to resync from server response
                try:
                    import re
                    err_body = json.loads(http_err.read().decode("utf-8"))
                    if isinstance(err_body, dict) and isinstance(err_body.get("error"), dict):
                        if err_body["error"].get("code") == "PREV_HASH_MISMATCH":
                            match = re.search(r'Expected prev_chain_hash "([^"]+)"', err_body["error"].get("message", ""))
                            if match:
                                write_chain_state(match.group(1))
                                log_error("Chain hash resynced to server: " + match.group(1))
                except Exception:
                    pass  # ignore parse errors
            else:
                log_error("API returned HTTP " + str(http_err.code))
        except Exception:
            pass  # Network error — don't advance chain state, will retry with same prev_chain_hash

    except Exception as e:
        log_error(e)

if __name__ == "__main__":
    main()
'''


def generate_guard_script(agent_name: str) -> str:
    """Return a self-contained Python guard script for PreToolUse freeze enforcement.

    The script:
      1. Reads agent config from ~/.elydora/agents/{agent_name}.json
      2. Checks cached status from ~/.elydora/agents/{agent_name}.status.json (60s TTL)
      3. If cache is stale, fetches agent status from GET {base_url}/v1/agents/{agent_id}
      4. If status is "frozen", writes error to stderr and exits with code 1 (blocks tool)
      5. Fail-open: if API unreachable or config missing, exits 0 (allow)
      6. Uses only stdlib — no external deps
    """
    return f'''#!/usr/bin/env python3
"""Elydora agent guard (PreToolUse) for: {agent_name}
Generated by elydora-sdk — DO NOT EDIT."""

import json
import os
import sys
import time

AGENT_NAME = {agent_name!r}
ELYDORA_DIR = os.path.join(os.path.expanduser("~"), ".elydora")
CONFIG_PATH = os.path.join(ELYDORA_DIR, "agents", AGENT_NAME + ".json")
STATUS_CACHE_PATH = os.path.join(ELYDORA_DIR, "agents", AGENT_NAME + ".status.json")
CACHE_TTL_S = 60  # 60 seconds

# Consume stdin so the parent process doesn't block on a full pipe
try:
    sys.stdin.read()
except Exception:
    pass


def main():
    # Read agent config
    try:
        with open(CONFIG_PATH, "r") as f:
            config = json.load(f)
    except Exception:
        return  # Can't read config — fail-open (allow)

    # Check cached status
    try:
        with open(STATUS_CACHE_PATH, "r") as f:
            cache = json.load(f)
        age = time.time() - cache.get("cached_at", 0)
        if age < CACHE_TTL_S:
            if cache.get("status") == "frozen":
                sys.stderr.write(
                    'Agent "' + AGENT_NAME + '" is frozen by Elydora. Tool execution blocked.\\n'
                )
                sys.exit(1)
            return  # Cache is fresh — use cached result
    except Exception:
        pass  # No cache or invalid — need to check API

    # Fetch agent status from API
    base_url = config.get("base_url", "https://api.elydora.com").rstrip("/")
    agent_id = config.get("agent_id", "")

    try:
        import urllib.request
        import urllib.error

        url = base_url + "/v1/agents/" + urllib.request.quote(agent_id, safe="")
        req = urllib.request.Request(url, method="GET")
        req.add_header("Accept", "application/json")
        token = config.get("token", "")
        if token:
            req.add_header("Authorization", "Bearer " + token)

        resp = urllib.request.urlopen(req, timeout=3)
        data = json.loads(resp.read().decode("utf-8"))
        agent_status = "active"
        if isinstance(data, dict) and isinstance(data.get("agent"), dict):
            agent_status = data["agent"].get("status", "active")

        # Update cache
        try:
            os.makedirs(os.path.dirname(STATUS_CACHE_PATH), exist_ok=True)
            with open(STATUS_CACHE_PATH, "w") as f:
                json.dump({{"status": agent_status, "cached_at": time.time()}}, f)
        except Exception:
            pass  # Ignore cache write failures

        if agent_status == "frozen":
            sys.stderr.write(
                'Agent "' + AGENT_NAME + '" is frozen by Elydora. Tool execution blocked.\\n'
            )
            sys.exit(1)
    except SystemExit:
        raise  # Re-raise sys.exit
    except Exception:
        pass  # API unreachable — fail-open (allow)


if __name__ == "__main__":
    main()
'''
