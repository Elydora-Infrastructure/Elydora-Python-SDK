# Elydora Python SDK

Official Python SDK for the [Elydora](https://elydora.com) tamper-evident audit platform. Build cryptographically verifiable audit trails for AI agent operations.

## Installation

```bash
pip install elydora
```

Requires Python 3.10+.

## Quick Start

```python
from elydora import ElydoraClient

# Authenticate
auth = ElydoraClient.login("https://api.elydora.com", "user@example.com", "password")

# Create client
client = ElydoraClient(
    org_id=auth["user"]["org_id"],
    agent_id="my-agent-id",
    private_key="<base64url-encoded-ed25519-seed>",
    base_url="https://api.elydora.com",
    token=auth["token"],
)

# Create and submit an operation
eor = client.create_operation(
    operation_type="data.access",
    subject={"user_id": "u-123", "resource": "patient-record"},
    action={"type": "read", "scope": "full"},
    payload={"record_id": "rec-456"},
)
response = client.submit_operation(eor)
print("Receipt:", response["receipt"]["receipt_id"])
```

## Async Support

```python
from elydora import AsyncElydoraClient

async def main():
    client = AsyncElydoraClient(
        org_id="org-123",
        agent_id="agent-456",
        private_key="<base64url-encoded-ed25519-seed>",
        token="<api-token>",
    )

    eor = client.create_operation(
        operation_type="inference",
        subject={"model": "gpt-4"},
        action={"type": "completion"},
    )
    response = await client.submit_operation(eor)
    await client.close()
```

## CLI

The SDK includes a CLI for installing audit hooks into AI coding agents.

Agent IDs map to one physical directory directly under `~/.elydora`; portable filename rules and physical directory/config checks apply before writes or recursive removal. Ambiguous uninstall discovery requires an explicit agent ID.

```bash
elydora install \
  --agent claudecode \
  --org_id org-123 \
  --agent_id agent-456 \
  --private_key_file /secure/path/private.key \
  --token_file /secure/path/api.token \
  --kid agent-456-key-v1
```

Credential options may be omitted in an interactive terminal; the CLI then reads the private key and optional API token through hidden prompts. Credential files must contain one UTF-8 line of at most 64 KiB. Unix credential files require owner-only permissions such as `chmod 600`. The installed signing key is stored once at `~/.elydora/<agent-id>/private.key` with mode `0600`, and generated audit hooks read that file at runtime.

Claude Code installation writes exact matchless `PreToolUse`, `PostToolUse`, and `PostToolUseFailure` groups to `$CLAUDE_CONFIG_DIR/settings.json`, with `~/.claude/settings.json` selected when the variable is absent. Relative and empty overrides resolve from the current working directory, matching Claude Code's native path behavior. Each handler uses Claude Code's cross-platform exec form with the current Python executable, a single script argument, and a ten-second timeout. Managed runtimes preserve the complete native snake_case event payload and enforce frozen or revoked state through exit code `2`. Project, local, managed, plugin, skill, and agent hook sources remain unchanged and continue loading additively. User settings, generated runtimes, runtime config, and private key commit as one rollback-capable transaction. `disableAllHooks` blocks installation; managed hook policy and safe mode can suppress user hooks. Run `/hooks` and `claude doctor` after installation.

Codex installation writes exact `PreToolUse` and `PostToolUse` command groups to `$CODEX_HOME/hooks.json` (`~/.codex/hooks.json` by default) and preserves the complete native event payload. A configured `CODEX_HOME` follows Codex's existing-directory canonicalization rule. User TOML, project, plugin, and managed sources remain unchanged and continue loading additively. The hook file, generated runtimes, runtime config, and private key commit as one rollback-capable update. Run `/hooks` after installation and approve both Elydora definition hashes.

GitHub Copilot CLI installation writes exact `preToolUse`, `postToolUse`, and `postToolUseFailure` handlers to `$COPILOT_HOME/hooks/elydora-audit.json` (`~/.copilot/hooks/elydora-audit.json` by default). Empty home overrides select the default. Policy, repository, inline settings, cross-tool Claude, and plugin hook sources remain unchanged and continue loading additively. Elydora evaluates the effective `disableAllHooks` value across Copilot's documented settings precedence before writing. The managed hook file, exact legacy migration, generated runtimes, runtime config, and private key commit through one rollback-capable transaction. Managed commands preserve the complete native camelCase payload and propagate freeze or revocation through exit code `2`; Copilot timeouts retain their documented fail-open behavior. Restart active Copilot CLI sessions after installation.

Cursor installation writes native global `preToolUse`, `postToolUse`, and `postToolUseFailure` handlers to `~/.cursor/hooks.json`. Elydora forwards Cursor's native success and failure payloads, preserves unrelated user hooks, and leaves project and enterprise sources unchanged. The generated guard and audit handlers use a 10-second fail-closed boundary, exact freeze exit-code propagation, protected runtime credentials, and one rollback-capable transaction for all runtime and hook configuration files.

Gemini CLI installation writes named, matchless `BeforeTool` and `AfterTool` command hooks to `$GEMINI_CLI_HOME/.gemini/settings.json` (`~/.gemini/settings.json` by default). Empty home overrides select the OS home; relative and literal-tilde values retain Gemini CLI's native path behavior. JSON comments and unrelated settings remain intact. Workspace, system-default, system-override, and extension hook sources remain unchanged and continue loading additively. User settings, generated runtimes, runtime config, and private key commit through one rollback-capable transaction. Managed handlers preserve the complete native snake_case payload, emit valid JSON on successful execution, propagate freeze and revocation through exit code `2`, and use encoded PowerShell commands on Windows. `hooksConfig.enabled` and `hooksConfig.disabled` remain authoritative. Run `/hooks list` after installation to inspect effective hooks from every source.

Cline installation writes `PreToolUse.mjs` and `PostToolUse.mjs` to `$CLINE_DIR/hooks` (default `~/.cline/hooks`). Documents, `.clinerules/hooks`, and workspace `.cline/hooks` remain unchanged and continue loading additively. Both hook files, generated Python runtimes, runtime config, and private key commit through one rollback-capable transaction. The wrappers preserve Cline 3's complete native payload, resolve Python through each runtime's absolute shebang, and emit the documented one-line JSON cancellation control.

Kimi installation writes exact `PreToolUse`, `PostToolUse`, and `PostToolUseFailure` rules to every detected runtime: Kimi Code's `$KIMI_CODE_HOME/config.toml` (default `~/.kimi-code/config.toml`) and the legacy Python CLI's `~/.kimi/config.toml`. A fresh installation targets stable Kimi Code; an existing legacy home activates the migration contract. Empty `KIMI_CODE_HOME` values use the default. The selected TOML files, generated runtimes, runtime config, and private key commit as one rollback-capable transaction. Managed commands preserve Kimi's native snake_case event JSON, propagate freeze and revocation through exit code `2`, and use encoded PowerShell on Windows. Run `/hooks` to inspect the global rules.

Grok Build installation writes native global `PreToolUse`, `PostToolUse`, and `PostToolUseFailure` hooks to `$GROK_HOME/hooks/elydora-audit.json` (default `~/.grok/hooks/elydora-audit.json`). The hook file, generated runtimes, runtime config, and private key commit as one rollback-capable transaction. Managed commands preserve Grok's native camelCase JSON, return `{"decision":"deny","reason":"..."}` with exit code `2` for frozen or revoked agents, and use encoded PowerShell on Windows. Project hooks follow Grok's `/hooks-trust` workflow; Elydora leaves project, plugin, `hooks-paths`, Claude Code, and Cursor compatibility sources unchanged. Run `grok inspect --json` to inspect the effective hook inventory.

Auggie installation commits `~/.augment/settings.json`, both platform wrappers, generated runtimes, runtime config, and private key as one rollback-capable transaction. The managed `PreToolUse` guard propagates exit code `2`; `PostToolUse` preserves Auggie's complete native hook payload. System, workspace, local workspace, and alternate `--augment-cache-dir` settings remain unchanged. Run `auggie tools list` to validate the effective user configuration.

Factory Droid 0.175.0 installation resolves one active user hook source in this order: `~/.factory/hooks.json`, the legacy `~/.factory/hooks/hooks.json`, then the `hooks` field from user `settings.local.json` and `settings.json`. Current hook files use the documented top-level `hooks` container; legacy direct event maps remain readable until Factory migrates them. Elydora writes exact `PreToolUse` and `PostToolUse` groups to that source, removes exact Elydora ownership from inactive user sources, and keeps project, folder, plugin, and organization hook definitions read-only. System, project, folder, and user `hooksDisabled` values follow Factory's extension-only precedence; system-managed `allowManagedHooksOnly` blocks a user-hook installation. Hook sources, generated runtimes, runtime config, and private key commit through one rollback-capable transaction. Managed commands preserve the complete native snake_case payload, propagate frozen or revoked state through exit code `2`, and use Factory's native PowerShell call operator with explicit `$LASTEXITCODE` propagation on Windows. Run `/hooks` after installation to refresh Droid's session snapshot and verify remote organization policy.

Qwen Code 0.20.0 installation writes exact, named `PreToolUse`, `PostToolUse`, and `PostToolUseFailure` command hooks to `$QWEN_HOME/settings.json` (default `~/.qwen/settings.json`). Explicit environment values lead Qwen's home bootstrap, followed by `<QWEN_HOME>/.env` or `~/.qwen/.env`, then `~/.env`; a discovered home contributes its own `.env`. System defaults, trusted workspace settings, system overrides, and trust rules remain read-only and participate in effective `disableAllHooks` evaluation. User settings, generated runtimes, runtime config, and private key commit through one rollback-capable transaction guarded by snapshots of every consulted source. Managed handlers use ten-second millisecond timeouts, preserve Qwen's complete native snake_case payload for success and failure events, and propagate frozen or revoked state through exit code `2`. Run `/hooks` after installation and restart active Qwen Code sessions.

Kiro CLI installation covers both runtime contracts. Kiro CLI v2 uses the generated custom agent through `kiro-cli --agent elydora-audit`. Kiro CLI v3 loads the global standalone hooks when started with `kiro-cli --v3`.

### Commands

| Command | Description |
|---------|-------------|
| `elydora install` | Install Elydora audit hook for a coding agent |
| `elydora uninstall` | Remove Elydora audit hook for a coding agent |
| `elydora status` | Show installation status for all agents |
| `elydora agents` | List supported coding agents |

### Supported Agents

| Agent | Key |
|-------|-----|
| Augment Code CLI | `augment` |
| Claude Code | `claudecode` |
| OpenAI Codex | `codex` |
| Cline | `cline` |
| Kimi Code | `kimi` |
| Grok Build | `grok` |
| GitHub Copilot CLI | `copilot` |
| Cursor | `cursor` |
| Factory Droid | `droid` |
| Gemini CLI | `gemini` |
| Kiro CLI | `kirocli` |
| Kiro IDE | `kiroide` |
| Letta Code | `letta` |
| OpenCode | `opencode` |
| Qwen Code | `qwen` |

## API Reference

### Configuration

```python
client = ElydoraClient(
    org_id="org-123",           # Organization ID
    agent_id="agent-456",       # Agent ID
    private_key="<seed>",       # Base64url-encoded Ed25519 seed
    base_url="https://...",     # API base URL (default: https://api.elydora.com)
    ttl_ms=30000,               # Operation TTL in ms (default: 30000)
    max_retries=3,              # Retries after the initial attempt (default: 3)
    token="<api-token>",         # Optional API token
)
```

Automatic retries apply to RFC-idempotent methods.
Connection failures that prove a request was never sent can also retry non-idempotent methods.
Retryable responses honor both `Retry-After` seconds and HTTP-date values.

### Authentication

```python
# Register a new user and organization
reg = ElydoraClient.register(base_url, email, password, display_name=None, org_name=None)

# Login and receive a session token
auth = ElydoraClient.login(base_url, email, password)

# Get current authenticated user profile
me = client.get_me()

# Issue a new API token (with optional TTL in seconds)
token_resp = client.issue_token(ttl_seconds=3600)
```

### Operations

```python
# Create a signed EOR locally (no network call)
eor = client.create_operation(
    operation_type="inference",
    subject={"model": "gpt-4"},
    action={"type": "completion"},
    payload={"prompt": "Hello"},
)

# Submit to API
response = client.submit_operation(eor)

# Retrieve an operation
op = client.get_operation(operation_id)

# Verify integrity
result = client.verify_operation(operation_id)
```

### Agent Management

```python
# Register a new agent
agent = client.register_agent({
    "agent_id": "my-agent",
    "integration_type": "codex",
    "display_name": "My Agent",
    "responsible_entity": "team@example.com",
    "keys": [{"kid": "key-v1", "public_key": "<base64url>", "algorithm": "ed25519"}],
})

# Get agent details
details = client.get_agent(agent_id)

# Freeze an agent
client.freeze_agent(agent_id, reason="security review")

# Revoke a key
client.revoke_key(agent_id, kid, reason="key rotation")

# List all agents in the organization
agents_resp = client.list_agents()

# Unfreeze a previously frozen agent
client.unfreeze_agent(agent_id, reason="review complete")

# Delete an agent permanently
deleted_resp = client.delete_agent(agent_id)
```

### Audit

```python
import time

results = client.query_audit(
    agent_id="agent-123",
    operation_type="inference",
    start_time=int(time.time() * 1000) - 86400000,
    end_time=int(time.time() * 1000),
    limit=50,
)
```

### Epochs

```python
epochs = client.list_epochs()
epoch = client.get_epoch(epoch_id)
```

### Exports

```python
export = client.create_export(
    start_time=start,
    end_time=end,
    format="json",
)

exports = client.list_exports()
detail = client.get_export(export_id)

# Download export file data
data = client.download_export(export_id)
```

### JWKS

```python
jwks = client.get_jwks()
```

### Health

```python
# Check API health (no authentication required)
health = client.health()
# health["status"], health["version"], health["protocol_version"], health["timestamp"]
```

### Crypto Functions

The SDK exports low-level cryptographic primitives for advanced use:

```python
from elydora import (
    jcs_canonicalize,          # RFC 8785 JSON Canonicalization
    sha256_base64url,          # SHA-256 hash as base64url
    compute_chain_hash,        # Chain hash computation
    compute_payload_hash,      # Payload hash (SHA-256 of JCS-canonicalized payload)
    sign_ed25519,              # Ed25519 signing
    sign_eor,                  # Sign an EOR dict
    get_public_key_base64url,  # Derive public key from private seed
)
```

### Utility Functions

```python
from elydora import (
    base64url_encode,   # Encode bytes to base64url (no padding)
    base64url_decode,   # Decode base64url string to bytes
    generate_nonce,     # Generate 16-byte random nonce (base64url)
    generate_uuidv7,    # Generate UUIDv7 (time-ordered, RFC 9562)
)
```

### Type Definitions

All types are `TypedDict` classes for structural typing:

```python
from elydora import (
    # Protocol types
    EOR,                       # Elydora Operation Record
    EAR,                       # Elydora Acknowledgment Receipt

    # Entity types
    Agent, AgentKey, Operation, Receipt, Epoch, Export, Organization, User,

    # API response types
    RegisterAgentResponse, GetAgentResponse, ListAgentsResponse,
    DeleteAgentResponse, SubmitOperationResponse, GetOperationResponse,
    VerifyOperationResponse, AuditQueryResponse, GetEpochResponse,
    ListEpochsResponse, CreateExportResponse, GetExportResponse,
    ListExportsResponse, JWKSResponse, AuthRegisterResponse,
    AuthLoginResponse, GetMeResponse, IssueTokenResponse, HealthResponse,

    # Request types
    RegisterAgentRequest,
)
```

## Error Handling

```python
from elydora import ElydoraError

try:
    client.submit_operation(eor)
except ElydoraError as e:
    print(e.code)        # e.g. "INVALID_SIGNATURE"
    print(e.message)     # Human-readable message
    print(e.status_code) # HTTP status code
    print(e.request_id)  # Request ID for support
```

## Dependencies

- [requests](https://pypi.org/project/requests/) - Sync HTTP client
- [aiohttp](https://pypi.org/project/aiohttp/) - Async HTTP client
- [cryptography](https://pypi.org/project/cryptography/) - Ed25519 signing

## License

MIT
