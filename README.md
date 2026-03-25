# Elydora Python SDK

Official Python SDK for the [Elydora](https://elydora.com) tamper-evident audit platform. Build cryptographically verifiable audit trails for AI agent operations.

## Installation

```bash
pip install elydora
```

Requires Python 3.9+.

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

```bash
elydora install \
  --agent claudecode \
  --org_id org-123 \
  --agent_id agent-456 \
  --private_key <key> \
  --kid agent-456-key-v1
```

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
| Claude Code | `claudecode` |
| Copilot CLI | `copilot` |
| Cursor | `cursor` |
| Gemini CLI | `gemini` |
| Kiro CLI | `kirocli` |
| Kiro IDE | `kiroide` |
| Letta Code | `letta` |
| OpenCode | `opencode` |

## API Reference

### Configuration

```python
client = ElydoraClient(
    org_id="org-123",           # Organization ID
    agent_id="agent-456",       # Agent ID
    private_key="<seed>",       # Base64url-encoded Ed25519 seed
    base_url="https://...",     # API base URL (default: https://api.elydora.com)
    ttl_ms=30000,               # Operation TTL in ms (default: 30000)
    max_retries=3,              # Max retries on transient failures (default: 3)
    token="<api-token>",         # Optional API token
)
```

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
