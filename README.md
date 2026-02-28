# Elydora Python SDK

Python SDK for the Elydora tamper-evident audit platform.

## Installation

```bash
pip install elydora
```

## Quick Start

```python
from elydora import ElydoraClient

client = ElydoraClient(
    org_id="org_...",
    agent_id="agent_...",
    private_key="<base64url-encoded-ed25519-seed>",
    base_url="https://api.elydora.com",
    token="<jwt-token>",
)

# Create and submit an operation
eor = client.create_operation(
    operation_type="data.access",
    subject={"user_id": "u123"},
    action={"type": "read", "resource": "documents"},
    payload={"document_id": "doc_456"},
)
response = client.submit_operation(eor)
print(response["receipt"]["receipt_id"])
```

## Async Usage

```python
from elydora import AsyncElydoraClient

async def main():
    client = AsyncElydoraClient(
        org_id="org_...",
        agent_id="agent_...",
        private_key="<base64url-encoded-ed25519-seed>",
        base_url="https://api.elydora.com",
        token="<jwt-token>",
    )
    eor = client.create_operation(
        operation_type="data.access",
        subject={"user_id": "u123"},
        action={"type": "read", "resource": "documents"},
    )
    response = await client.submit_operation(eor)
    await client.close()
```
