"""Type definitions matching the Elydora backend API contract.

All types use TypedDict for structural typing, compatible with Python 3.9+.
"""

from __future__ import annotations

import sys
from typing import Any, Dict, List, Optional

if sys.version_info >= (3, 11):
    from typing import Literal, TypedDict
else:
    from typing_extensions import Literal, TypedDict


# ---------------------------------------------------------------------------
# Enums (as Literal types)
# ---------------------------------------------------------------------------

AgentStatus = Literal["active", "frozen", "revoked"]
KeyStatus = Literal["active", "retired", "revoked"]
ExportStatus = Literal["queued", "running", "done", "failed"]
RbacRole = Literal[
    "org_owner",
    "security_admin",
    "compliance_auditor",
    "readonly_investigator",
    "integration_engineer",
]
ErrorCode = Literal[
    "INVALID_SIGNATURE",
    "UNKNOWN_AGENT",
    "KEY_REVOKED",
    "AGENT_FROZEN",
    "TTL_EXPIRED",
    "REPLAY_DETECTED",
    "PREV_HASH_MISMATCH",
    "PAYLOAD_TOO_LARGE",
    "RATE_LIMITED",
    "INTERNAL_ERROR",
    "UNAUTHORIZED",
    "FORBIDDEN",
    "NOT_FOUND",
    "VALIDATION_ERROR",
]

# ---------------------------------------------------------------------------
# Entity types
# ---------------------------------------------------------------------------


class Agent(TypedDict):
    agent_id: str
    org_id: str
    display_name: str
    responsible_entity: str
    status: AgentStatus
    created_at: int
    updated_at: int


class AgentKey(TypedDict):
    kid: str
    agent_id: str
    public_key: str
    algorithm: Literal["ed25519"]
    status: KeyStatus
    created_at: int
    retired_at: Optional[int]


class Operation(TypedDict):
    operation_id: str
    org_id: str
    agent_id: str
    seq_no: int
    operation_type: str
    issued_at: int
    ttl_ms: int
    nonce: str
    subject: str
    action: str
    payload_hash: str
    prev_chain_hash: str
    chain_hash: str
    agent_pubkey_kid: str
    signature: str
    r2_payload_key: Optional[str]
    created_at: int


class Receipt(TypedDict):
    receipt_id: str
    operation_id: str
    r2_receipt_key: str
    created_at: int


class Epoch(TypedDict):
    epoch_id: str
    org_id: str
    start_time: int
    end_time: int
    root_hash: str
    leaf_count: int
    r2_epoch_key: str
    created_at: int


class Organization(TypedDict):
    org_id: str
    name: str
    created_at: int
    updated_at: int


class User(TypedDict):
    user_id: str
    org_id: str
    email: str
    display_name: str
    role: RbacRole
    status: Literal["active", "suspended"]
    created_at: int
    updated_at: int


class Export(TypedDict):
    export_id: str
    org_id: str
    status: ExportStatus
    query_params: str
    r2_export_key: Optional[str]
    created_at: int
    completed_at: Optional[int]


# ---------------------------------------------------------------------------
# Protocol types
# ---------------------------------------------------------------------------


class EOR(TypedDict):
    """Elydora Operation Record."""
    op_version: Literal["1.0"]
    operation_id: str
    org_id: str
    agent_id: str
    issued_at: int
    ttl_ms: int
    nonce: str
    operation_type: str
    subject: Dict[str, Any]
    action: Dict[str, Any]
    payload: Any  # Dict[str, Any] | str | None
    payload_hash: str
    prev_chain_hash: str
    agent_pubkey_kid: str
    signature: str


class EAR(TypedDict):
    """Elydora Acknowledgment Receipt."""
    receipt_version: str
    receipt_id: str
    operation_id: str
    org_id: str
    agent_id: str
    server_received_at: int
    seq_no: int
    chain_hash: str
    queue_message_id: str
    receipt_hash: str
    elydora_kid: str
    elydora_signature: str


# ---------------------------------------------------------------------------
# API request types
# ---------------------------------------------------------------------------


class RegisterAgentKeyParam(TypedDict):
    kid: str
    public_key: str
    algorithm: Literal["ed25519"]


class RegisterAgentRequest(TypedDict, total=False):
    agent_id: str
    display_name: str
    responsible_entity: str
    keys: List[RegisterAgentKeyParam]


class AuditQueryParams(TypedDict, total=False):
    org_id: str
    agent_id: str
    operation_type: str
    start_time: int
    end_time: int
    cursor: str
    limit: int


# ---------------------------------------------------------------------------
# API response types
# ---------------------------------------------------------------------------


class RegisterAgentResponse(TypedDict):
    agent: Agent
    keys: List[AgentKey]


class GetAgentResponse(TypedDict):
    agent: Agent
    keys: List[AgentKey]


class SubmitOperationResponse(TypedDict):
    receipt: EAR


class GetOperationResponse(TypedDict, total=False):
    operation: Operation
    receipt: Receipt


class VerifyChecks(TypedDict, total=False):
    signature: bool
    chain: bool
    receipt: bool
    merkle: bool


class VerifyOperationResponse(TypedDict, total=False):
    valid: bool
    checks: VerifyChecks
    errors: List[str]


class AuditQueryResponse(TypedDict):
    operations: List[Operation]
    cursor: Optional[str]
    total_count: int


class GetEpochResponse(TypedDict, total=False):
    epoch: Epoch
    anchor: Dict[str, Any]


class ListEpochsResponse(TypedDict):
    epochs: List[Epoch]


class CreateExportResponse(TypedDict):
    export: Export


class GetExportResponse(TypedDict, total=False):
    export: Export
    download_url: str


class ListExportsResponse(TypedDict):
    exports: List[Export]


class JWK(TypedDict, total=False):
    kty: str
    crv: str
    x: str
    kid: str
    use: str
    alg: str


class JWKSResponse(TypedDict):
    keys: List[JWK]


class AuthRegisterResponse(TypedDict):
    user: User
    organization: Organization
    token: str


class AuthLoginResponse(TypedDict):
    user: User
    token: str
