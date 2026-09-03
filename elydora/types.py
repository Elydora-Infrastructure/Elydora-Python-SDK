"""TypedDict definitions matching the Elydora Backend API contract."""

import sys
from typing import Any, Dict, List, Optional, Tuple

if sys.version_info >= (3, 11):
    from typing import Literal, NotRequired, TypedDict
else:
    from typing_extensions import Literal, NotRequired, TypedDict


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
IntegrationType = Literal[
    "augment",
    "claudecode",
    "cline",
    "codex",
    "copilot",
    "cursor",
    "droid",
    "gemini",
    "grok",
    "kimi",
    "kirocli",
    "kiroide",
    "letta",
    "opencode",
    "qwen",
    "enterprise",
    "gui",
    "sdk",
    "other",
]
INTEGRATION_TYPES: Tuple[IntegrationType, ...] = (
    "augment", "claudecode", "cline", "codex", "copilot", "cursor", "droid",
    "gemini", "grok", "kimi", "kirocli", "kiroide", "letta", "opencode", "qwen",
    "enterprise", "gui", "sdk", "other",
)
AdminAction = Literal[
    "agent.register",
    "agent.update",
    "agent.freeze",
    "agent.unfreeze",
    "agent.revoke",
    "agent.delete",
    "key.revoke",
    "export.create",
    "org.create",
    "org.update",
    "member.invite",
    "invitation.cancel",
    "member.remove",
    "member.role_change",
    "agent.assign",
    "agent.unassign",
    "webhook.register",
    "webhook.delete",
]
ErrorCode = Literal[
    "INVALID_SIGNATURE",
    "UNKNOWN_AGENT",
    "KEY_REVOKED",
    "KEY_RETIRED",
    "AGENT_FROZEN",
    "AGENT_REVOKED",
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

class Agent(TypedDict):
    agent_id: str
    org_id: str
    display_name: str
    responsible_entity: str
    status: AgentStatus
    integration_type: IntegrationType
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
    description: Optional[str]
    ba_org_id: Optional[str]
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


class RegisterAgentKeyParam(TypedDict):
    kid: str
    public_key: str
    algorithm: Literal["ed25519"]


class RegisterAgentRequest(TypedDict):
    agent_id: str
    integration_type: IntegrationType
    keys: List[RegisterAgentKeyParam]
    display_name: NotRequired[str]
    responsible_entity: NotRequired[str]


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
    payload: Any


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


class EpochAnchor(TypedDict, total=False):
    tsa_url: str
    anchored_at: int
    tsa_token: str
    root_hash: str


class GetEpochResponse(TypedDict, total=False):
    epoch: Epoch
    anchor: EpochAnchor


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


class ListAgentsResponse(TypedDict):
    agents: List[Agent]


class DeleteAgentResponse(TypedDict):
    deleted: bool


class AuthMeUser(TypedDict):
    user_id: str
    org_id: Optional[str]
    email: str
    display_name: str
    role: RbacRole
    status: Literal["active", "suspended"]
    created_at: int
    updated_at: int
    onboarding_completed: bool


class CurrentOrganization(TypedDict):
    org_id: Optional[str]
    ba_org_id: Optional[str]
    role: RbacRole


class GetMeResponse(TypedDict):
    user: AuthMeUser
    current_organization: CurrentOrganization


class IssueApiTokenResponse(TypedDict):
    token: str
    expires_at: Optional[int]
    token_id: str


class RotateApiTokenResponse(TypedDict):
    token: str
    expires_at: Optional[int]
    token_id: str


class HealthResponse(TypedDict):
    status: str
    version: str
    protocol_version: str
    capabilities: Dict[str, str]
    timestamp: int


class AdminEvent(TypedDict):
    event_id: str
    org_id: str
    actor: str
    action: str
    target_type: str
    target_id: str
    details: Optional[str]
    created_at: int


class AgentAssignment(TypedDict):
    id: str
    agent_id: str
    user_id: str
    org_id: str
    assigned_by: str
    created_at: int


class WebhookEntry(TypedDict):
    webhook_id: str
    org_id: str
    endpoint_url: str
    events: List[str]
    status: Literal["active", "disabled"]
    created_at: int
    updated_at: int


class MemberEntry(TypedDict):
    member_id: str
    user_id: str
    role: str
    joined_at: str
    email: str
    display_name: str


class UpdateAgentRequest(TypedDict):
    integration_type: IntegrationType


class UpdateAgentResponse(TypedDict):
    agent: Agent


class FreezeAgentResponse(TypedDict):
    agent: Agent
    previous_status: AgentStatus


class UnfreezeAgentResponse(TypedDict):
    agent: Agent
    previous_status: AgentStatus


class ListWebhooksResponse(TypedDict):
    webhooks: List[WebhookEntry]


class RegisterWebhookResponse(TypedDict):
    webhook: WebhookEntry


class ListMembersResponse(TypedDict):
    members: List[MemberEntry]


class ListAdminEventsResponse(TypedDict):
    events: List[AdminEvent]


class DependencyHealth(TypedDict):
    status: Literal["ok", "failed"]
    latency_ms: int
    contract_phase: NotRequired[Literal["expand", "contract"]]


class DeepHealthResponse(TypedDict):
    status: Literal["healthy", "degraded"]
    version: str
    protocol_version: str
    capabilities: Dict[str, str]
    timestamp: int
    dependencies: Dict[str, DependencyHealth]
