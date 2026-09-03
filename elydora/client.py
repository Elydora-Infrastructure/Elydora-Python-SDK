"""Synchronous Elydora client using the requests library."""

from __future__ import annotations

import warnings
from typing import Any, Dict, List, Optional, Union

import requests

from ._client_common import (
    DEFAULT_BASE_URL,
    GENESIS_CHAIN_HASH,
    REQUEST_TIMEOUT_SECONDS,
    admin_events_params,
    api_token_body,
    build_eor,
    build_headers,
    error_from_response,
    export_body,
    register_body,
    without_none,
)
from ._retry import require_max_retries
from ._sync_http import request_with_retries
from .integration_types import require_integration_type
from .types import (
    AuditQueryResponse,
    AuthLoginResponse,
    AuthRegisterResponse,
    CreateExportResponse,
    DeepHealthResponse,
    DeleteAgentResponse,
    EOR,
    FreezeAgentResponse,
    GetAgentResponse,
    GetEpochResponse,
    GetExportResponse,
    GetMeResponse,
    GetOperationResponse,
    HealthResponse,
    IntegrationType,
    IssueApiTokenResponse,
    JWKSResponse,
    ListAdminEventsResponse,
    ListAgentsResponse,
    ListEpochsResponse,
    ListExportsResponse,
    ListMembersResponse,
    ListWebhooksResponse,
    RegisterAgentRequest,
    RegisterAgentResponse,
    RegisterWebhookResponse,
    RotateApiTokenResponse,
    SubmitOperationResponse,
    UnfreezeAgentResponse,
    UpdateAgentResponse,
    VerifyOperationResponse,
)


class ElydoraClient:
    """Synchronous client for the Elydora API.

    Args:
        org_id: Organization identifier.
        agent_id: Agent identifier.
        private_key: Base64url-encoded 32-byte Ed25519 private key seed.
        base_url: API base URL.
        ttl_ms: Time-to-live for operations in milliseconds.
        max_retries: Retries after the initial attempt on transient failures.
        token: Optional API token for authenticated endpoints.
    """

    def __init__(
        self,
        org_id: str,
        agent_id: str,
        private_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        ttl_ms: int = 30000,
        max_retries: int = 3,
        token: Optional[str] = None,
    ) -> None:
        self.org_id = org_id
        self.agent_id = agent_id
        self.private_key = private_key
        self.base_url = base_url.rstrip("/")
        self.ttl_ms = ttl_ms
        self.max_retries = require_max_retries(max_retries)
        self.token = token
        self._prev_chain_hash = GENESIS_CHAIN_HASH
        self._kid = agent_id + "-key-1"
        self._session = requests.Session()

    def set_kid(self, kid: str) -> None:
        self._kid = kid

    def set_prev_chain_hash(self, prev_chain_hash: str) -> None:
        self._prev_chain_hash = prev_chain_hash

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        params: Optional[Dict[str, str]] = None,
    ) -> Any:
        return request_with_retries(
            self._session,
            method,
            f"{self.base_url}{path}",
            path=path,
            max_retries=self.max_retries,
            response_handler=self._handle_response,
            json_body=json_body,
            params=params,
            headers=build_headers(self.token),
        )

    def _get_public(self, path: str, *, accept_status: Optional[int] = None) -> Any:
        response = self._session.get(f"{self.base_url}{path}", timeout=REQUEST_TIMEOUT_SECONDS)
        if accept_status is not None and response.status_code == accept_status:
            return response.json()
        return self._handle_response(response)

    @staticmethod
    def _handle_response(resp: requests.Response) -> Any:
        if resp.status_code >= 400:
            try:
                body = resp.json()
            except ValueError:
                body = None
            raise error_from_response(resp.status_code, body, resp.text)
        if resp.status_code == 204:
            return None
        return resp.json()

    @staticmethod
    def _post_json(url: str, body: Dict[str, Any]) -> Any:
        response = requests.post(
            url,
            json=body,
            headers=build_headers(None),
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        return ElydoraClient._handle_response(response)

    @staticmethod
    def register(
        base_url: str,
        email: str,
        password: str,
        display_name: Optional[str] = None,
        org_name: Optional[str] = None,
    ) -> AuthRegisterResponse:
        """Deprecated password registration; Console users sign in through Better Auth."""
        warnings.warn(
            "ElydoraClient.register() is deprecated. Use Better Auth endpoints directly.",
            DeprecationWarning,
            stacklevel=2,
        )
        url = f"{base_url.rstrip('/')}/v1/auth/register"
        return ElydoraClient._post_json(url, register_body(email, password, display_name, org_name))

    @staticmethod
    def login(base_url: str, email: str, password: str) -> AuthLoginResponse:
        """Deprecated password login; Console users sign in through Better Auth."""
        warnings.warn(
            "ElydoraClient.login() is deprecated. Use Better Auth endpoints directly.",
            DeprecationWarning,
            stacklevel=2,
        )
        url = f"{base_url.rstrip('/')}/v1/auth/login"
        return ElydoraClient._post_json(url, {"email": email, "password": password})

    def get_me(self) -> GetMeResponse:
        return self._request("GET", "/v1/auth/me")

    def issue_api_token(self, ttl_seconds: Optional[int] = None) -> IssueApiTokenResponse:
        return self._request("POST", "/v1/auth/token", json_body=api_token_body(ttl_seconds))

    def issue_token(self, ttl_seconds: Optional[int] = None) -> IssueApiTokenResponse:
        """Deprecated alias for issue_api_token()."""
        warnings.warn(
            "ElydoraClient.issue_token() is deprecated. Use issue_api_token().",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.issue_api_token(ttl_seconds=ttl_seconds)

    def rotate_api_token(self) -> RotateApiTokenResponse:
        return self._request("POST", "/v1/auth/rotate", json_body={})

    def register_agent(self, request: RegisterAgentRequest) -> RegisterAgentResponse:
        require_integration_type(request.get("integration_type"))
        return self._request("POST", "/v1/agents/register", json_body=request)

    def get_agent(self, agent_id: str) -> GetAgentResponse:
        return self._request("GET", f"/v1/agents/{agent_id}")

    def list_agents(self) -> ListAgentsResponse:
        return self._request("GET", "/v1/agents")

    def freeze_agent(self, agent_id: str, reason: str) -> FreezeAgentResponse:
        return self._request("POST", f"/v1/agents/{agent_id}/freeze", json_body={"reason": reason})

    def unfreeze_agent(self, agent_id: str, reason: str) -> UnfreezeAgentResponse:
        return self._request("POST", f"/v1/agents/{agent_id}/unfreeze", json_body={"reason": reason})

    def update_agent(self, agent_id: str, integration_type: IntegrationType) -> UpdateAgentResponse:
        require_integration_type(integration_type)
        return self._request(
            "PATCH", f"/v1/agents/{agent_id}", json_body={"integration_type": integration_type}
        )

    def delete_agent(self, agent_id: str) -> DeleteAgentResponse:
        return self._request("DELETE", f"/v1/agents/{agent_id}")

    def revoke_key(self, agent_id: str, kid: str, reason: str) -> None:
        self._request(
            "POST", f"/v1/agents/{agent_id}/revoke", json_body={"kid": kid, "reason": reason}
        )

    def create_operation(
        self,
        operation_type: str,
        subject: Dict[str, Any],
        action: Dict[str, Any],
        payload: Union[Dict[str, Any], str, None] = None,
    ) -> EOR:
        """Build and sign an EOR locally; submit it with submit_operation()."""
        eor, chain_hash = build_eor(
            org_id=self.org_id,
            agent_id=self.agent_id,
            private_key=self.private_key,
            kid=self._kid,
            ttl_ms=self.ttl_ms,
            prev_chain_hash=self._prev_chain_hash,
            operation_type=operation_type,
            subject=subject,
            action=action,
            payload=payload,
        )
        self._prev_chain_hash = chain_hash
        return eor

    def submit_operation(self, eor: EOR) -> SubmitOperationResponse:
        return self._request("POST", "/v1/operations", json_body=eor)

    def get_operation(self, operation_id: str) -> GetOperationResponse:
        return self._request("GET", f"/v1/operations/{operation_id}")

    def verify_operation(self, operation_id: str) -> VerifyOperationResponse:
        return self._request("POST", f"/v1/operations/{operation_id}/verify", json_body={})

    def query_audit(
        self,
        *,
        org_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        operation_type: Optional[str] = None,
        start_time: Optional[int] = None,
        end_time: Optional[int] = None,
        cursor: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> AuditQueryResponse:
        body = without_none({
            "org_id": org_id,
            "agent_id": agent_id,
            "operation_type": operation_type,
            "start_time": start_time,
            "end_time": end_time,
            "cursor": cursor,
            "limit": limit,
        })
        return self._request("POST", "/v1/audit/query", json_body=body)

    def list_epochs(self) -> ListEpochsResponse:
        return self._request("GET", "/v1/epochs")

    def get_epoch(self, epoch_id: str) -> GetEpochResponse:
        return self._request("GET", f"/v1/epochs/{epoch_id}")

    def create_export(
        self,
        start_time: int,
        end_time: int,
        format: str = "json",
        agent_id: Optional[str] = None,
        operation_type: Optional[str] = None,
    ) -> CreateExportResponse:
        body = export_body(start_time, end_time, format, agent_id, operation_type)
        return self._request("POST", "/v1/exports", json_body=body)

    def list_exports(self) -> ListExportsResponse:
        return self._request("GET", "/v1/exports")

    def get_export(self, export_id: str) -> GetExportResponse:
        return self._request("GET", f"/v1/exports/{export_id}")

    def download_export(self, export_id: str) -> bytes:
        response = self._session.get(
            f"{self.base_url}/v1/exports/{export_id}/download",
            headers=build_headers(self.token),
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        if response.status_code >= 400:
            self._handle_response(response)
        return response.content

    def list_webhooks(self) -> ListWebhooksResponse:
        return self._request("GET", "/v1/webhooks")

    def register_webhook(
        self, endpoint_url: str, events: List[str], secret: str
    ) -> RegisterWebhookResponse:
        body = {"endpoint_url": endpoint_url, "events": events, "secret": secret}
        return self._request("POST", "/v1/webhooks", json_body=body)

    def delete_webhook(self, webhook_id: str) -> None:
        self._request("DELETE", f"/v1/webhooks/{webhook_id}")

    def list_members(self) -> ListMembersResponse:
        return self._request("GET", "/v1/members")

    def list_admin_events(self, limit: Optional[int] = None) -> ListAdminEventsResponse:
        return self._request("GET", "/v1/admin/events", params=admin_events_params(limit))

    def get_jwks(self) -> JWKSResponse:
        return self._get_public("/.well-known/elydora/jwks.json")

    def health(self) -> HealthResponse:
        return self._get_public("/v1/health")

    def deep_health(self) -> DeepHealthResponse:
        """503 carries the degraded report, not an error."""
        return self._get_public("/v1/health/deep", accept_status=503)
