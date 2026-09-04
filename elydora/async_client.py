"""Asynchronous Elydora client using aiohttp."""

from __future__ import annotations

import warnings
from urllib.parse import quote
from typing import Any, Dict, List, Optional, Union

import aiohttp

from ._async_http import request_with_retries
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

TIMEOUT = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)


class AsyncElydoraClient:
    """Asynchronous client for the Elydora API.

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
        self._session: Optional[aiohttp.ClientSession] = None

    def set_kid(self, kid: str) -> None:
        self._kid = kid

    def set_prev_chain_hash(self, prev_chain_hash: str) -> None:
        self._prev_chain_hash = prev_chain_hash

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        params: Optional[Dict[str, str]] = None,
    ) -> Any:
        return await request_with_retries(
            await self._get_session(),
            method,
            f"{self.base_url}{path}",
            path=path,
            max_retries=self.max_retries,
            response_handler=self._handle_response,
            json_body=json_body,
            params=params,
            headers=build_headers(self.token),
        )

    async def _get_public(self, path: str, *, accept_status: Optional[int] = None) -> Any:
        session = await self._get_session()
        async with session.get(f"{self.base_url}{path}", timeout=TIMEOUT) as response:
            if accept_status is not None and response.status == accept_status:
                return await response.json()
            return await self._handle_response(response)

    @staticmethod
    async def _handle_response(resp: aiohttp.ClientResponse) -> Any:
        if resp.status >= 400:
            try:
                body = await resp.json()
            except (aiohttp.ContentTypeError, ValueError):
                body = None
            raise error_from_response(resp.status, body, await resp.text())
        if resp.status == 204:
            return None
        return await resp.json()

    @staticmethod
    async def _post_json(url: str, body: Dict[str, Any]) -> Any:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url, json=body, headers=build_headers(None), timeout=TIMEOUT
            ) as response:
                return await AsyncElydoraClient._handle_response(response)

    @staticmethod
    async def register(
        base_url: str,
        email: str,
        password: str,
        display_name: Optional[str] = None,
        org_name: Optional[str] = None,
    ) -> AuthRegisterResponse:
        """Deprecated password registration; Console users sign in through Better Auth."""
        warnings.warn(
            "AsyncElydoraClient.register() is deprecated. Use Better Auth endpoints directly.",
            DeprecationWarning,
            stacklevel=2,
        )
        url = f"{base_url.rstrip('/')}/v1/auth/register"
        return await AsyncElydoraClient._post_json(
            url, register_body(email, password, display_name, org_name)
        )

    @staticmethod
    async def login(base_url: str, email: str, password: str) -> AuthLoginResponse:
        """Deprecated password login; Console users sign in through Better Auth."""
        warnings.warn(
            "AsyncElydoraClient.login() is deprecated. Use Better Auth endpoints directly.",
            DeprecationWarning,
            stacklevel=2,
        )
        url = f"{base_url.rstrip('/')}/v1/auth/login"
        return await AsyncElydoraClient._post_json(url, {"email": email, "password": password})

    async def get_me(self) -> GetMeResponse:
        return await self._request("GET", "/v1/auth/me")

    async def issue_api_token(self, ttl_seconds: Optional[int] = None) -> IssueApiTokenResponse:
        return await self._request(
            "POST", "/v1/auth/token", json_body=api_token_body(ttl_seconds)
        )

    async def issue_token(self, ttl_seconds: Optional[int] = None) -> IssueApiTokenResponse:
        """Deprecated alias for issue_api_token()."""
        warnings.warn(
            "AsyncElydoraClient.issue_token() is deprecated. Use issue_api_token().",
            DeprecationWarning,
            stacklevel=2,
        )
        return await self.issue_api_token(ttl_seconds=ttl_seconds)

    async def rotate_api_token(self) -> RotateApiTokenResponse:
        return await self._request("POST", "/v1/auth/rotate", json_body={})

    async def register_agent(self, request: RegisterAgentRequest) -> RegisterAgentResponse:
        require_integration_type(request.get("integration_type"))
        return await self._request("POST", "/v1/agents/register", json_body=request)

    async def get_agent(self, agent_id: str) -> GetAgentResponse:
        return await self._request("GET", f"/v1/agents/{quote(agent_id, safe='')}")

    async def list_agents(self) -> ListAgentsResponse:
        return await self._request("GET", "/v1/agents")

    async def freeze_agent(self, agent_id: str, reason: str) -> FreezeAgentResponse:
        return await self._request(
            "POST", f"/v1/agents/{quote(agent_id, safe='')}/freeze", json_body={"reason": reason}
        )

    async def unfreeze_agent(self, agent_id: str, reason: str) -> UnfreezeAgentResponse:
        return await self._request(
            "POST", f"/v1/agents/{quote(agent_id, safe='')}/unfreeze", json_body={"reason": reason}
        )

    async def update_agent(
        self, agent_id: str, integration_type: IntegrationType
    ) -> UpdateAgentResponse:
        require_integration_type(integration_type)
        return await self._request(
            "PATCH", f"/v1/agents/{quote(agent_id, safe='')}", json_body={"integration_type": integration_type}
        )

    async def delete_agent(self, agent_id: str) -> DeleteAgentResponse:
        return await self._request("DELETE", f"/v1/agents/{quote(agent_id, safe='')}")

    async def revoke_key(self, agent_id: str, kid: str, reason: str) -> None:
        await self._request(
            "POST", f"/v1/agents/{quote(agent_id, safe='')}/revoke", json_body={"kid": kid, "reason": reason}
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

    async def submit_operation(self, eor: EOR) -> SubmitOperationResponse:
        return await self._request("POST", "/v1/operations", json_body=eor)

    async def get_operation(self, operation_id: str) -> GetOperationResponse:
        return await self._request("GET", f"/v1/operations/{operation_id}")

    async def verify_operation(self, operation_id: str) -> VerifyOperationResponse:
        return await self._request(
            "POST", f"/v1/operations/{operation_id}/verify", json_body={}
        )

    async def query_audit(
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
        return await self._request("POST", "/v1/audit/query", json_body=body)

    async def list_epochs(self) -> ListEpochsResponse:
        return await self._request("GET", "/v1/epochs")

    async def get_epoch(self, epoch_id: str) -> GetEpochResponse:
        return await self._request("GET", f"/v1/epochs/{epoch_id}")

    async def create_export(
        self,
        start_time: int,
        end_time: int,
        format: str = "json",
        agent_id: Optional[str] = None,
        operation_type: Optional[str] = None,
    ) -> CreateExportResponse:
        body = export_body(start_time, end_time, format, agent_id, operation_type)
        return await self._request("POST", "/v1/exports", json_body=body)

    async def list_exports(self) -> ListExportsResponse:
        return await self._request("GET", "/v1/exports")

    async def get_export(self, export_id: str) -> GetExportResponse:
        return await self._request("GET", f"/v1/exports/{export_id}")

    async def download_export(self, export_id: str) -> bytes:
        session = await self._get_session()
        async with session.get(
            f"{self.base_url}/v1/exports/{export_id}/download",
            headers=build_headers(self.token),
            timeout=TIMEOUT,
        ) as response:
            if response.status >= 400:
                await self._handle_response(response)
            return await response.read()

    async def list_webhooks(self) -> ListWebhooksResponse:
        return await self._request("GET", "/v1/webhooks")

    async def register_webhook(
        self, endpoint_url: str, events: List[str], secret: str
    ) -> RegisterWebhookResponse:
        body = {"endpoint_url": endpoint_url, "events": events, "secret": secret}
        return await self._request("POST", "/v1/webhooks", json_body=body)

    async def delete_webhook(self, webhook_id: str) -> None:
        await self._request("DELETE", f"/v1/webhooks/{webhook_id}")

    async def list_members(self) -> ListMembersResponse:
        return await self._request("GET", "/v1/members")

    async def list_admin_events(self, limit: Optional[int] = None) -> ListAdminEventsResponse:
        return await self._request(
            "GET", "/v1/admin/events", params=admin_events_params(limit)
        )

    async def get_jwks(self) -> JWKSResponse:
        return await self._get_public("/.well-known/elydora/jwks.json")

    async def health(self) -> HealthResponse:
        return await self._get_public("/v1/health")

    async def deep_health(self) -> DeepHealthResponse:
        """503 carries the degraded report, not an error."""
        return await self._get_public("/v1/health/deep", accept_status=503)
