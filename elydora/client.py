"""Synchronous Elydora client using the requests library."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Union

import requests

from .crypto import compute_chain_hash, compute_payload_hash, sign_eor
from .errors import ElydoraError
from .types import (
    AuditQueryResponse,
    AuthLoginResponse,
    AuthRegisterResponse,
    CreateExportResponse,
    EOR,
    GetAgentResponse,
    GetEpochResponse,
    GetExportResponse,
    GetOperationResponse,
    JWKSResponse,
    ListEpochsResponse,
    ListExportsResponse,
    RegisterAgentRequest,
    RegisterAgentResponse,
    SubmitOperationResponse,
    VerifyOperationResponse,
)
from .utils import generate_nonce, generate_uuidv7


class ElydoraClient:
    """Synchronous client for the Elydora API.

    Args:
        org_id: Organization identifier.
        agent_id: Agent identifier.
        private_key: Base64url-encoded 32-byte Ed25519 private key seed.
        base_url: API base URL.
        ttl_ms: Time-to-live for operations in milliseconds.
        max_retries: Maximum number of retries on transient failures.
        token: Optional JWT bearer token for authenticated endpoints.
    """

    def __init__(
        self,
        org_id: str,
        agent_id: str,
        private_key: str,
        *,
        base_url: str = "https://api.elydora.com",
        ttl_ms: int = 30000,
        max_retries: int = 3,
        token: Optional[str] = None,
    ) -> None:
        self.org_id = org_id
        self.agent_id = agent_id
        self.private_key = private_key
        self.base_url = base_url.rstrip("/")
        self.ttl_ms = ttl_ms
        self.max_retries = max_retries
        self.token = token

        self._prev_chain_hash = ""
        self._kid = ""
        self._session = requests.Session()

    def set_kid(self, kid: str) -> None:
        """Set the key ID used for signing operations."""
        self._kid = kid

    def set_prev_chain_hash(self, prev_chain_hash: str) -> None:
        """Set the previous chain hash for the next operation."""
        self._prev_chain_hash = prev_chain_hash

    # -----------------------------------------------------------------
    # Internal HTTP helpers
    # -----------------------------------------------------------------

    def _headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        url = f"{self.base_url}{path}"
        hdrs = headers or self._headers()

        last_exc: Optional[Exception] = None
        for attempt in range(self.max_retries):
            try:
                resp = self._session.request(
                    method, url, json=json_body, params=params, headers=hdrs, timeout=30
                )
                return self._handle_response(resp)
            except ElydoraError:
                raise
            except requests.exceptions.ConnectionError as exc:
                last_exc = exc
                if attempt < self.max_retries - 1:
                    time.sleep(min(2 ** attempt, 8))
                    continue
                raise
            except requests.exceptions.Timeout as exc:
                last_exc = exc
                if attempt < self.max_retries - 1:
                    time.sleep(min(2 ** attempt, 8))
                    continue
                raise

        raise last_exc  # type: ignore[misc]

    @staticmethod
    def _handle_response(resp: requests.Response) -> Any:
        if resp.status_code >= 400:
            try:
                body = resp.json()
            except Exception:
                raise ElydoraError(
                    code="INTERNAL_ERROR",
                    message=resp.text or "Unknown error",
                    status_code=resp.status_code,
                )
            err = body.get("error", {})
            raise ElydoraError(
                code=err.get("code", "INTERNAL_ERROR"),
                message=err.get("message", resp.text),
                request_id=err.get("request_id", ""),
                details=err.get("details"),
                status_code=resp.status_code,
            )
        if resp.status_code == 204:
            return None
        return resp.json()

    # -----------------------------------------------------------------
    # Auth (static methods)
    # -----------------------------------------------------------------

    @staticmethod
    def register(
        base_url: str,
        email: str,
        password: str,
        display_name: Optional[str] = None,
        org_name: Optional[str] = None,
    ) -> AuthRegisterResponse:
        """Register a new user and organization."""
        url = f"{base_url.rstrip('/')}/v1/auth/register"
        body: Dict[str, Any] = {"email": email, "password": password}
        if display_name is not None:
            body["display_name"] = display_name
        if org_name is not None:
            body["org_name"] = org_name
        resp = requests.post(url, json=body, headers={"Content-Type": "application/json"}, timeout=30)
        return ElydoraClient._handle_response(resp)

    @staticmethod
    def login(base_url: str, email: str, password: str) -> AuthLoginResponse:
        """Authenticate and receive a JWT."""
        url = f"{base_url.rstrip('/')}/v1/auth/login"
        body = {"email": email, "password": password}
        resp = requests.post(url, json=body, headers={"Content-Type": "application/json"}, timeout=30)
        return ElydoraClient._handle_response(resp)

    # -----------------------------------------------------------------
    # Agent management
    # -----------------------------------------------------------------

    def register_agent(self, request: RegisterAgentRequest) -> RegisterAgentResponse:
        """Register a new agent with the organization."""
        return self._request("POST", "/v1/agents/register", json_body=request)

    def get_agent(self, agent_id: str) -> GetAgentResponse:
        """Retrieve agent details and keys."""
        return self._request("GET", f"/v1/agents/{agent_id}")

    def freeze_agent(self, agent_id: str, reason: str) -> None:
        """Freeze an agent."""
        self._request("POST", f"/v1/agents/{agent_id}/freeze", json_body={"reason": reason})

    def revoke_key(self, agent_id: str, kid: str, reason: str) -> None:
        """Revoke an agent's key."""
        self._request(
            "POST",
            f"/v1/agents/{agent_id}/revoke",
            json_body={"kid": kid, "reason": reason},
        )

    # -----------------------------------------------------------------
    # Operations (CORE)
    # -----------------------------------------------------------------

    def create_operation(
        self,
        operation_type: str,
        subject: Dict[str, Any],
        action: Dict[str, Any],
        payload: Union[Dict[str, Any], str, None] = None,
    ) -> EOR:
        """Build and sign an Elydora Operation Record (EOR).

        This does NOT submit the operation to the server. Call submit_operation()
        with the returned EOR to submit it.
        """
        operation_id = generate_uuidv7()
        issued_at = int(time.time() * 1000)
        nonce = generate_nonce()
        payload_hash = compute_payload_hash(payload)
        chain_hash = compute_chain_hash(
            self._prev_chain_hash, payload_hash, operation_id, issued_at
        )

        eor: Dict[str, Any] = {
            "op_version": "1.0",
            "operation_id": operation_id,
            "org_id": self.org_id,
            "agent_id": self.agent_id,
            "issued_at": issued_at,
            "ttl_ms": self.ttl_ms,
            "nonce": nonce,
            "operation_type": operation_type,
            "subject": subject,
            "action": action,
            "payload": payload,
            "payload_hash": payload_hash,
            "prev_chain_hash": self._prev_chain_hash,
            "agent_pubkey_kid": self._kid,
            "signature": "",
        }

        # Sign the EOR (signature field excluded from canonical form)
        eor["signature"] = sign_eor(eor, self.private_key)

        # Update chain state
        self._prev_chain_hash = chain_hash

        return eor  # type: ignore[return-value]

    def submit_operation(self, eor: EOR) -> SubmitOperationResponse:
        """Submit a signed EOR to the server."""
        return self._request("POST", "/v1/operations", json_body=eor)

    def get_operation(self, operation_id: str) -> GetOperationResponse:
        """Retrieve an operation by ID."""
        return self._request("GET", f"/v1/operations/{operation_id}")

    def verify_operation(self, operation_id: str) -> VerifyOperationResponse:
        """Verify an operation's integrity."""
        return self._request("POST", f"/v1/operations/{operation_id}/verify")

    # -----------------------------------------------------------------
    # Audit
    # -----------------------------------------------------------------

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
        """Query the tamper-evident audit log."""
        body: Dict[str, Any] = {}
        if org_id is not None:
            body["org_id"] = org_id
        if agent_id is not None:
            body["agent_id"] = agent_id
        if operation_type is not None:
            body["operation_type"] = operation_type
        if start_time is not None:
            body["start_time"] = start_time
        if end_time is not None:
            body["end_time"] = end_time
        if cursor is not None:
            body["cursor"] = cursor
        if limit is not None:
            body["limit"] = limit
        return self._request("POST", "/v1/audit/query", json_body=body)

    # -----------------------------------------------------------------
    # Epochs
    # -----------------------------------------------------------------

    def list_epochs(self) -> ListEpochsResponse:
        """List all epochs for the organization."""
        return self._request("GET", "/v1/epochs")

    def get_epoch(self, epoch_id: str) -> GetEpochResponse:
        """Retrieve an epoch root record."""
        return self._request("GET", f"/v1/epochs/{epoch_id}")

    # -----------------------------------------------------------------
    # Exports
    # -----------------------------------------------------------------

    def create_export(
        self,
        start_time: int,
        end_time: int,
        format: str = "json",
        agent_id: Optional[str] = None,
        operation_type: Optional[str] = None,
    ) -> CreateExportResponse:
        """Create a compliance export job."""
        body: Dict[str, Any] = {
            "start_time": start_time,
            "end_time": end_time,
            "format": format,
        }
        if agent_id is not None:
            body["agent_id"] = agent_id
        if operation_type is not None:
            body["operation_type"] = operation_type
        return self._request("POST", "/v1/exports", json_body=body)

    def list_exports(self) -> ListExportsResponse:
        """List all exports for the organization."""
        return self._request("GET", "/v1/exports")

    def get_export(self, export_id: str) -> GetExportResponse:
        """Retrieve export status and download URL."""
        return self._request("GET", f"/v1/exports/{export_id}")

    # -----------------------------------------------------------------
    # JWKS
    # -----------------------------------------------------------------

    def get_jwks(self) -> JWKSResponse:
        """Retrieve the platform JWKS (public, no auth required)."""
        url = f"{self.base_url}/.well-known/elydora/jwks.json"
        resp = self._session.get(url, timeout=30)
        return self._handle_response(resp)
