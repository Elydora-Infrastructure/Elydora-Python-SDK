"""Request and response building shared by the sync and async clients."""

from __future__ import annotations

import time
from typing import Any, Dict, Optional, Tuple, Union

from .crypto import compute_chain_hash, compute_payload_hash, sign_eor
from .errors import ElydoraError
from .types import EOR
from .utils import generate_nonce, generate_uuidv7

# 32 zero bytes; equals the Backend GENESIS_CHAIN_HASH.
GENESIS_CHAIN_HASH = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
DEFAULT_BASE_URL = "https://api.elydora.com"
REQUEST_TIMEOUT_SECONDS = 30


def build_headers(token: Optional[str]) -> Dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def error_from_response(status_code: int, body: Any, text: str) -> ElydoraError:
    error = body.get("error", {}) if isinstance(body, dict) else {}
    return ElydoraError(
        code=error.get("code", "INTERNAL_ERROR"),
        message=error.get("message") or text or "Unknown error",
        request_id=error.get("request_id", ""),
        details=error.get("details"),
        status_code=status_code,
    )


def without_none(values: Dict[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in values.items() if value is not None}


def register_body(
    email: str,
    password: str,
    display_name: Optional[str],
    org_name: Optional[str],
) -> Dict[str, Any]:
    return without_none({
        "email": email,
        "password": password,
        "display_name": display_name,
        "org_name": org_name,
    })


def api_token_body(ttl_seconds: Optional[int]) -> Dict[str, Any]:
    return without_none({"ttl_seconds": ttl_seconds})


def export_body(
    start_time: int,
    end_time: int,
    format: str,
    agent_id: Optional[str],
    operation_type: Optional[str],
) -> Dict[str, Any]:
    return without_none({
        "start_time": start_time,
        "end_time": end_time,
        "format": format,
        "agent_id": agent_id,
        "operation_type": operation_type,
    })


def admin_events_params(limit: Optional[int]) -> Dict[str, str]:
    return {} if limit is None else {"limit": str(limit)}


def build_eor(
    *,
    org_id: str,
    agent_id: str,
    private_key: str,
    kid: str,
    ttl_ms: int,
    prev_chain_hash: str,
    operation_type: str,
    subject: Dict[str, Any],
    action: Dict[str, Any],
    payload: Union[Dict[str, Any], str, None],
) -> Tuple[EOR, str]:
    """Build and sign one EOR; returns the record and its chain hash."""
    operation_id = generate_uuidv7()
    issued_at = int(time.time() * 1000)
    payload_hash = compute_payload_hash(payload)
    chain_hash = compute_chain_hash(prev_chain_hash, payload_hash, operation_id, issued_at)
    eor: Dict[str, Any] = {
        "op_version": "1.0",
        "operation_id": operation_id,
        "org_id": org_id,
        "agent_id": agent_id,
        "issued_at": issued_at,
        "ttl_ms": ttl_ms,
        "nonce": generate_nonce(),
        "operation_type": operation_type,
        "subject": subject,
        "action": action,
        "payload": payload,
        "payload_hash": payload_hash,
        "prev_chain_hash": prev_chain_hash,
        "agent_pubkey_kid": kid,
        "signature": "",
    }
    eor["signature"] = sign_eor(eor, private_key)
    return eor, chain_hash  # type: ignore[return-value]
