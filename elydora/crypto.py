"""Cryptographic utilities: Ed25519 signing, SHA-256, chain hash, JCS canonicalization.

Mirrors the backend implementation in ElydoraBackend/src/utils/crypto.ts exactly.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Dict, Optional, Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .utils import base64url_decode, base64url_encode


# ---------------------------------------------------------------------------
# SHA-256
# ---------------------------------------------------------------------------


def sha256_base64url(data: Union[str, bytes]) -> str:
    """Compute SHA-256 of data and return base64url-encoded hash."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    digest = hashlib.sha256(data).digest()
    return base64url_encode(digest)


# ---------------------------------------------------------------------------
# JCS Canonicalization (RFC 8785)
# ---------------------------------------------------------------------------


def _jcs_serialize_number(value: Union[int, float]) -> str:
    """Serialize a number per JCS / ES2015 Number serialization rules."""
    if isinstance(value, bool):
        # bool is a subclass of int in Python; handle before int check
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    # float
    if math.isnan(value) or math.isinf(value):
        return "null"
    if value == 0.0:
        # Handle -0.0 -> "0"
        return "0"
    # Use Python's repr which matches ES2015 for normal floats,
    # but we need to ensure no trailing zeros beyond what's needed.
    # json.dumps handles this correctly per the JSON spec.
    return json.dumps(value)


def jcs_canonicalize(value: Any) -> str:
    """Canonicalize a value according to JCS (RFC 8785).

    - Object keys sorted lexicographically
    - No whitespace
    - Numbers serialized using ES2015 rules
    - Strings serialized with minimal JSON escaping
    - undefined values in objects are omitted
    """
    if value is None:
        return "null"

    if isinstance(value, bool):
        return "true" if value else "false"

    if isinstance(value, (int, float)):
        return _jcs_serialize_number(value)

    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)

    if isinstance(value, list):
        elements = [jcs_canonicalize(v) for v in value]
        return "[" + ",".join(elements) + "]"

    if isinstance(value, dict):
        keys = sorted(value.keys())
        pairs = []
        for key in keys:
            v = value[key]
            if v is not None or key in value:
                # Include keys with None values (maps to JSON null),
                # but skip keys that don't exist (which won't happen with dict iteration)
                pairs.append(json.dumps(key, ensure_ascii=False) + ":" + jcs_canonicalize(v))
        return "{" + ",".join(pairs) + "}"

    return json.dumps(value)


# ---------------------------------------------------------------------------
# Payload hash
# ---------------------------------------------------------------------------


def compute_payload_hash(payload: Any) -> str:
    """Compute SHA-256 hash of JCS-canonicalized payload, base64url encoded."""
    canonical = jcs_canonicalize(payload)
    return sha256_base64url(canonical)


# ---------------------------------------------------------------------------
# Chain hash
# ---------------------------------------------------------------------------


def compute_chain_hash(
    prev_chain_hash: str,
    payload_hash: str,
    operation_id: str,
    issued_at: int,
) -> str:
    """Compute chain hash: SHA-256(prev|payload_hash|op_id|issued_at) as base64url.

    Matches the backend formula exactly:
      chain_hash = SHA-256(prev_chain_hash + "|" + payload_hash + "|" + operation_id + "|" + str(issued_at))
    """
    input_str = f"{prev_chain_hash}|{payload_hash}|{operation_id}|{issued_at}"
    return sha256_base64url(input_str)


# ---------------------------------------------------------------------------
# Ed25519 signing
# ---------------------------------------------------------------------------


def sign_ed25519(private_key_base64url: str, data: bytes) -> str:
    """Sign data with Ed25519 private key (32-byte seed, base64url encoded).

    Returns a base64url-encoded 64-byte signature.
    """
    seed = base64url_decode(private_key_base64url)
    key = Ed25519PrivateKey.from_private_bytes(seed)
    signature = key.sign(data)
    return base64url_encode(signature)


def get_public_key_base64url(private_key_base64url: str) -> str:
    """Derive the Ed25519 public key from the private key seed.

    Returns base64url-encoded 32-byte public key.
    """
    seed = base64url_decode(private_key_base64url)
    key = Ed25519PrivateKey.from_private_bytes(seed)
    pub = key.public_key()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    raw_bytes = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64url_encode(raw_bytes)


# ---------------------------------------------------------------------------
# EOR signing
# ---------------------------------------------------------------------------


def sign_eor(eor_dict: Dict[str, Any], private_key_base64url: str) -> str:
    """Sign an EOR by canonicalizing all fields except 'signature', then signing.

    Returns the base64url-encoded Ed25519 signature.
    """
    # Build the signable object: all EOR fields except 'signature'
    signable = {k: v for k, v in eor_dict.items() if k != "signature"}
    canonical = jcs_canonicalize(signable)
    return sign_ed25519(private_key_base64url, canonical.encode("utf-8"))
