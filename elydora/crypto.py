"""Ed25519 signing, SHA-256, chain hash, and RFC 8785 canonicalization; mirrors the Backend."""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Dict, Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .utils import base64url_decode, base64url_encode


def sha256_base64url(data: Union[str, bytes]) -> str:
    """Compute SHA-256 of data and return base64url-encoded hash."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    digest = hashlib.sha256(data).digest()
    return base64url_encode(digest)


def _jcs_serialize_number(value: Union[int, float]) -> str:
    """ES2015 number serialization: NaN and infinities become null, -0.0 becomes 0."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if math.isnan(value) or math.isinf(value):
        return "null"
    if value == 0.0:
        return "0"
    return json.dumps(value)


def jcs_canonicalize(value: Any) -> str:
    """Canonicalize a value according to JCS (RFC 8785)."""
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
        pairs = [
            json.dumps(key, ensure_ascii=False) + ":" + jcs_canonicalize(value[key])
            for key in sorted(value.keys())
        ]
        return "{" + ",".join(pairs) + "}"

    return json.dumps(value)


def compute_payload_hash(payload: Any) -> str:
    """Compute SHA-256 hash of JCS-canonicalized payload, base64url encoded."""
    canonical = jcs_canonicalize(payload)
    return sha256_base64url(canonical)


def compute_chain_hash(
    prev_chain_hash: str,
    payload_hash: str,
    operation_id: str,
    issued_at: int,
) -> str:
    """SHA-256 of "prev|payload_hash|operation_id|issued_at" as base64url."""
    input_str = f"{prev_chain_hash}|{payload_hash}|{operation_id}|{issued_at}"
    return sha256_base64url(input_str)


def sign_ed25519(private_key_base64url: str, data: bytes) -> str:
    """Sign data with a base64url 32-byte Ed25519 seed; returns a base64url signature."""
    seed = base64url_decode(private_key_base64url)
    key = Ed25519PrivateKey.from_private_bytes(seed)
    signature = key.sign(data)
    return base64url_encode(signature)


def get_public_key_base64url(private_key_base64url: str) -> str:
    """Derive the base64url Ed25519 public key from a base64url seed."""
    seed = base64url_decode(private_key_base64url)
    public_key = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    return base64url_encode(public_key.public_bytes(Encoding.Raw, PublicFormat.Raw))


def sign_eor(eor_dict: Dict[str, Any], private_key_base64url: str) -> str:
    """Sign the JCS form of every EOR field except signature."""
    signable = {k: v for k, v in eor_dict.items() if k != "signature"}
    canonical = jcs_canonicalize(signable)
    return sign_ed25519(private_key_base64url, canonical.encode("utf-8"))
