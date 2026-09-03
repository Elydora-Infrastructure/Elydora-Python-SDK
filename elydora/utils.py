"""Utility helpers: UUIDv7, nonce generation, base64url encoding."""

from __future__ import annotations

import base64
import os
import struct
import time


def base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url string with no padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def base64url_decode(s: str) -> bytes:
    """Decode a base64url string (with or without padding) to bytes."""
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)


def generate_nonce() -> str:
    """Generate a 16-byte random nonce, base64url encoded."""
    return base64url_encode(os.urandom(16))


def generate_uuidv7() -> str:
    """UUIDv7 (RFC 9562): 48-bit ms timestamp, version 7, variant 10, 74 random bits."""
    timestamp_ms = int(time.time() * 1000)
    ts_bytes = struct.pack(">Q", timestamp_ms)[2:]
    rand_a = (struct.unpack(">H", os.urandom(2))[0] & 0x0FFF) | 0x7000
    rand_b = bytearray(os.urandom(8))
    rand_b[0] = (rand_b[0] & 0x3F) | 0x80

    uuid_bytes = ts_bytes + struct.pack(">H", rand_a) + bytes(rand_b)

    hex_str = uuid_bytes.hex()
    return (
        f"{hex_str[0:8]}-{hex_str[8:12]}-{hex_str[12:16]}-"
        f"{hex_str[16:20]}-{hex_str[20:32]}"
    )
