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
    """Generate a UUIDv7 (time-ordered, random) as a string.

    Layout (RFC 9562):
      - 48-bit Unix timestamp in milliseconds
      - 4-bit version (0b0111)
      - 12-bit random
      - 2-bit variant (0b10)
      - 62-bit random
    """
    timestamp_ms = int(time.time() * 1000)

    # 48-bit timestamp
    ts_bytes = struct.pack(">Q", timestamp_ms)[2:]  # last 6 bytes of 8-byte big-endian

    # 2 bytes: version (4 bits = 0x7) + 12 random bits
    rand_a = struct.unpack(">H", os.urandom(2))[0]
    rand_a = (rand_a & 0x0FFF) | 0x7000  # set version nibble

    # 8 bytes: variant (2 bits = 0b10) + 62 random bits
    rand_b = bytearray(os.urandom(8))
    rand_b[0] = (rand_b[0] & 0x3F) | 0x80  # set variant bits

    uuid_bytes = ts_bytes + struct.pack(">H", rand_a) + bytes(rand_b)

    hex_str = uuid_bytes.hex()
    return (
        f"{hex_str[0:8]}-{hex_str[8:12]}-{hex_str[12:16]}-"
        f"{hex_str[16:20]}-{hex_str[20:32]}"
    )
