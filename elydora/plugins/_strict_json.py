"""Strict JSON parsing with duplicate-key rejection."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple


JsonObject = Dict[str, Any]


class _DuplicateKey(ValueError):
    pass


def _unique_object(pairs: List[Tuple[str, Any]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(f'duplicate field "{key}"')
        result[key] = value
    return result


def parse_json_object(raw: str, label: str) -> JsonObject:
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (_DuplicateKey, json.JSONDecodeError) as error:
        raise ValueError(f"Failed to parse {label}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return value
