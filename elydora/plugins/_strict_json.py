"""Strict JSON parsing with duplicate-key rejection."""

from __future__ import annotations

import json
from typing import Any, Dict, List, NoReturn, Tuple


JsonObject = Dict[str, Any]


class _DuplicateKey(ValueError):
    pass


class _InvalidConstant(ValueError):
    pass


def _unique_object(pairs: List[Tuple[str, Any]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(f'duplicate field "{key}"')
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    raise _InvalidConstant(f'invalid numeric constant "{value}"')


def parse_json_object(raw: str, label: str) -> JsonObject:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (_DuplicateKey, _InvalidConstant, json.JSONDecodeError) as error:
        raise ValueError(f"Failed to parse {label}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return value
