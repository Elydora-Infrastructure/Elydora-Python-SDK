"""Runtime validation for agent integration types."""

from typing import cast

from .types import INTEGRATION_TYPES, IntegrationType


def require_integration_type(value: object) -> IntegrationType:
    if not isinstance(value, str) or value not in INTEGRATION_TYPES:
        expected = ", ".join(INTEGRATION_TYPES)
        raise ValueError(f"Invalid integration_type {value!r}. Expected one of: {expected}")
    return cast(IntegrationType, value)
