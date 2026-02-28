"""Elydora SDK error types."""

from __future__ import annotations

from typing import Any, Dict, Optional


class ElydoraError(Exception):
    """Error returned by the Elydora API."""

    def __init__(
        self,
        code: str,
        message: str,
        request_id: str = "",
        details: Optional[Dict[str, Any]] = None,
        status_code: int = 0,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.request_id = request_id
        self.details = details or {}
        self.status_code = status_code

    def __repr__(self) -> str:
        return (
            f"ElydoraError(code={self.code!r}, message={self.message!r}, "
            f"request_id={self.request_id!r})"
        )
