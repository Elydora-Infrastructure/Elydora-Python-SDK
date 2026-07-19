"""Shared retry policy for the synchronous and asynchronous clients."""

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from logging import Logger
from typing import Optional

IDEMPOTENT_METHODS = frozenset({"DELETE", "GET", "HEAD", "OPTIONS", "PUT"})
RETRYABLE_STATUS_CODES = frozenset({408, 429, 500, 502, 503, 504})
MAX_BACKOFF_SECONDS = 8


def require_max_retries(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("max_retries must be a non-negative integer")
    return value


def can_retry(
    method: str,
    retry_count: int,
    max_retries: int,
    *,
    request_known_unprocessed: bool = False,
) -> bool:
    if retry_count >= max_retries:
        return False
    return request_known_unprocessed or method.upper() in IDEMPOTENT_METHODS


def should_retry_response(
    method: str,
    status_code: int,
    retry_count: int,
    max_retries: int,
) -> bool:
    return status_code in RETRYABLE_STATUS_CODES and can_retry(
        method, retry_count, max_retries
    )


def retry_delay_seconds(
    retry_count: int,
    retry_after: Optional[str] = None,
    *,
    now: Optional[datetime] = None,
) -> float:
    parsed_delay = _parse_retry_after(retry_after, now=now)
    if parsed_delay is not None:
        return parsed_delay
    return float(min(2**retry_count, MAX_BACKOFF_SECONDS))


def log_retry(
    logger: Logger,
    method: str,
    path: str,
    retry_count: int,
    max_retries: int,
    delay: float,
    reason: str,
) -> None:
    logger.warning(
        "Retrying Elydora request method=%s path=%s retry=%d/%d "
        "delay_seconds=%s reason=%s",
        method.upper(),
        path,
        retry_count + 1,
        max_retries,
        delay,
        reason,
    )


def _parse_retry_after(
    value: Optional[str],
    *,
    now: Optional[datetime],
) -> Optional[float]:
    if value is None:
        return None

    normalized = value.strip()
    if normalized.isascii() and normalized.isdecimal():
        return float(int(normalized))

    try:
        retry_at = parsedate_to_datetime(normalized)
    except (TypeError, ValueError, OverflowError):
        return None
    if retry_at.tzinfo is None:
        retry_at = retry_at.replace(tzinfo=timezone.utc)

    current_time = now or datetime.now(timezone.utc)
    return max(0.0, (retry_at - current_time).total_seconds())
