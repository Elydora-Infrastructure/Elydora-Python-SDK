"""Synchronous HTTP execution with the Elydora retry contract."""

import logging
import time
from typing import Any, Callable, Dict, Optional

import requests

from ._retry import can_retry, log_retry, retry_delay_seconds, should_retry_response

logger = logging.getLogger(__name__)


def request_with_retries(
    session: requests.Session,
    method: str,
    url: str,
    *,
    path: str,
    max_retries: int,
    response_handler: Callable[[requests.Response], Any],
    json_body: Any = None,
    params: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Any:
    retry_count = 0
    while True:
        try:
            response = session.request(
                method,
                url,
                json=json_body,
                params=params,
                headers=headers,
                timeout=30,
            )
            if should_retry_response(
                method, response.status_code, retry_count, max_retries
            ):
                delay = retry_delay_seconds(
                    retry_count, response.headers.get("Retry-After")
                )
                response.close()
                log_retry(
                    logger,
                    method,
                    path,
                    retry_count,
                    max_retries,
                    delay,
                    f"http_{response.status_code}",
                )
                time.sleep(delay)
                retry_count += 1
                continue
            return response_handler(response)
        except requests.exceptions.ConnectTimeout as error:
            if can_retry(
                method,
                retry_count,
                max_retries,
                request_known_unprocessed=True,
            ):
                delay = retry_delay_seconds(retry_count)
                log_retry(
                    logger,
                    method,
                    path,
                    retry_count,
                    max_retries,
                    delay,
                    type(error).__name__,
                )
                time.sleep(delay)
                retry_count += 1
                continue
            raise
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
        ) as error:
            if can_retry(method, retry_count, max_retries):
                delay = retry_delay_seconds(retry_count)
                log_retry(
                    logger,
                    method,
                    path,
                    retry_count,
                    max_retries,
                    delay,
                    type(error).__name__,
                )
                time.sleep(delay)
                retry_count += 1
                continue
            raise
