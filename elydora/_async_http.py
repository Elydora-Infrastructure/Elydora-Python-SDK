"""Asynchronous HTTP execution with the Elydora retry contract."""

import asyncio
import logging
from typing import Any, Awaitable, Callable, Dict, Optional

import aiohttp

from ._retry import can_retry, log_retry, retry_delay_seconds, should_retry_response

logger = logging.getLogger(__name__)


async def request_with_retries(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    *,
    path: str,
    max_retries: int,
    response_handler: Callable[[aiohttp.ClientResponse], Awaitable[Any]],
    json_body: Any = None,
    params: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Any:
    retry_count = 0
    while True:
        try:
            delay: Optional[float] = None
            reason = ""
            async with session.request(
                method,
                url,
                json=json_body,
                params=params,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as response:
                if should_retry_response(
                    method, response.status, retry_count, max_retries
                ):
                    delay = retry_delay_seconds(
                        retry_count, response.headers.get("Retry-After")
                    )
                    reason = f"http_{response.status}"
                else:
                    return await response_handler(response)
            if delay is not None:
                log_retry(logger, method, path, retry_count, max_retries, delay, reason)
                await asyncio.sleep(delay)
                retry_count += 1
                continue
        except aiohttp.ClientConnectorError as error:
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
                await asyncio.sleep(delay)
                retry_count += 1
                continue
            raise
        except (aiohttp.ClientConnectionError, asyncio.TimeoutError) as error:
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
                await asyncio.sleep(delay)
                retry_count += 1
                continue
            raise
