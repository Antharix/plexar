"""Smart async retry with exponential backoff."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Coroutine, Type, TypeVar

logger = logging.getLogger(__name__)
T = TypeVar("T")


async def retry_async(
    fn: Callable[[], Coroutine[Any, Any, T]],
    max_retries: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: tuple[Type[Exception], ...] = (Exception,),
) -> T:
    """
    Retry an async callable with exponential backoff.

    Args:
        fn:          Async callable to retry (no arguments)
        max_retries: Maximum number of retry attempts (0 = no retries)
        delay:       Initial delay between retries in seconds
        backoff:     Multiplier applied to delay after each retry
        exceptions:  Exception types that trigger a retry

    Returns:
        Return value of fn on success

    Raises:
        The last exception if all retries are exhausted
    """
    last_exc: Exception | None = None
    current_delay = delay

    for attempt in range(max_retries + 1):
        try:
            return await fn()
        except exceptions as exc:
            last_exc = exc
            if attempt < max_retries:
                logger.debug(
                    f"Attempt {attempt + 1}/{max_retries + 1} failed: {exc}. "
                    f"Retrying in {current_delay:.1f}s..."
                )
                await asyncio.sleep(current_delay)
                current_delay *= backoff
            else:
                logger.debug(f"All {max_retries + 1} attempts failed. Last error: {exc}")

    raise last_exc  # type: ignore[misc]
