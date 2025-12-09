"""
Exponential backoff retry logic with jitter.

Prevents cascading failures by:
1. Waiting longer after each failure
2. Adding randomness to prevent thundering herd
3. Logging all attempts and errors

PREVENTS:  Cascading failures, overwhelming failed services
"""

import logging
import time
import random
from typing import Callable, TypeVar, Any, Optional
from Database.DatabaseConfig import RETRY_CONFIG

logger = logging.getLogger(__name__)

T = TypeVar('T')


# ==================== RETRY DECORATORS ====================

def retry_with_backoff(
        max_retries: Optional[int] = None,
        initial_backoff: Optional[int] = None,
        max_backoff: Optional[int] = None,
        backoff_multiplier: Optional[float] = None,
        jitter: Optional[bool] = None,
        exceptions: tuple = (Exception,)
):
    """
    Decorator for automatic retry with exponential backoff.

    Retries on specified exceptions with increasing delays:
    - Attempt 1: Fails immediately
    - Attempt 2: Wait 5 seconds, then retry
    - Attempt 3: Wait 10 seconds, then retry
    - Attempt 4: Wait 20 seconds, then retry
    - etc.

    Usage:
        @retry_with_backoff(max_retries=3)
        def fetch_data():
            return api. get()
    """

    # Use config defaults if not provided
    max_retries = max_retries or RETRY_CONFIG['max_retries']
    initial_backoff = initial_backoff or RETRY_CONFIG['initial_backoff_seconds']
    max_backoff = max_backoff or RETRY_CONFIG['max_backoff_seconds']
    backoff_multiplier = backoff_multiplier or RETRY_CONFIG['backoff_multiplier']
    jitter = jitter if jitter is not None else RETRY_CONFIG['jitter']

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        def wrapper(*args, **kwargs) -> T:
            last_exception = None

            for attempt in range(1, max_retries + 1):
                try:
                    if attempt > 1:
                        logger.debug(f"Retry attempt {attempt}/{max_retries} for {func.__name__}")

                    result = func(*args, **kwargs)

                    if attempt > 1:
                        logger.info(f"✓ {func.__name__} succeeded on attempt {attempt}")

                    return result

                except exceptions as e:
                    last_exception = e

                    if attempt < max_retries:
                        # Calculate backoff with exponential growth
                        backoff = min(
                            initial_backoff * (backoff_multiplier ** (attempt - 1)),
                            max_backoff
                        )

                        # Add jitter (randomness) to prevent thundering herd
                        if jitter:
                            backoff = backoff * (0.5 + random.random())  # 50-150% of backoff

                        logger.warning(
                            f"⚠️  {func.__name__} failed (attempt {attempt}/{max_retries}): {e}\n"
                            f"    Waiting {backoff:.1f}s before retry..."
                        )

                        time.sleep(backoff)
                    else:
                        logger.error(
                            f"✗ {func.__name__} failed after {max_retries} attempts:\n"
                            f"    {type(e).__name__}: {e}"
                        )

            # All retries exhausted
            raise last_exception

        return wrapper

    return decorator


def retry_on_network_errors(func: Callable[..., T]) -> Callable[..., T]:
    """
    Retry specifically on network errors (connection, timeout).

    Usage:
        @retry_on_network_errors
        def fetch_from_api():
            ...
    """
    import httpx

    return retry_with_backoff(
        max_retries=3,
        initial_backoff=2,
        exceptions=(httpx.HTTPError, TimeoutError, ConnectionError)
    )(func)


# ==================== MANUAL RETRY LOGIC ====================

class RetryableOperation:
    """
    Manual retry handler for complex scenarios.

    Useful when decorator isn't sufficient.
    """

    def __init__(self, max_retries: int = RETRY_CONFIG['max_retries']):
        self.max_retries = max_retries
        self.attempts = 0
        self.last_error = None

    def execute(self, operation: Callable[..., T], *args, **kwargs) -> T:
        """
        Execute operation with retry logic.

        Returns:
            Result of operation
        """
        for attempt in range(1, self.max_retries + 1):
            self.attempts = attempt

            try:
                return operation(*args, **kwargs)

            except Exception as e:
                self.last_error = e

                if attempt < self.max_retries:
                    backoff = min(
                        RETRY_CONFIG['initial_backoff_seconds'] *
                        (RETRY_CONFIG['backoff_multiplier'] ** (attempt - 1)),
                        RETRY_CONFIG['max_backoff_seconds']
                    )

                    if RETRY_CONFIG['jitter']:
                        backoff = backoff * (0.5 + random.random())

                    logger.warning(
                        f"Attempt {attempt} failed: {e}. "
                        f"Waiting {backoff:.1f}s..."
                    )
                    time.sleep(backoff)

        logger.error(f"Operation failed after {self.max_retries} attempts: {self.last_error}")
        raise self.last_error