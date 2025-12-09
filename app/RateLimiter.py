"""
Rate limiting to prevent overwhelming external APIs.

Implements token bucket algorithm:
- Allows bursts up to a limit
- Refills tokens over time
- Prevents sustained high-rate requests

PREVENTS: NVD API bans, GitHub API throttling, DuckDuckGo blocks
"""

import logging
import threading
import time
from typing import Dict

from Database.DatabaseConfig import RATE_LIMITS

logger = logging.getLogger(__name__)


# ==================== TOKEN BUCKET RATE LIMITER ====================

class RateLimiter:
    """
    Token bucket rate limiter for API calls.

    How it works:
    - Each API has a bucket of tokens (default: requests_per_minute)
    - Each request costs 1 token
    - Tokens refill at:  rate_per_minute / 60 tokens per second
    - If no tokens, request waits or is rejected
    """

    def __init__(self, requests_per_minute: int):
        """
        Initialize rate limiter.

        Args:
            requests_per_minute (int): Max requests per 60 seconds
        """
        self.requests_per_minute = requests_per_minute
        self.tokens = float(requests_per_minute)
        self.max_tokens = float(requests_per_minute)
        self.last_refill = time.time()
        self.lock = threading.Lock()

    def wait_if_needed(self) -> float:
        """
        Wait until a token is available.

        Returns:
            float: How long we waited (seconds)
        """
        with self.lock:
            waited = self._wait_for_token()
            self.tokens -= 1

            elapsed = time.time() - self.last_refill
            if elapsed >= 60:
                # Refill tokens after 1 minute
                self.tokens = self.max_tokens
                self.last_refill = time.time()

            return waited

    def _wait_for_token(self) -> float:
        """Internal method to wait for token availability"""
        start_time = time.time()

        # Refill tokens based on time elapsed
        elapsed = time.time() - self.last_refill
        refill_rate = self.max_tokens / 60  # Tokens per second
        self.tokens = min(self.max_tokens, self.tokens + (elapsed * refill_rate))
        self.last_refill = time.time()

        # If no tokens, calculate wait time
        if self.tokens < 1:
            wait_time = (1 - self.tokens) / refill_rate
            logger.info(
                f"⏳ Rate limit reached.  Waiting {wait_time:.1f}s before next request..."
            )
            time.sleep(wait_time)
            self.tokens = 0

        waited = time.time() - start_time
        return waited

    def get_stats(self) -> dict:
        """Get current rate limiter status"""
        with self.lock:
            return {
                "tokens_available": self.tokens,
                "max_tokens": self.max_tokens,
                "requests_per_minute": self.requests_per_minute,
            }


# ==================== GLOBAL RATE LIMITERS ====================

_rate_limiters: Dict[str, RateLimiter] = {}
_limiter_lock = threading.Lock()


def get_rate_limiter(api_name: str) -> RateLimiter:
    """
    Get or create a rate limiter for an API.

    Args:
        api_name (str): Name of API (must be in RATE_LIMITS config)

    Returns:
        RateLimiter: Rate limiter for that API
    """
    global _rate_limiters

    if api_name not in RATE_LIMITS:
        raise ValueError(f"Unknown API: {api_name}. Available: {list(RATE_LIMITS.keys())}")

    if api_name not in _rate_limiters:
        with _limiter_lock:
            if api_name not in _rate_limiters:
                rate_limit = RATE_LIMITS[api_name]
                _rate_limiters[api_name] = RateLimiter(
                    requests_per_minute=rate_limit["requests_per_minute"]
                )
                logger.info(
                    f"✓ Rate limiter created for {api_name}:  "
                    f"{rate_limit['requests_per_minute']} req/min"
                )

    return _rate_limiters[api_name]


def rate_limit(api_name: str):
    """
    Decorator to rate-limit a function call.

    Usage:
        @rate_limit("nvd_api")
        def fetch_cves():
            # This function will wait if rate limit exceeded
            ...
    """

    def decorator(func):
        def wrapper(*args, **kwargs):
            limiter = get_rate_limiter(api_name)
            waited = limiter.wait_if_needed()

            if waited > 0:
                logger.debug(f"Rate limiter wait: {waited:.2f}s for {api_name}")

            return func(*args, **kwargs)

        return wrapper

    return decorator


def get_all_rate_limiter_stats() -> dict:
    """Get stats for all rate limiters"""
    return {
        name: limiter.get_stats()
        for name, limiter in _rate_limiters.items()
    }