"""
Rate Limiter
Token bucket rate limiting for scanner-side request throttling.
"""

import asyncio
import threading
import time
from dataclasses import dataclass


@dataclass
class RateLimitConfig:
    """Rate limiting configuration"""
    requests_per_second: float = 10.0
    burst_size: int = 20
    enabled: bool = True


class RateLimiter:
    """
    Token bucket rate limiter for controlling request rate.

    Features:
    - Token bucket algorithm
    - Configurable rate and burst
    - Async and sync support
    - Per-domain limiting
    """

    def __init__(
        self,
        requests_per_second: float = 10.0,
        burst_size: int = 20,
        enabled: bool = True,
    ):
        self.rate = requests_per_second
        self.burst = burst_size
        self.enabled = enabled

        # Token bucket state
        self._tokens = float(burst_size)
        self._last_update = time.monotonic()
        self._lock = threading.Lock()
        self._async_lock: asyncio.Lock | None = None

        # Per-domain limiters
        self._domain_limiters: dict = {}

    def _refill(self):
        """Refill tokens based on elapsed time"""
        now = time.monotonic()
        elapsed = now - self._last_update
        self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
        self._last_update = now

    def acquire(self, tokens: int = 1) -> bool:
        """
        Acquire tokens (blocking if necessary).

        Args:
            tokens: Number of tokens to acquire

        Returns:
            True when tokens acquired
        """
        if not self.enabled:
            return True

        with self._lock:
            self._refill()

            if self._tokens >= tokens:
                self._tokens -= tokens
                return True

            # Calculate wait time
            wait_time = (tokens - self._tokens) / self.rate
            time.sleep(wait_time)

            self._refill()
            self._tokens -= tokens
            return True

    async def acquire_async(self, tokens: int = 1) -> bool:
        """
        Acquire tokens asynchronously.

        Args:
            tokens: Number of tokens to acquire

        Returns:
            True when tokens acquired
        """
        if not self.enabled:
            return True

        if self._async_lock is None:
            self._async_lock = asyncio.Lock()

        async with self._async_lock:
            self._refill()

            if self._tokens >= tokens:
                self._tokens -= tokens
                return True

            # Calculate wait time
            wait_time = (tokens - self._tokens) / self.rate
            await asyncio.sleep(wait_time)

            self._refill()
            self._tokens -= tokens
            return True

    def try_acquire(self, tokens: int = 1) -> bool:
        """
        Try to acquire tokens without blocking.

        Args:
            tokens: Number of tokens to acquire

        Returns:
            True if tokens acquired, False otherwise
        """
        if not self.enabled:
            return True

        with self._lock:
            self._refill()

            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    def get_domain_limiter(self, domain: str) -> "RateLimiter":
        """
        Get or create a rate limiter for a specific domain.

        Args:
            domain: Domain name

        Returns:
            RateLimiter for the domain
        """
        if domain not in self._domain_limiters:
            self._domain_limiters[domain] = RateLimiter(
                requests_per_second=self.rate,
                burst_size=self.burst,
                enabled=self.enabled,
            )
        return self._domain_limiters[domain]

    @property
    def available_tokens(self) -> float:
        """Get current available tokens"""
        with self._lock:
            self._refill()
            return self._tokens

    def reset(self):
        """Reset the rate limiter"""
        with self._lock:
            self._tokens = float(self.burst)
            self._last_update = time.monotonic()

    def update_config(
        self,
        requests_per_second: float = None,
        burst_size: int = None,
        enabled: bool = None,
    ):
        """Update rate limiter configuration"""
        with self._lock:
            if requests_per_second is not None:
                self.rate = requests_per_second
            if burst_size is not None:
                self.burst = burst_size
                self._tokens = min(self._tokens, float(burst_size))
            if enabled is not None:
                self.enabled = enabled


# Singleton
_limiter: RateLimiter | None = None


def get_rate_limiter(**kwargs) -> RateLimiter:
    """Get singleton rate limiter"""
    global _limiter
    if _limiter is None:
        _limiter = RateLimiter(**kwargs)
    return _limiter
