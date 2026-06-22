"""
API dependencies: API-key auth and in-process rate limiting.

Both are deliberately simple so the system can run with no external stores.
For a large production deployment, swap the rate limiter for Redis-backed
token bucket and the API key for OAuth2 / JWT.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Optional

from fastapi import Header, HTTPException, Request, status


class RateLimiter:
    """Fixed-window rate limiter keyed by client IP (and optional API key).

    Thread-safe. Accepts up to `max_requests` per `window_seconds`. On excess,
    `check()` returns False and callers should return HTTP 429.
    """

    def __init__(self, max_requests: int = 120, window_seconds: int = 60) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._buckets: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, client_id: str) -> bool:
        now = time.time()
        threshold = now - self.window_seconds
        with self._lock:
            bucket = self._buckets[client_id]
            # Drop timestamps outside the window
            while bucket and bucket[0] < threshold:
                bucket.popleft()
            if len(bucket) >= self.max_requests:
                return False
            bucket.append(now)
            return True


class ApiKeyAuth:
    """Static API-key validator. Multiple keys separated by comma are allowed."""

    def __init__(self, keys: str) -> None:
        # Accept "key1,key2,key3"
        self.keys = {k.strip() for k in keys.split(",") if k.strip()}

    def verify(self, key: Optional[str]) -> None:
        if not self.keys:
            return  # Auth disabled
        if key is None or key not in self.keys:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing API key.",
            )


# Module-level singletons wired by the app factory
_rate_limiter: Optional[RateLimiter] = None
_api_key_auth: Optional[ApiKeyAuth] = None


def configure_dependencies(rate_limiter: RateLimiter, api_key_auth: ApiKeyAuth) -> None:
    global _rate_limiter, _api_key_auth
    _rate_limiter = rate_limiter
    _api_key_auth = api_key_auth


async def enforce_rate_limit(request: Request) -> None:
    if _rate_limiter is None:
        return
    client = request.client.host if request.client else "unknown"
    if not _rate_limiter.check(client):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Try again shortly.",
        )


async def verify_api_key(x_api_key: Optional[str] = Header(None)) -> None:
    if _api_key_auth is None:
        return
    _api_key_auth.verify(x_api_key)
