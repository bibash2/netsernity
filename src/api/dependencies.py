"""
API dependencies: JWT auth, API-key auth, rate limiting, and RBAC.

Supports three auth modes:
  1. JWT Bearer token (primary — for dashboard users)
  2. Static API key (legacy — for external systems/sensors)
  3. Disabled (when auth is not configured — all requests get admin access)
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Optional

from fastapi import Depends, Header, HTTPException, Request, status


class RateLimiter:
    """Fixed-window rate limiter keyed by client IP."""

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
            while bucket and bucket[0] < threshold:
                bucket.popleft()
            if len(bucket) >= self.max_requests:
                return False
            bucket.append(now)
            return True


class ApiKeyAuth:
    """Static API-key validator. Multiple keys separated by comma are allowed."""

    def __init__(self, keys: str) -> None:
        self.keys = {k.strip() for k in keys.split(",") if k.strip()}

    def verify(self, key: Optional[str]) -> None:
        if not self.keys:
            return
        if key is None or key not in self.keys:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing API key.",
            )


# Module-level singletons wired by the app factory
_rate_limiter: Optional[RateLimiter] = None
_api_key_auth: Optional[ApiKeyAuth] = None
_jwt_handler = None  # JWTHandler instance, set by configure_auth()


def configure_dependencies(rate_limiter: RateLimiter, api_key_auth: ApiKeyAuth) -> None:
    global _rate_limiter, _api_key_auth
    _rate_limiter = rate_limiter
    _api_key_auth = api_key_auth


def configure_auth(jwt_handler) -> None:
    global _jwt_handler
    _jwt_handler = jwt_handler


async def enforce_rate_limit(request: Request) -> None:
    if _rate_limiter is None:
        return
    client = request.client.host if request.client else "unknown"
    if not _rate_limiter.check(client):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Try again shortly.",
        )


async def get_current_user(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
) -> dict:
    """Authenticate via JWT Bearer token or legacy API key.

    When auth is not configured, returns an anonymous admin user so the system
    works without authentication (development mode / backward compatibility).
    """
    if _jwt_handler is None:
        return {"sub": "anonymous", "role": "admin", "name": ""}

    if authorization and authorization.startswith("Bearer "):
        payload = _jwt_handler.verify_token(authorization[7:])
        if payload:
            return payload

    if x_api_key and _api_key_auth and _api_key_auth.keys:
        try:
            _api_key_auth.verify(x_api_key)
            return {"sub": "api_key_user", "role": "operator", "name": "API Key"}
        except HTTPException:
            pass

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide a Bearer token or API key.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_role(*roles: str):
    """Factory that returns a dependency enforcing role membership."""

    async def _check(user: dict = Depends(get_current_user)) -> dict:
        if user["role"] not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of: {', '.join(roles)}",
            )
        return user

    return _check


async def verify_api_key(x_api_key: Optional[str] = Header(None)) -> None:
    """Legacy API-key-only check (kept for backward compatibility)."""
    if _api_key_auth is None:
        return
    _api_key_auth.verify(x_api_key)
