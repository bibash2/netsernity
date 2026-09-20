"""HMAC-SHA256 JWT implementation — no external dependencies.

Matches the project's from-scratch philosophy. Uses only Python stdlib
(hmac, hashlib, base64, json).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Optional


class JWTHandler:

    def __init__(self, secret: str, expiry_seconds: int = 86400) -> None:
        self._secret = secret.encode()
        self._expiry = expiry_seconds

    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    @staticmethod
    def _b64url_decode(s: str) -> bytes:
        padding = 4 - len(s) % 4
        if padding != 4:
            s += "=" * padding
        return base64.urlsafe_b64decode(s)

    def create_token(self, username: str, role: str, full_name: str = "") -> str:
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": username,
            "role": role,
            "name": full_name,
            "iat": int(time.time()),
            "exp": int(time.time()) + self._expiry,
        }
        h = self._b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        p = self._b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        sig = hmac.new(self._secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
        return f"{h}.{p}.{self._b64url_encode(sig)}"

    def verify_token(self, token: str) -> Optional[dict]:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        h, p, s = parts
        expected = hmac.new(self._secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
        try:
            actual = self._b64url_decode(s)
        except Exception:
            return None
        if not hmac.compare_digest(expected, actual):
            return None
        try:
            payload = json.loads(self._b64url_decode(p))
        except (json.JSONDecodeError, ValueError):
            return None
        if payload.get("exp", 0) < time.time():
            return None
        return payload
