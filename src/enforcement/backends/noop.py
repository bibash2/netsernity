"""No-op backend for testing and when enforcement is disabled."""

from __future__ import annotations

from .base import FirewallBackend


class NoOpBackend(FirewallBackend):
    """Silent backend that does nothing. Used in tests and when enforcement is off."""

    def __init__(self) -> None:
        self.blocked: dict[str, int] = {}
        self.setup_called = False
        self.flush_called = False

    def setup(self) -> None:
        self.setup_called = True

    def block_ip(self, ip_address: str, duration_seconds: int) -> None:
        self.blocked[ip_address] = duration_seconds

    def unblock_ip(self, ip_address: str) -> None:
        self.blocked.pop(ip_address, None)

    def flush(self) -> None:
        self.blocked.clear()
        self.flush_called = True
