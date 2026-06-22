"""Abstract base class for firewall backends."""

from __future__ import annotations

from abc import ABC, abstractmethod


class FirewallBackend(ABC):
    """Interface for firewall manipulation.

    Each implementation translates block/unblock/flush calls into the
    appropriate system commands for a specific firewall technology.
    """

    @abstractmethod
    def setup(self) -> None:
        """Create required firewall tables, chains, or sets. Idempotent."""

    @abstractmethod
    def block_ip(self, ip_address: str, duration_seconds: int) -> None:
        """Add a DROP rule for the given IP with the specified TTL."""

    @abstractmethod
    def unblock_ip(self, ip_address: str) -> None:
        """Remove any blocking rules for the given IP."""

    @abstractmethod
    def flush(self) -> None:
        """Remove all rules managed by this backend. Used on startup to reset state."""
