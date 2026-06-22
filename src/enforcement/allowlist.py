"""CIDR-based allowlist to protect known-good IPs from enforcement."""

from __future__ import annotations

import ipaddress
from typing import Sequence

from ..utils.logger import get_logger

logger = get_logger(__name__)


class Allowlist:
    """Check whether an IP address falls within any allowlisted CIDR range."""

    def __init__(self, cidrs: Sequence[str]) -> None:
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in cidrs:
            try:
                self._networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                logger.warning("Ignoring invalid CIDR in allowlist: %s", cidr)

    def is_allowed(self, ip_string: str) -> bool:
        """Return True if the IP is in any allowlisted network (should NOT be blocked)."""
        try:
            address = ipaddress.ip_address(ip_string)
        except ValueError:
            return False
        return any(address in network for network in self._networks)

    @property
    def networks(self) -> list[str]:
        return [str(n) for n in self._networks]
