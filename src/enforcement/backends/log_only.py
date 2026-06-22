"""Log-only backend for dry-run mode.

Logs every enforcement action without modifying the firewall. Use this as the
first deployment step to validate that policy and thresholds are sane before
enabling real blocking.
"""

from __future__ import annotations

from ...utils.logger import get_logger
from .base import FirewallBackend

logger = get_logger(__name__)


class LogOnlyBackend(FirewallBackend):
    """Logs enforcement actions without executing them."""

    def setup(self) -> None:
        logger.info("LogOnlyBackend active — enforcement actions will be logged but not executed")

    def block_ip(self, ip_address: str, duration_seconds: int) -> None:
        logger.info(
            "[DRY RUN] would block ip=%s duration=%ss",
            ip_address, duration_seconds,
        )

    def unblock_ip(self, ip_address: str) -> None:
        logger.info("[DRY RUN] would unblock ip=%s", ip_address)

    def flush(self) -> None:
        logger.info("[DRY RUN] would flush all blocked IPs")
