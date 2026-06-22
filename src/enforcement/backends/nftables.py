"""nftables backend — uses kernel-native sets with timeout for IP blocking.

Requires CAP_NET_ADMIN. The nft commands create an isolated table and set so
that NetSentry rules never interfere with the host's base firewall policy.

Structure created:
    table inet <table_name> {
        set blocked_ips { type ipv4_addr; flags timeout; }
        chain input { type filter hook input priority 0; policy accept;
            ip saddr @blocked_ips drop
        }
    }
"""

from __future__ import annotations

import subprocess

from ...utils.logger import get_logger
from .base import FirewallBackend

logger = get_logger(__name__)


class NftablesBackend(FirewallBackend):
    """Block IPs via nftables sets with kernel-managed timeouts."""

    def __init__(self, table_name: str = "netsentry", chain_name: str = "blocked") -> None:
        self._table = table_name
        self._chain = chain_name

    def _run_nft(self, *args: str) -> subprocess.CompletedProcess:
        cmd = ["nft"] + list(args)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            logger.error("nft command failed: %s stderr=%s", " ".join(cmd), result.stderr.strip())
        return result

    def setup(self) -> None:
        """Create the netsentry table, set, and chain. Idempotent."""
        # Create table (idempotent via 'add')
        self._run_nft("add", "table", "inet", self._table)

        # Create set with timeout support
        self._run_nft(
            "add", "set", "inet", self._table, "blocked_ips",
            "{ type ipv4_addr; flags timeout; }"
        )

        # Create filter chain hooked into input
        self._run_nft(
            "add", "chain", "inet", self._table, self._chain,
            "{ type filter hook input priority 0; policy accept; }"
        )

        # Add drop rule for IPs in the set
        self._run_nft(
            "add", "rule", "inet", self._table, self._chain,
            "ip", "saddr", "@blocked_ips", "drop"
        )

        logger.info(
            "nftables setup complete: table=%s chain=%s",
            self._table, self._chain,
        )

    def block_ip(self, ip_address: str, duration_seconds: int) -> None:
        """Add IP to the blocked set with a kernel-managed timeout."""
        timeout_spec = f"{duration_seconds}s"
        result = self._run_nft(
            "add", "element", "inet", self._table, "blocked_ips",
            "{ " + ip_address + " timeout " + timeout_spec + " }"
        )
        if result.returncode == 0:
            logger.info(
                "nftables blocked ip=%s duration=%ss table=%s",
                ip_address, duration_seconds, self._table,
            )

    def unblock_ip(self, ip_address: str) -> None:
        """Remove IP from the blocked set."""
        result = self._run_nft(
            "delete", "element", "inet", self._table, "blocked_ips",
            "{ " + ip_address + " }"
        )
        if result.returncode == 0:
            logger.info("nftables unblocked ip=%s", ip_address)

    def flush(self) -> None:
        """Flush all elements from the blocked set, keeping the table and chain intact."""
        self._run_nft("flush", "set", "inet", self._table, "blocked_ips")
        logger.info("nftables flushed blocked_ips set in table=%s", self._table)
