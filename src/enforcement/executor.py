"""Response executor — orchestrates enforcement decisions.

Given an alert dict from AlertManager, the executor:
1. Looks up the response policy for the attack class
2. Checks whether confidence meets the minimum threshold
3. Validates the source IP and checks the allowlist
4. Delegates to the firewall backend if all checks pass
5. Tracks currently blocked IPs for the management API
"""

from __future__ import annotations

import ipaddress
import threading
import time
from dataclasses import dataclass
from typing import Optional

from ..utils.logger import get_logger
from .allowlist import Allowlist
from .backends.base import FirewallBackend
from .policy import RESPONSE_POLICY, ActionType, ResponseAction

logger = get_logger(__name__)


@dataclass
class BlockRecord:
    """Tracks a currently active IP block."""

    ip_address: str
    attack_type: str
    action_type: str
    confidence: float
    blocked_at: float
    expires_at: float
    alert_id: str


class ResponseExecutor:
    """Orchestrates enforcement actions based on alert data and policy."""

    def __init__(
        self,
        backend: FirewallBackend,
        allowlist: Allowlist,
        enabled: bool = False,
        min_confidence_override: Optional[float] = None,
        default_block_duration_seconds: int = 86400,
        max_blocked_ips: int = 10000,
    ) -> None:
        self._backend = backend
        self._allowlist = allowlist
        self._enabled = enabled
        self._min_confidence_override = min_confidence_override
        self._default_block_duration = default_block_duration_seconds
        self._max_blocked_ips = max_blocked_ips

        self._blocked_ips: dict[str, BlockRecord] = {}
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self._enabled

    def setup(self) -> None:
        """Initialize the firewall backend. Call once at startup."""
        self._backend.flush()
        self._backend.setup()
        logger.info(
            "ResponseExecutor initialized: enabled=%s backend=%s allowlist=%d networks",
            self._enabled, type(self._backend).__name__, len(self._allowlist.networks),
        )

    def enforce(self, alert: dict) -> Optional[BlockRecord]:
        """Evaluate an alert and enforce the appropriate action.

        Returns a BlockRecord if the IP was blocked, None otherwise.
        """
        if not self._enabled:
            return None

        source_ip = alert.get("source_ip")
        if not source_ip:
            return None

        # Validate IP format — prevents command injection
        try:
            ipaddress.ip_address(source_ip)
        except ValueError:
            logger.warning("Invalid source IP in alert, skipping enforcement: %s", source_ip)
            return None

        attack_type = alert.get("attack_type", "UNKNOWN")
        policy = RESPONSE_POLICY.get(attack_type)
        if policy is None or policy.action_type == ActionType.ALLOW:
            return None

        # Confidence gating
        confidence = alert.get("confidence", 0.0)
        required_confidence = (
            self._min_confidence_override
            if self._min_confidence_override is not None
            else policy.min_confidence
        )
        if confidence < required_confidence:
            logger.debug(
                "Skipping enforcement for ip=%s attack=%s: confidence=%.3f < required=%.3f",
                source_ip, attack_type, confidence, required_confidence,
            )
            return None

        # Allowlist check
        if self._allowlist.is_allowed(source_ip):
            logger.warning(
                "Allowlisted IP detected as attack: ip=%s attack=%s confidence=%.3f — not blocking",
                source_ip, attack_type, confidence,
            )
            return None

        # Determine block duration
        duration = policy.block_duration_seconds or self._default_block_duration

        # Capacity check
        with self._lock:
            if source_ip in self._blocked_ips:
                existing = self._blocked_ips[source_ip]
                if existing.expires_at > time.time():
                    return existing  # Already blocked, skip duplicate

            if len(self._blocked_ips) >= self._max_blocked_ips:
                logger.error(
                    "Max blocked IPs reached (%d), refusing to block ip=%s — manual review needed",
                    self._max_blocked_ips, source_ip,
                )
                return None

        # Execute the block
        try:
            self._backend.block_ip(source_ip, duration)
        except Exception:
            logger.exception("Failed to block ip=%s via backend", source_ip)
            return None

        now = time.time()
        record = BlockRecord(
            ip_address=source_ip,
            attack_type=attack_type,
            action_type=policy.action_type.value,
            confidence=confidence,
            blocked_at=now,
            expires_at=now + duration,
            alert_id=alert.get("alert_id", ""),
        )

        with self._lock:
            self._blocked_ips[source_ip] = record

        logger.warning(
            "ENFORCED %s on ip=%s attack=%s confidence=%.3f duration=%ds alert=%s",
            policy.action_type.value, source_ip, attack_type,
            confidence, duration, alert.get("alert_id"),
        )

        return record

    def unblock(self, ip_address: str) -> bool:
        """Manually unblock an IP. Returns True if it was blocked."""
        with self._lock:
            if ip_address not in self._blocked_ips:
                return False
            self._blocked_ips.pop(ip_address)

        try:
            self._backend.unblock_ip(ip_address)
        except Exception:
            logger.exception("Failed to unblock ip=%s via backend", ip_address)
            return False

        logger.info("Manually unblocked ip=%s", ip_address)
        return True

    def get_blocked_ips(self) -> list[dict]:
        """Return a list of currently blocked IPs with metadata."""
        now = time.time()
        with self._lock:
            # Clean expired entries while we're here
            expired = [ip for ip, r in self._blocked_ips.items() if r.expires_at <= now]
            for ip in expired:
                self._blocked_ips.pop(ip)

            return [
                {
                    "ip_address": r.ip_address,
                    "attack_type": r.attack_type,
                    "action_type": r.action_type,
                    "confidence": r.confidence,
                    "blocked_at": r.blocked_at,
                    "expires_at": r.expires_at,
                    "remaining_seconds": int(r.expires_at - now),
                    "alert_id": r.alert_id,
                }
                for r in self._blocked_ips.values()
            ]

    def flush_all(self) -> int:
        """Remove all blocks. Returns the count of IPs unblocked."""
        with self._lock:
            count = len(self._blocked_ips)
            self._blocked_ips.clear()
        self._backend.flush()
        logger.info("Flushed all blocked IPs, count=%d", count)
        return count
