"""Enforcement policy definitions.

Maps attack classifications to structured enforcement actions with durations,
confidence thresholds, and action types. Separate from the advisory
RECOMMENDED_ACTION strings in alert_manager — this drives real enforcement.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ActionType(Enum):
    """Types of enforcement actions the system can take."""

    ALLOW = "allow"
    RATE_LIMIT = "rate_limit"
    BLOCK = "block"
    DROP = "drop"


@dataclass(frozen=True)
class ResponseAction:
    """A structured enforcement action with parameters."""

    action_type: ActionType
    block_duration_seconds: int
    min_confidence: float
    notify: bool = False

    @property
    def is_blocking(self) -> bool:
        return self.action_type in (ActionType.BLOCK, ActionType.DROP)


# Policy mapping: attack class -> enforcement action.
# Each entry defines what action to take, how long to block, and the minimum
# confidence required before the system will auto-enforce.
RESPONSE_POLICY: dict[str, ResponseAction] = {
    "BENIGN": ResponseAction(
        action_type=ActionType.ALLOW,
        block_duration_seconds=0,
        min_confidence=0.0,
    ),
    "PortScan": ResponseAction(
        action_type=ActionType.RATE_LIMIT,
        block_duration_seconds=3600,       # 1 hour
        min_confidence=0.90,
    ),
    "WebAttack": ResponseAction(
        action_type=ActionType.RATE_LIMIT,
        block_duration_seconds=3600,       # 1 hour
        min_confidence=0.90,
    ),
    "BruteForce": ResponseAction(
        action_type=ActionType.BLOCK,
        block_duration_seconds=86400,      # 24 hours
        min_confidence=0.85,
    ),
    "Botnet": ResponseAction(
        action_type=ActionType.BLOCK,
        block_duration_seconds=86400,      # 24 hours
        min_confidence=0.85,
        notify=True,
    ),
    "Infiltration": ResponseAction(
        action_type=ActionType.BLOCK,
        block_duration_seconds=86400,      # 24 hours
        min_confidence=0.85,
        notify=True,
    ),
    "DDoS": ResponseAction(
        action_type=ActionType.DROP,
        block_duration_seconds=86400,      # 24 hours
        min_confidence=0.80,
        notify=True,
    ),
}
