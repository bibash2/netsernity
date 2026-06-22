"""
Alert manager.

Receives prediction results, applies severity logic, enriches them with context
(timestamp, source, suggested response action), stores them in a bounded
in-memory ring buffer, and optionally forwards them to external sinks
(stdout, file, webhook). Designed so the API can simply call
`alerts.record(result, source_ip=...)` after each prediction.
"""

from __future__ import annotations

import json
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..utils.logger import get_logger

logger = get_logger(__name__)


# Severity ranking per attack class
SEVERITY_MAP: dict[str, str] = {
    "BENIGN": "info",
    "PortScan": "low",
    "WebAttack": "medium",
    "BruteForce": "medium",
    "Botnet": "high",
    "Infiltration": "high",
    "DDoS": "critical",
}

# Suggested automated response per attack class
RECOMMENDED_ACTION: dict[str, str] = {
    "BENIGN": "allow",
    "PortScan": "rate_limit_source",
    "WebAttack": "rate_limit_source",
    "BruteForce": "block_source_24h",
    "Botnet": "isolate_host",
    "Infiltration": "isolate_host_and_investigate",
    "DDoS": "drop_and_notify_upstream",
}


class AlertManager:
    """Bounded in-memory alert store plus optional file sink."""

    def __init__(
        self,
        capacity: int = 1000,
        log_file: Optional[str | Path] = None,
        on_alert: Optional[callable] = None,
    ) -> None:
        self.capacity = capacity
        self.alerts: deque[dict] = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self._counter = 0
        self._on_alert = on_alert
        self.log_file = Path(log_file) if log_file else None
        if self.log_file:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    def record(self, prediction_result: dict, source_ip: Optional[str] = None) -> Optional[dict]:
        """Accept one prediction result and create an alert if it's an attack.

        Returns the alert record, or None for benign traffic.
        """
        if not prediction_result.get("is_attack", False):
            return None

        pred_class = prediction_result.get("prediction", "UNKNOWN")
        with self._lock:
            self._counter += 1
            alert = {
                "alert_id": f"ALT-{self._counter:08d}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "severity": SEVERITY_MAP.get(pred_class, "medium"),
                "attack_type": pred_class,
                "confidence": prediction_result.get("confidence", 0.0),
                "anomaly_score": prediction_result.get("anomaly_score", 0.0),
                "anomaly_flagged": prediction_result.get("anomaly_flagged", False),
                "source_ip": source_ip,
                "recommended_action": RECOMMENDED_ACTION.get(pred_class, "investigate"),
                "probabilities": prediction_result.get("probabilities", {}),
            }
            self.alerts.append(alert)

        logger.warning(
            "alert severity=%s type=%s confidence=%.3f source=%s action=%s",
            alert["severity"], alert["attack_type"], alert["confidence"],
            source_ip or "unknown", alert["recommended_action"],
        )

        # Write to file sink
        if self.log_file:
            try:
                with open(self.log_file, "a") as f:
                    f.write(json.dumps(alert) + "\n")
            except OSError as e:
                logger.error("Failed to persist alert to %s: %s", self.log_file, e)

        # Trigger enforcement callback
        if self._on_alert is not None:
            try:
                self._on_alert(alert)
            except Exception as e:
                logger.error("Enforcement callback failed for alert %s: %s", alert["alert_id"], e)

        return alert

    # ------------------------------------------------------------------
    def recent(self, limit: int = 50, severity: Optional[str] = None) -> list[dict]:
        """Return the most recent alerts, optionally filtered by severity."""
        with self._lock:
            records = list(self.alerts)
        if severity:
            records = [r for r in records if r.get("severity") == severity]
        # newest first
        return list(reversed(records))[:limit]

    # ------------------------------------------------------------------
    def summary(self) -> dict:
        """Aggregate stats across all stored alerts."""
        with self._lock:
            records = list(self.alerts)

        by_type: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for r in records:
            by_type[r["attack_type"]] = by_type.get(r["attack_type"], 0) + 1
            by_severity[r["severity"]] = by_severity.get(r["severity"], 0) + 1
        return {
            "total_alerts": len(records),
            "by_type": by_type,
            "by_severity": by_severity,
        }

    def clear(self) -> None:
        with self._lock:
            self.alerts.clear()
            self._counter = 0
