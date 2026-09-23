"""
Lightweight Prometheus-style metrics exporter — no external dependencies.

Exposes:
    nids_predictions_total{result="attack|benign"}
    nids_alerts_total{severity="low|medium|high|critical"}
    nids_prediction_latency_ms_bucket{le="..."}
    nids_prediction_latency_ms_sum
    nids_prediction_latency_ms_count
    nids_http_requests_total{route,status}
    nids_up

Implemented from scratch so we don't need to pull in prometheus_client as a
runtime dependency. Output format matches the text-based exposition spec
(v0.0.4) and is accepted by Prometheus servers unchanged.
"""

from __future__ import annotations

import threading
from typing import Optional


LATENCY_BUCKETS_MS: list[float] = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000]


class MetricsRegistry:
    """Threadsafe in-memory registry of counters + histograms."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.counters: dict[tuple, float] = {}
        self.histogram_counts: dict[tuple, list[int]] = {}
        self.histogram_sums: dict[tuple, float] = {}
        self.histogram_totals: dict[tuple, int] = {}
        self.gauges: dict[tuple, float] = {}
        # Register baseline gauge
        self.set_gauge("nids_up", 1)

    # ------------------------------------------------------------------
    @staticmethod
    def _key(name: str, labels: Optional[dict[str, str]] = None) -> tuple:
        label_items = tuple(sorted((labels or {}).items()))
        return (name, label_items)

    # ------------------------------------------------------------------
    def inc_counter(self, name: str, labels: Optional[dict[str, str]] = None, value: float = 1.0) -> None:
        key = self._key(name, labels)
        with self._lock:
            self.counters[key] = self.counters.get(key, 0.0) + value

    def set_gauge(self, name: str, value: float, labels: Optional[dict[str, str]] = None) -> None:
        key = self._key(name, labels)
        with self._lock:
            self.gauges[key] = value

    def observe_histogram(self, name: str, value_ms: float, labels: Optional[dict[str, str]] = None) -> None:
        key = self._key(name, labels)
        with self._lock:
            if key not in self.histogram_counts:
                self.histogram_counts[key] = [0] * len(LATENCY_BUCKETS_MS)
                self.histogram_sums[key] = 0.0
                self.histogram_totals[key] = 0
            for i, bucket in enumerate(LATENCY_BUCKETS_MS):
                if value_ms <= bucket:
                    self.histogram_counts[key][i] += 1
            self.histogram_sums[key] += value_ms
            self.histogram_totals[key] += 1

    # ------------------------------------------------------------------
    @staticmethod
    def _fmt_labels(label_items: tuple) -> str:
        if not label_items:
            return ""
        parts = [f'{k}="{v}"' for k, v in label_items]
        return "{" + ",".join(parts) + "}"

    def render(self) -> str:
        """Produce the Prometheus text exposition payload."""
        lines: list[str] = []
        with self._lock:
            # Counters
            counters_by_name: dict[str, list[tuple[tuple, float]]] = {}
            for (name, labels), value in self.counters.items():
                counters_by_name.setdefault(name, []).append((labels, value))
            for name, series in counters_by_name.items():
                lines.append(f"# TYPE {name} counter")
                for labels, value in series:
                    lines.append(f"{name}{self._fmt_labels(labels)} {value}")

            # Gauges
            gauges_by_name: dict[str, list[tuple[tuple, float]]] = {}
            for (name, labels), value in self.gauges.items():
                gauges_by_name.setdefault(name, []).append((labels, value))
            for name, series in gauges_by_name.items():
                lines.append(f"# TYPE {name} gauge")
                for labels, value in series:
                    lines.append(f"{name}{self._fmt_labels(labels)} {value}")

            # Histograms
            hist_by_name: dict[str, list[tuple[tuple, list[int], float, int]]] = {}
            for key, counts in self.histogram_counts.items():
                name, labels = key
                hist_by_name.setdefault(name, []).append(
                    (labels, counts, self.histogram_sums[key], self.histogram_totals[key])
                )
            for name, series in hist_by_name.items():
                lines.append(f"# TYPE {name} histogram")
                for labels, counts, total_sum, total_count in series:
                    cumulative = 0
                    for i, bucket in enumerate(LATENCY_BUCKETS_MS):
                        cumulative = counts[i]
                        bucket_labels = labels + (("le", str(bucket)),)
                        lines.append(f"{name}_bucket{self._fmt_labels(bucket_labels)} {cumulative}")
                    inf_labels = labels + (("le", "+Inf"),)
                    lines.append(f"{name}_bucket{self._fmt_labels(inf_labels)} {total_count}")
                    lines.append(f"{name}_sum{self._fmt_labels(labels)} {total_sum}")
                    lines.append(f"{name}_count{self._fmt_labels(labels)} {total_count}")

        return "\n".join(lines) + "\n"


# Global registry accessed by the API
REGISTRY = MetricsRegistry()
