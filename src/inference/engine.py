"""
Real-time inference engine.

Loads trained artifacts once at startup, then serves predictions for either
single flows or batches. Tracks latency stats (p50, p95, p99) to support SLA
monitoring. Threadsafe for use from an async API (the model objects are
immutable after load and predictions are stateless).
"""

from __future__ import annotations

import threading
import time
from collections import deque
from pathlib import Path
from typing import Optional

import numpy as np

from ..data import CLASS_NAMES, FEATURE_NAMES, Preprocessor
from ..models import EnsembleNIDS
from ..utils.logger import get_logger

logger = get_logger(__name__)


class InferenceEngine:
    """Production-facing prediction service."""

    def __init__(self, models_dir: str | Path) -> None:
        self.models_dir = Path(models_dir)
        self.preprocessor: Optional[Preprocessor] = None
        self.ensemble: Optional[EnsembleNIDS] = None
        self._lock = threading.Lock()
        self._latencies_ms: deque[float] = deque(maxlen=1000)
        self._total_predictions: int = 0
        self._total_attacks_detected: int = 0
        self._load()

    # ------------------------------------------------------------------
    def _load(self) -> None:
        pre_path = self.models_dir / "preprocessor.pkl"
        ens_path = self.models_dir / "ensemble.pkl"
        if not pre_path.exists() or not ens_path.exists():
            raise FileNotFoundError(
                f"Missing model artifacts under {self.models_dir}. "
                f"Run the training pipeline first."
            )
        self.preprocessor = Preprocessor.load(pre_path)
        self.ensemble = EnsembleNIDS.load(ens_path)
        logger.info("Inference engine loaded artifacts from %s", self.models_dir)

    def ready(self) -> bool:
        return self.preprocessor is not None and self.ensemble is not None

    # ------------------------------------------------------------------
    def predict(self, flow_features: dict | list[dict]) -> dict:
        """Predict on one or many flows.

        Input is either a dict of feature_name -> value, or a list of such dicts.
        Returns a dict with predictions, probabilities, anomaly scores, and
        timing info. Designed to be directly JSON-serializable.
        """
        if self.preprocessor is None or self.ensemble is None:
            raise RuntimeError("Inference engine not ready.")

        if isinstance(flow_features, dict):
            batch = [flow_features]
            single = True
        else:
            batch = flow_features
            single = False

        X = self._dicts_to_matrix(batch)

        t0 = time.time()
        with self._lock:
            X_scaled = self.preprocessor.transform(X)
            detail = self.ensemble.predict_with_detail(X_scaled)
        latency_ms = (time.time() - t0) * 1000

        predictions = detail["final_prediction"].tolist()
        probas = detail["ensemble_proba"].tolist()
        anomaly_scores = detail["anomaly_score"].tolist()
        anomaly_flags = detail["anomaly_flagged"].tolist()

        results = []
        for i, pred_idx in enumerate(predictions):
            class_name = CLASS_NAMES[pred_idx] if pred_idx < len(CLASS_NAMES) else f"class_{pred_idx}"
            is_attack = class_name != "BENIGN"
            confidence = float(max(probas[i]))
            results.append({
                "prediction": class_name,
                "class_id": int(pred_idx),
                "is_attack": bool(is_attack),
                "confidence": confidence,
                "anomaly_score": float(anomaly_scores[i]),
                "anomaly_flagged": bool(anomaly_flags[i]),
                "probabilities": {
                    CLASS_NAMES[j]: float(probas[i][j])
                    for j in range(len(probas[i]))
                    if j < len(CLASS_NAMES)
                },
            })

        # Record telemetry
        with self._lock:
            per_sample_latency = latency_ms / max(1, len(batch))
            self._latencies_ms.extend([per_sample_latency] * len(batch))
            self._total_predictions += len(batch)
            self._total_attacks_detected += sum(1 for r in results if r["is_attack"])

        response = {
            "results": results[0] if single else results,
            "batch_size": len(batch),
            "total_latency_ms": round(latency_ms, 3),
            "avg_latency_ms": round(latency_ms / max(1, len(batch)), 3),
        }
        return response

    # ------------------------------------------------------------------
    def _dicts_to_matrix(self, rows: list[dict]) -> np.ndarray:
        matrix = np.zeros((len(rows), len(FEATURE_NAMES)), dtype=np.float64)
        for i, row in enumerate(rows):
            for j, feat in enumerate(FEATURE_NAMES):
                val = row.get(feat, 0.0)
                try:
                    matrix[i, j] = float(val)
                except (TypeError, ValueError):
                    matrix[i, j] = 0.0
        return matrix

    # ------------------------------------------------------------------
    def stats(self) -> dict:
        """Return inference-engine telemetry snapshot."""
        with self._lock:
            latencies = list(self._latencies_ms)
            total = self._total_predictions
            attacks = self._total_attacks_detected

        if latencies:
            arr = np.array(latencies)
            stats = {
                "total_predictions": total,
                "total_attacks_detected": attacks,
                "attack_rate": attacks / max(1, total),
                "latency_ms": {
                    "p50": float(np.percentile(arr, 50)),
                    "p95": float(np.percentile(arr, 95)),
                    "p99": float(np.percentile(arr, 99)),
                    "mean": float(arr.mean()),
                },
            }
        else:
            stats = {
                "total_predictions": total,
                "total_attacks_detected": attacks,
                "attack_rate": 0.0,
                "latency_ms": {"p50": 0.0, "p95": 0.0, "p99": 0.0, "mean": 0.0},
            }
        return stats
