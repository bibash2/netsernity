"""
Ensemble classifier — weighted soft-voting over the from-scratch models.

Combines predictions from:
    - RandomForestClassifier (supervised, known attacks)
    - MLPClassifier          (supervised, deep nonlinear patterns)
    - IsolationForest        (unsupervised, zero-day anomalies)

The ensemble weights each supervised model's probability output, then overrides
the benign prediction if the Isolation Forest reports the sample as anomalous
with a high score. This layered fusion is the production detection policy.
"""

from __future__ import annotations

import pickle
from pathlib import Path
from typing import Optional

import numpy as np

from .base import BaseModel
from .isolation_forest import IsolationForest
from .neural_network import MLPClassifier
from .random_forest import RandomForestClassifier


class EnsembleNIDS(BaseModel):
    """Production detection head for NetSentry.

    Parameters
    ----------
    rf_weight, mlp_weight : float
        Weights applied to each supervised model's probability vector.
        They should sum to 1.0.
    anomaly_boost : float
        When the Isolation Forest anomaly score exceeds `anomaly_boost`,
        any sample currently predicted as benign is reclassified as attack
        (using the most-likely attack class from the supervised models).
    benign_class : int
        Label used for benign traffic (default 0).
    """

    def __init__(
        self,
        rf: Optional[RandomForestClassifier] = None,
        mlp: Optional[MLPClassifier] = None,
        iso: Optional[IsolationForest] = None,
        rf_weight: float = 0.55,
        mlp_weight: float = 0.45,
        anomaly_boost: float = 0.7,
        benign_class: int = 0,
    ) -> None:
        super().__init__()
        self.rf = rf
        self.mlp = mlp
        self.iso = iso
        self.rf_weight = rf_weight
        self.mlp_weight = mlp_weight
        self.anomaly_boost = anomaly_boost
        self.benign_class = benign_class

    def fit(self, X: np.ndarray, y: np.ndarray) -> "EnsembleNIDS":  # type: ignore[override]
        """Fit all underlying models. Typically you fit them externally and pass
        them into the constructor, but this convenience method trains a default
        config in one call."""
        if self.rf is None:
            self.rf = RandomForestClassifier(n_estimators=50, random_state=42, verbose=False)
        if self.mlp is None:
            self.mlp = MLPClassifier(hidden_layers=(64, 32), epochs=30, random_state=42)
        if self.iso is None:
            self.iso = IsolationForest(n_estimators=80, random_state=42)

        self.rf.fit(X, y)
        self.mlp.fit(X, y)
        # Isolation Forest is unsupervised — train it only on benign samples
        benign_mask = y == self.benign_class
        self.iso.fit(X[benign_mask])

        self.n_features_ = X.shape[1]
        self.classes_ = np.unique(y)
        self.n_classes_ = int(self.classes_.max()) + 1
        self.is_fitted = True
        return self

    def _check_components(self) -> None:
        if self.rf is None or self.mlp is None or self.iso is None:
            raise RuntimeError("Ensemble requires RF, MLP, and IsolationForest components.")
        if not (self.rf.is_fitted and self.mlp.is_fitted and self.iso.is_fitted):
            raise RuntimeError("All underlying models must be fitted.")

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        self._check_components()
        X = np.asarray(X, dtype=np.float64)
        if X.ndim == 1:
            X = X.reshape(1, -1)

        rf_proba = self.rf.predict_proba(X)
        mlp_proba = self.mlp.predict_proba(X)
        total_w = self.rf_weight + self.mlp_weight
        combined = (self.rf_weight * rf_proba + self.mlp_weight * mlp_proba) / total_w
        return combined

    def predict(self, X: np.ndarray) -> np.ndarray:
        self._check_components()
        X = np.asarray(X, dtype=np.float64)
        if X.ndim == 1:
            X = X.reshape(1, -1)

        proba = self.predict_proba(X)
        base_pred = np.argmax(proba, axis=1)

        # Anomaly override: if IF flags the sample strongly and the supervised
        # models said "benign", re-route to the most likely attack class.
        anomaly_scores = self.iso.anomaly_score(X)
        for i in range(X.shape[0]):
            if base_pred[i] == self.benign_class and anomaly_scores[i] >= self.anomaly_boost:
                # Pick the highest-probability non-benign class
                non_benign = np.arange(proba.shape[1]) != self.benign_class
                if non_benign.any():
                    idx_pool = np.where(non_benign)[0]
                    best = idx_pool[np.argmax(proba[i, non_benign])]
                    base_pred[i] = best

        return base_pred.astype(np.int64)

    def predict_with_detail(self, X: np.ndarray) -> dict:
        """Return per-model predictions and the combined decision for auditing."""
        self._check_components()
        X = np.asarray(X, dtype=np.float64)
        if X.ndim == 1:
            X = X.reshape(1, -1)

        rf_proba = self.rf.predict_proba(X)
        mlp_proba = self.mlp.predict_proba(X)
        anomaly = self.iso.anomaly_score(X)
        combined = self.predict_proba(X)
        final = self.predict(X)

        return {
            "rf_proba": rf_proba,
            "mlp_proba": mlp_proba,
            "anomaly_score": anomaly,
            "ensemble_proba": combined,
            "final_prediction": final,
            "anomaly_flagged": anomaly >= self.anomaly_boost,
        }

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(self, f, protocol=pickle.HIGHEST_PROTOCOL)

    @classmethod
    def load(cls, path: str | Path) -> "EnsembleNIDS":
        with open(path, "rb") as f:
            obj = pickle.load(f)
        if not isinstance(obj, cls):
            raise TypeError(f"Loaded object is not an EnsembleNIDS: {type(obj)}")
        return obj
