"""Unit tests for the from-scratch ML models."""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.models import (
    DecisionTreeClassifier,
    EnsembleNIDS,
    IsolationForest,
    MLPClassifier,
    RandomForestClassifier,
)


@pytest.fixture(scope="module")
def toy_data() -> tuple[np.ndarray, np.ndarray]:
    """A small, well-separated 3-class dataset we can train on in milliseconds."""
    rng = np.random.default_rng(0)
    n = 300
    X0 = rng.normal([0.0, 0.0], 0.4, size=(n, 2))
    X1 = rng.normal([4.0, 0.0], 0.4, size=(n, 2))
    X2 = rng.normal([2.0, 4.0], 0.4, size=(n, 2))
    X = np.vstack([X0, X1, X2])
    y = np.concatenate([np.zeros(n), np.ones(n), np.full(n, 2)]).astype(np.int64)
    perm = rng.permutation(len(y))
    return X[perm], y[perm]


# ----------------------------------------------------------------------
# Decision Tree
# ----------------------------------------------------------------------
class TestDecisionTree:
    def test_fits_and_predicts(self, toy_data: tuple[np.ndarray, np.ndarray]) -> None:
        X, y = toy_data
        tree = DecisionTreeClassifier(max_depth=6, random_state=0)
        tree.fit(X, y)
        assert tree.is_fitted
        preds = tree.predict(X)
        assert preds.shape == y.shape
        assert (preds == y).mean() > 0.95

    def test_predict_proba_sums_to_one(self, toy_data: tuple[np.ndarray, np.ndarray]) -> None:
        X, y = toy_data
        tree = DecisionTreeClassifier(max_depth=5).fit(X, y)
        proba = tree.predict_proba(X[:20])
        assert proba.shape == (20, 3)
        np.testing.assert_allclose(proba.sum(axis=1), 1.0, atol=1e-6)

    def test_gini_and_entropy(self) -> None:
        counts = np.array([50, 50])
        assert DecisionTreeClassifier._gini(counts) == pytest.approx(0.5)
        assert DecisionTreeClassifier._entropy(counts) == pytest.approx(1.0)

    def test_not_fitted_raises(self) -> None:
        t = DecisionTreeClassifier()
        with pytest.raises(RuntimeError):
            t.predict(np.zeros((1, 2)))


# ----------------------------------------------------------------------
# Random Forest
# ----------------------------------------------------------------------
class TestRandomForest:
    def test_fits_and_predicts(self, toy_data: tuple[np.ndarray, np.ndarray]) -> None:
        X, y = toy_data
        rf = RandomForestClassifier(n_estimators=10, max_depth=6, random_state=0, oob_score=True)
        rf.fit(X, y)
        preds = rf.predict(X)
        assert (preds == y).mean() > 0.95

    def test_oob_score_in_range(self, toy_data: tuple[np.ndarray, np.ndarray]) -> None:
        X, y = toy_data
        rf = RandomForestClassifier(n_estimators=15, max_depth=6, random_state=0, oob_score=True)
        rf.fit(X, y)
        assert rf.oob_score_ is not None
        assert 0.0 <= rf.oob_score_ <= 1.0
        assert rf.oob_score_ > 0.8

    def test_feature_importances(self, toy_data: tuple[np.ndarray, np.ndarray]) -> None:
        X, y = toy_data
        rf = RandomForestClassifier(n_estimators=8, max_depth=5, random_state=0).fit(X, y)
        imp = rf.feature_importances_
        assert imp is not None and imp.shape == (X.shape[1],)
        assert imp.sum() == pytest.approx(1.0, abs=1e-6)


# ----------------------------------------------------------------------
# MLP
# ----------------------------------------------------------------------
class TestMLP:
    def test_fits_and_predicts(self, toy_data: tuple[np.ndarray, np.ndarray]) -> None:
        X, y = toy_data
        mlp = MLPClassifier(
            hidden_layers=(16, 8),
            epochs=40,
            batch_size=64,
            learning_rate=1e-2,
            dropout=0.0,
            random_state=0,
        )
        mlp.fit(X, y)
        preds = mlp.predict(X)
        acc = (preds == y).mean()
        assert acc > 0.90, f"MLP accuracy too low: {acc}"

    def test_probabilities_sum_to_one(self, toy_data: tuple[np.ndarray, np.ndarray]) -> None:
        X, y = toy_data
        mlp = MLPClassifier(hidden_layers=(8,), epochs=5, dropout=0.0, random_state=0).fit(X, y)
        proba = mlp.predict_proba(X[:5])
        np.testing.assert_allclose(proba.sum(axis=1), 1.0, atol=1e-6)

    def test_early_stopping_runs(self, toy_data: tuple[np.ndarray, np.ndarray]) -> None:
        X, y = toy_data
        split = len(y) * 3 // 4
        mlp = MLPClassifier(
            hidden_layers=(16,),
            epochs=100,
            early_stopping_patience=3,
            dropout=0.0,
            random_state=0,
        )
        mlp.fit(X[:split], y[:split], X_val=X[split:], y_val=y[split:])
        # Either early-stopped (fewer recorded losses than epochs) or completed
        assert len(mlp.history_["train_loss"]) <= 100


# ----------------------------------------------------------------------
# Isolation Forest
# ----------------------------------------------------------------------
class TestIsolationForest:
    def test_detects_anomalies(self) -> None:
        rng = np.random.default_rng(0)
        normal = rng.normal(0, 1, size=(500, 4))
        anomalies = rng.normal(10, 1, size=(25, 4))
        iso = IsolationForest(n_estimators=50, subsample_size=128, contamination=0.05, random_state=0)
        iso.fit(normal)
        preds_normal = iso.is_anomaly(normal)
        preds_anom = iso.is_anomaly(anomalies)
        # Most normal samples should not be flagged; most anomalies should be
        assert preds_normal.mean() < 0.15
        assert preds_anom.mean() > 0.80


# ----------------------------------------------------------------------
# Ensemble
# ----------------------------------------------------------------------
class TestEnsemble:
    def test_end_to_end(self, toy_data: tuple[np.ndarray, np.ndarray]) -> None:
        X, y = toy_data
        rf = RandomForestClassifier(n_estimators=8, max_depth=6, random_state=0).fit(X, y)
        mlp = MLPClassifier(hidden_layers=(16, 8), epochs=20, dropout=0.0, random_state=0).fit(X, y)
        iso = IsolationForest(n_estimators=30, subsample_size=128, random_state=0).fit(X[y == 0])
        ens = EnsembleNIDS(rf=rf, mlp=mlp, iso=iso)
        ens.is_fitted = True
        ens.n_features_ = X.shape[1]
        ens.classes_ = np.unique(y)
        ens.n_classes_ = 3
        preds = ens.predict(X)
        assert (preds == y).mean() > 0.90
        detail = ens.predict_with_detail(X[:5])
        assert detail["ensemble_proba"].shape == (5, 3)

    def test_high_anomaly_boost_reduces_false_positives(
        self, toy_data: tuple[np.ndarray, np.ndarray]
    ) -> None:
        """High anomaly_boost (0.9) should produce fewer FPs than low (0.5)."""
        X, y = toy_data
        rf = RandomForestClassifier(n_estimators=8, max_depth=6, random_state=0).fit(X, y)
        mlp = MLPClassifier(hidden_layers=(16, 8), epochs=20, dropout=0.0, random_state=0).fit(X, y)
        iso = IsolationForest(n_estimators=30, subsample_size=128, random_state=0).fit(X[y == 0])

        benign_samples = X[y == 0]

        ens_aggressive = EnsembleNIDS(rf=rf, mlp=mlp, iso=iso, anomaly_boost=0.5)
        ens_aggressive.is_fitted = True
        ens_aggressive.n_features_ = X.shape[1]
        ens_aggressive.classes_ = np.unique(y)
        ens_aggressive.n_classes_ = 3

        ens_conservative = EnsembleNIDS(rf=rf, mlp=mlp, iso=iso, anomaly_boost=0.9)
        ens_conservative.is_fitted = True
        ens_conservative.n_features_ = X.shape[1]
        ens_conservative.classes_ = np.unique(y)
        ens_conservative.n_classes_ = 3

        fpr_aggressive = (ens_aggressive.predict(benign_samples) != 0).mean()
        fpr_conservative = (ens_conservative.predict(benign_samples) != 0).mean()

        assert fpr_conservative <= fpr_aggressive, (
            f"Conservative FPR ({fpr_conservative:.2%}) should be <= "
            f"aggressive FPR ({fpr_aggressive:.2%})"
        )


class TestMetrics:
    def test_fpr_fnr_detection_rate(self) -> None:
        from src.utils.metrics import false_positive_rate, false_negative_rate, detection_rate

        y_true = np.array([0, 0, 0, 0, 1, 1, 2, 2])
        y_pred = np.array([0, 0, 1, 0, 1, 0, 2, 2])  # 1 FP (benign→attack), 1 FN (attack→benign)

        fpr = false_positive_rate(y_true, y_pred)
        fnr = false_negative_rate(y_true, y_pred)
        dr = detection_rate(y_true, y_pred)

        assert abs(fpr - 0.25) < 1e-6     # 1 out of 4 benign misclassified
        assert abs(fnr - 0.25) < 1e-6     # 1 out of 4 attacks missed
        assert abs(dr - 0.75) < 1e-6      # 3 out of 4 attacks caught
