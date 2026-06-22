"""Tests for the data pipeline and from-scratch metrics."""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.data import CLASS_NAMES, FEATURE_NAMES, Preprocessor, generate_dataset
from src.utils import metrics as M


class TestGenerator:
    def test_shape_and_labels(self) -> None:
        X, y, feats = generate_dataset(n_samples=2000, random_state=42, label_noise=0.0)
        assert X.shape == (2000, len(FEATURE_NAMES))
        assert y.shape == (2000,)
        assert set(feats) == set(FEATURE_NAMES)
        assert set(np.unique(y).tolist()).issubset(set(range(len(CLASS_NAMES))))

    def test_benign_majority(self) -> None:
        _, y, _ = generate_dataset(n_samples=5000, random_state=1, label_noise=0.0)
        assert (y == 0).mean() > 0.5  # benign is the largest class


class TestPreprocessor:
    def test_fit_transform_shapes(self) -> None:
        X, y, _ = generate_dataset(n_samples=500, random_state=7, label_noise=0.0)
        pre = Preprocessor(FEATURE_NAMES, top_k_features=15)
        pre.fit(X, y)
        Xt = pre.transform(X[:100])
        assert Xt.shape == (100, 15)

    def test_stratified_split_preserves_classes(self) -> None:
        X, y, _ = generate_dataset(n_samples=3000, random_state=3, label_noise=0.0)
        X_tr, y_tr, X_val, y_val, X_te, y_te = Preprocessor.stratified_split(
            X, y, test_size=0.2, val_size=0.1, random_state=3
        )
        # No data loss
        assert len(y_tr) + len(y_val) + len(y_te) == len(y)
        # All splits have every class present
        assert set(np.unique(y_tr)) == set(np.unique(y))
        assert set(np.unique(y_te)) == set(np.unique(y))

    def test_scaler_zero_mean_unit_std_on_train(self) -> None:
        X, y, _ = generate_dataset(n_samples=500, random_state=2, label_noise=0.0)
        pre = Preprocessor(FEATURE_NAMES, top_k_features=None).fit(X, y)
        Xt = pre.transform(X)
        # Mean should be ~0, std ~1
        assert np.allclose(Xt.mean(axis=0), 0.0, atol=1e-6)
        assert np.allclose(Xt.std(axis=0), 1.0, atol=1e-2)

    def test_handles_inf_and_nan(self) -> None:
        X, y, _ = generate_dataset(n_samples=200, random_state=2, label_noise=0.0)
        X = X.copy()
        X[0, 0] = float("inf")
        X[1, 1] = float("nan")
        pre = Preprocessor(FEATURE_NAMES).fit(X, y)
        Xt = pre.transform(X)
        assert np.isfinite(Xt).all()


class TestMetrics:
    def test_confusion_matrix(self) -> None:
        y_true = np.array([0, 1, 2, 0, 1, 2])
        y_pred = np.array([0, 1, 1, 0, 1, 2])
        cm = M.confusion_matrix(y_true, y_pred, n_classes=3)
        assert cm.shape == (3, 3)
        assert cm[0, 0] == 2
        assert cm[1, 1] == 2
        assert cm[2, 1] == 1
        assert cm[2, 2] == 1

    def test_accuracy(self) -> None:
        y_true = np.array([0, 1, 0, 1])
        y_pred = np.array([0, 1, 1, 1])
        assert M.accuracy(y_true, y_pred) == pytest.approx(0.75)

    def test_precision_recall_f1_perfect(self) -> None:
        y = np.array([0, 1, 2, 0, 1, 2])
        r = M.precision_recall_f1(y, y, n_classes=3)
        assert r["macro"]["f1"] == pytest.approx(1.0)
        assert r["weighted"]["f1"] == pytest.approx(1.0)

    def test_roc_auc_perfect(self) -> None:
        y_true = np.array([0, 0, 1, 1])
        scores = np.array([0.1, 0.2, 0.8, 0.9])
        auc = M.roc_auc_binary(y_true, scores)
        assert auc == pytest.approx(1.0)

    def test_roc_auc_random_around_half(self) -> None:
        rng = np.random.default_rng(0)
        y = rng.integers(0, 2, size=5000)
        scores = rng.random(5000)
        auc = M.roc_auc_binary(y, scores)
        assert 0.45 < auc < 0.55
