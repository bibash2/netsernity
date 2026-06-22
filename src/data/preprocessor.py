"""
Data preprocessing — built from scratch.

Pipeline:
    1. Clean: handle +/- inf and NaN values.
    2. Split: stratified train / validation / test partitioning.
    3. Scale: per-feature z-score standardization fit on the training set only
             (prevents test-set leakage).
    4. Feature select: rank features by per-class variance ratio and keep the
                      top-k most informative.

The only dependency is NumPy. We persist fitted artefacts (mean, std, selected
feature indices) so inference and training use identical transforms.
"""

from __future__ import annotations

import pickle
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import numpy as np


@dataclass
class PreprocessorArtifacts:
    feature_names: list[str]
    selected_feature_indices: np.ndarray
    scaler_mean: np.ndarray
    scaler_std: np.ndarray
    n_classes: int
    clip_bounds: tuple[float, float] = (-1e9, 1e9)


class Preprocessor:
    """Fit preprocessing parameters on training data and apply to any new data."""

    def __init__(
        self,
        feature_names: list[str],
        top_k_features: Optional[int] = None,
        clip_bounds: tuple[float, float] = (-1e9, 1e9),
    ) -> None:
        self.feature_names = list(feature_names)
        self.top_k_features = top_k_features
        self.clip_bounds = clip_bounds
        self.artifacts: Optional[PreprocessorArtifacts] = None

    # ------------------------------------------------------------------
    # Data cleaning
    # ------------------------------------------------------------------
    def _clean(self, X: np.ndarray) -> np.ndarray:
        X = np.asarray(X, dtype=np.float64)
        X = np.where(np.isinf(X), np.nan, X)
        # Column-wise median imputation for any remaining NaNs
        if np.isnan(X).any():
            for col in range(X.shape[1]):
                column = X[:, col]
                if np.isnan(column).any():
                    median = float(np.nanmedian(column)) if np.any(~np.isnan(column)) else 0.0
                    X[np.isnan(column), col] = median
        # Clip extreme outliers
        lo, hi = self.clip_bounds
        X = np.clip(X, lo, hi)
        return X

    # ------------------------------------------------------------------
    # Feature selection — ANOVA F-ratio style (ratio of between-class to
    # within-class variance). Fully implemented from scratch.
    # ------------------------------------------------------------------
    @staticmethod
    def _score_features(X: np.ndarray, y: np.ndarray) -> np.ndarray:
        n_samples, n_features = X.shape
        classes = np.unique(y)
        overall_mean = X.mean(axis=0)

        between_var = np.zeros(n_features)
        within_var = np.zeros(n_features)
        for c in classes:
            mask = y == c
            nc = int(mask.sum())
            if nc < 2:
                continue
            class_mean = X[mask].mean(axis=0)
            between_var += nc * (class_mean - overall_mean) ** 2
            within_var += ((X[mask] - class_mean) ** 2).sum(axis=0)

        k = max(len(classes) - 1, 1)
        within_dof = max(n_samples - len(classes), 1)
        f_scores = (between_var / k) / (within_var / within_dof + 1e-12)
        return f_scores

    # ------------------------------------------------------------------
    # Stratified train/val/test split
    # ------------------------------------------------------------------
    @staticmethod
    def stratified_split(
        X: np.ndarray,
        y: np.ndarray,
        test_size: float = 0.2,
        val_size: float = 0.1,
        random_state: Optional[int] = 42,
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        rng = np.random.default_rng(random_state)
        classes = np.unique(y)
        train_idx: list[int] = []
        val_idx: list[int] = []
        test_idx: list[int] = []
        for c in classes:
            indices = np.where(y == c)[0]
            rng.shuffle(indices)
            n = len(indices)
            n_test = int(round(n * test_size))
            n_val = int(round(n * val_size))
            test_idx.extend(indices[:n_test].tolist())
            val_idx.extend(indices[n_test : n_test + n_val].tolist())
            train_idx.extend(indices[n_test + n_val :].tolist())

        train_idx_np = np.array(train_idx, dtype=np.int64)
        val_idx_np = np.array(val_idx, dtype=np.int64)
        test_idx_np = np.array(test_idx, dtype=np.int64)
        # Re-shuffle within each split so class order doesn't bleed into batches.
        rng.shuffle(train_idx_np)
        rng.shuffle(val_idx_np)
        rng.shuffle(test_idx_np)

        return (
            X[train_idx_np], y[train_idx_np],
            X[val_idx_np], y[val_idx_np],
            X[test_idx_np], y[test_idx_np],
        )

    # ------------------------------------------------------------------
    # Fit / transform
    # ------------------------------------------------------------------
    def fit(self, X_train: np.ndarray, y_train: np.ndarray) -> "Preprocessor":
        X_clean = self._clean(X_train)

        # Feature selection
        if self.top_k_features and self.top_k_features < X_clean.shape[1]:
            scores = self._score_features(X_clean, y_train)
            selected = np.argsort(-scores)[: self.top_k_features]
            selected.sort()  # keep original feature order for readability
        else:
            selected = np.arange(X_clean.shape[1])

        X_sel = X_clean[:, selected]
        mean = X_sel.mean(axis=0)
        std = X_sel.std(axis=0)
        std = np.where(std < 1e-8, 1.0, std)  # avoid divide-by-zero

        self.artifacts = PreprocessorArtifacts(
            feature_names=self.feature_names,
            selected_feature_indices=selected,
            scaler_mean=mean,
            scaler_std=std,
            n_classes=int(y_train.max()) + 1,
            clip_bounds=self.clip_bounds,
        )
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        if self.artifacts is None:
            raise RuntimeError("Preprocessor is not fitted.")
        X_clean = self._clean(X)
        X_sel = X_clean[:, self.artifacts.selected_feature_indices]
        return (X_sel - self.artifacts.scaler_mean) / self.artifacts.scaler_std

    def fit_transform(self, X_train: np.ndarray, y_train: np.ndarray) -> np.ndarray:
        self.fit(X_train, y_train)
        return self.transform(X_train)

    def selected_feature_names(self) -> list[str]:
        if self.artifacts is None:
            raise RuntimeError("Preprocessor is not fitted.")
        return [self.feature_names[i] for i in self.artifacts.selected_feature_indices]

    def save(self, path: str | Path) -> None:
        if self.artifacts is None:
            raise RuntimeError("Nothing to save — preprocessor not fitted.")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(self, f, protocol=pickle.HIGHEST_PROTOCOL)

    @classmethod
    def load(cls, path: str | Path) -> "Preprocessor":
        with open(path, "rb") as f:
            obj = pickle.load(f)
        if not isinstance(obj, cls):
            raise TypeError(f"Loaded object is not a Preprocessor: {type(obj)}")
        return obj
