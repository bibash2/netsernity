"""
Isolation Forest — built from scratch.

Detects anomalies (e.g. zero-day attacks) by measuring how easily each sample
can be isolated by random partitioning. Points that require few splits to isolate
are anomalous.

Implemented strictly from the original algorithm in:
    Liu, Ting, Zhou, "Isolation Forest" (ICDM 2008).

Only uses NumPy.
"""

from __future__ import annotations

import time
from typing import Optional

import numpy as np


class _ITreeNode:
    __slots__ = ("feature_index", "threshold", "left", "right", "size", "is_external")

    def __init__(self) -> None:
        self.feature_index: int = -1
        self.threshold: float = 0.0
        self.left: Optional["_ITreeNode"] = None
        self.right: Optional["_ITreeNode"] = None
        self.size: int = 0
        self.is_external: bool = False


def _average_path_length(n: int) -> float:
    """Expected path length of an unsuccessful search in a binary search tree."""
    if n <= 1:
        return 0.0
    # Harmonic number approximation
    return 2.0 * (np.log(n - 1) + 0.5772156649) - (2.0 * (n - 1) / n)


class IsolationForest:
    """Isolation Forest anomaly detector.

    Produces anomaly scores in [0, 1] where:
        score near 1  => likely anomaly
        score near 0  => likely normal

    Decision rule: `predict(X)` returns 1 for normal, -1 for anomaly — matching
    the sklearn convention, but implemented here from scratch.

    Parameters
    ----------
    n_estimators : int
        Number of isolation trees.
    subsample_size : int
        Number of samples drawn to build each tree (psi in the paper).
    contamination : float
        Expected proportion of anomalies. Used to set the decision threshold.
    random_state : int or None
        Seed.
    """

    def __init__(
        self,
        n_estimators: int = 100,
        subsample_size: int = 256,
        contamination: float = 0.1,
        random_state: Optional[int] = None,
    ) -> None:
        self.n_estimators = n_estimators
        self.subsample_size = subsample_size
        self.contamination = contamination
        self.random_state = random_state
        self._rng = np.random.default_rng(random_state)

        self.trees_: list[_ITreeNode] = []
        self.height_limit_: int = 0
        self.threshold_: float = 0.5
        self.training_time_: float = 0.0
        self.is_fitted: bool = False

    def _build_tree(self, X: np.ndarray, current_height: int, height_limit: int) -> _ITreeNode:
        node = _ITreeNode()
        n = X.shape[0]
        n_features = X.shape[1]

        if current_height >= height_limit or n <= 1:
            node.is_external = True
            node.size = n
            return node

        # Pick a random feature that has variation in the current subset
        tried = 0
        feature_index = int(self._rng.integers(0, n_features))
        col = X[:, feature_index]
        while col.min() == col.max() and tried < n_features:
            feature_index = int(self._rng.integers(0, n_features))
            col = X[:, feature_index]
            tried += 1

        if col.min() == col.max():
            # All samples identical in every feature — make a leaf.
            node.is_external = True
            node.size = n
            return node

        threshold = float(self._rng.uniform(col.min(), col.max()))
        left_mask = col < threshold
        right_mask = ~left_mask

        node.feature_index = feature_index
        node.threshold = threshold
        node.is_external = False
        node.left = self._build_tree(X[left_mask], current_height + 1, height_limit)
        node.right = self._build_tree(X[right_mask], current_height + 1, height_limit)
        return node

    def _path_length(self, x: np.ndarray, node: _ITreeNode, current_height: int) -> float:
        while not node.is_external:
            if x[node.feature_index] < node.threshold:
                node = node.left  # type: ignore[assignment]
            else:
                node = node.right  # type: ignore[assignment]
            current_height += 1
        return current_height + _average_path_length(node.size)

    def fit(self, X: np.ndarray) -> "IsolationForest":
        start = time.time()
        X = np.asarray(X, dtype=np.float64)
        n = X.shape[0]
        psi = min(self.subsample_size, n)
        self.height_limit_ = int(np.ceil(np.log2(max(psi, 2))))
        self.trees_ = []

        for _ in range(self.n_estimators):
            idx = self._rng.choice(n, size=psi, replace=False)
            sample = X[idx]
            tree = self._build_tree(sample, 0, self.height_limit_)
            self.trees_.append(tree)

        self.is_fitted = True

        # Calibrate threshold using the training data and the contamination rate.
        scores = self.anomaly_score(X)
        self.threshold_ = float(np.quantile(scores, 1.0 - self.contamination))
        self.training_time_ = time.time() - start
        return self

    def anomaly_score(self, X: np.ndarray) -> np.ndarray:
        if not self.is_fitted:
            raise RuntimeError("IsolationForest is not fitted yet.")
        X = np.asarray(X, dtype=np.float64)
        if X.ndim == 1:
            X = X.reshape(1, -1)

        avg_path = _average_path_length(self.subsample_size)
        scores = np.zeros(X.shape[0], dtype=np.float64)
        for i, x in enumerate(X):
            path_sum = 0.0
            for tree in self.trees_:
                path_sum += self._path_length(x, tree, 0)
            mean_path = path_sum / len(self.trees_)
            # Score is 2^(-E[h(x)]/c(n))
            scores[i] = 2.0 ** (-mean_path / avg_path)
        return scores

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Return 1 for normal samples and -1 for anomalies."""
        scores = self.anomaly_score(X)
        return np.where(scores >= self.threshold_, -1, 1).astype(np.int64)

    def is_anomaly(self, X: np.ndarray) -> np.ndarray:
        """Return boolean array — True means anomalous."""
        return self.predict(X) == -1
