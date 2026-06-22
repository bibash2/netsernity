"""
Decision Tree Classifier — built from scratch.

Implements the CART algorithm (Classification and Regression Trees) with:
    - Gini impurity and entropy as splitting criteria
    - Best-split search over random feature subsets (for forest use)
    - Pre-pruning via max_depth, min_samples_split, min_samples_leaf
    - Vectorized split evaluation for efficiency on large datasets

Only depends on NumPy.

References: Breiman et al., "Classification and Regression Trees" (1984).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import numpy as np

from .base import BaseModel


@dataclass
class TreeNode:
    """A single node in the decision tree."""

    # Internal node attributes
    feature_index: Optional[int] = None
    threshold: Optional[float] = None
    left: Optional["TreeNode"] = None
    right: Optional["TreeNode"] = None

    # Leaf node attributes
    is_leaf: bool = False
    class_distribution: np.ndarray = field(default_factory=lambda: np.array([]))
    predicted_class: int = -1

    # Diagnostics
    n_samples: int = 0
    impurity: float = 0.0
    depth: int = 0


class DecisionTreeClassifier(BaseModel):
    """CART-style decision tree classifier implemented from first principles.

    Parameters
    ----------
    max_depth : int
        Maximum depth of the tree. None means unlimited.
    min_samples_split : int
        Minimum number of samples required to split an internal node.
    min_samples_leaf : int
        Minimum number of samples required at a leaf node.
    criterion : {"gini", "entropy"}
        The function to measure the quality of a split.
    max_features : int or "sqrt" or None
        Number of features to consider at each split. Used by Random Forest.
    random_state : int or None
        Seed for reproducibility when max_features is not None.
    """

    def __init__(
        self,
        max_depth: Optional[int] = 15,
        min_samples_split: int = 20,
        min_samples_leaf: int = 5,
        criterion: str = "gini",
        max_features: Optional[object] = None,
        random_state: Optional[int] = None,
    ) -> None:
        super().__init__()
        if criterion not in ("gini", "entropy"):
            raise ValueError(f"Unknown criterion: {criterion}")
        self.max_depth = max_depth if max_depth is not None else 10**9
        self.min_samples_split = min_samples_split
        self.min_samples_leaf = min_samples_leaf
        self.criterion = criterion
        self.max_features = max_features
        self.random_state = random_state
        self.root_: Optional[TreeNode] = None
        self._rng = np.random.default_rng(random_state)

    # ------------------------------------------------------------------
    # Impurity measures
    # ------------------------------------------------------------------
    @staticmethod
    def _gini(class_counts: np.ndarray) -> float:
        total = class_counts.sum()
        if total == 0:
            return 0.0
        probs = class_counts / total
        return float(1.0 - np.sum(probs * probs))

    @staticmethod
    def _entropy(class_counts: np.ndarray) -> float:
        total = class_counts.sum()
        if total == 0:
            return 0.0
        probs = class_counts / total
        # Avoid log(0) by masking zero probabilities
        nz = probs[probs > 0]
        return float(-np.sum(nz * np.log2(nz)))

    def _impurity(self, class_counts: np.ndarray) -> float:
        if self.criterion == "gini":
            return self._gini(class_counts)
        return self._entropy(class_counts)

    # ------------------------------------------------------------------
    # Split search
    # ------------------------------------------------------------------
    def _compute_class_counts(self, y: np.ndarray) -> np.ndarray:
        counts = np.zeros(self.n_classes_, dtype=np.int64)
        values, occurrences = np.unique(y, return_counts=True)
        for v, c in zip(values, occurrences):
            counts[int(v)] = c
        return counts

    def _select_feature_indices(self, n_features: int) -> np.ndarray:
        if self.max_features is None:
            return np.arange(n_features)
        if self.max_features == "sqrt":
            k = max(1, int(np.sqrt(n_features)))
        elif isinstance(self.max_features, int):
            k = min(self.max_features, n_features)
        else:
            raise ValueError(f"Invalid max_features: {self.max_features}")
        return self._rng.choice(n_features, size=k, replace=False)

    def _best_split(
        self, X: np.ndarray, y: np.ndarray
    ) -> tuple[Optional[int], Optional[float], float]:
        """Find the (feature, threshold) pair that best splits (X, y).

        Returns (feature_index, threshold, information_gain). Returns
        (None, None, 0.0) when no acceptable split exists.
        """
        n_samples, n_features = X.shape
        parent_counts = self._compute_class_counts(y)
        parent_impurity = self._impurity(parent_counts)

        best_gain = 0.0
        best_feature: Optional[int] = None
        best_threshold: Optional[float] = None

        feature_indices = self._select_feature_indices(n_features)

        for feat in feature_indices:
            column = X[:, feat]
            # Sort once per feature so we can sweep thresholds in O(n)
            sort_idx = np.argsort(column, kind="quicksort")
            x_sorted = column[sort_idx]
            y_sorted = y[sort_idx]

            # Consider only unique midpoints between consecutive distinct values.
            # We walk from left to right, maintaining running class counts.
            left_counts = np.zeros(self.n_classes_, dtype=np.int64)
            right_counts = parent_counts.copy()

            for i in range(1, n_samples):
                c = int(y_sorted[i - 1])
                left_counts[c] += 1
                right_counts[c] -= 1

                # Skip when the split does not respect min_samples_leaf
                if i < self.min_samples_leaf or (n_samples - i) < self.min_samples_leaf:
                    continue
                # Skip when consecutive x values are identical (no valid split point)
                if x_sorted[i] == x_sorted[i - 1]:
                    continue

                left_imp = self._impurity(left_counts)
                right_imp = self._impurity(right_counts)
                weighted = (i / n_samples) * left_imp + ((n_samples - i) / n_samples) * right_imp
                gain = parent_impurity - weighted

                if gain > best_gain:
                    best_gain = gain
                    best_feature = int(feat)
                    best_threshold = float((x_sorted[i - 1] + x_sorted[i]) / 2.0)

        return best_feature, best_threshold, best_gain

    # ------------------------------------------------------------------
    # Tree construction (iterative to avoid recursion limits)
    # ------------------------------------------------------------------
    def _build_tree(self, X: np.ndarray, y: np.ndarray) -> TreeNode:
        root = TreeNode(depth=0, n_samples=len(y))
        root.class_distribution = self._compute_class_counts(y)
        root.impurity = self._impurity(root.class_distribution)

        # Stack holds (node, X_subset, y_subset)
        stack: list[tuple[TreeNode, np.ndarray, np.ndarray]] = [(root, X, y)]

        while stack:
            node, X_sub, y_sub = stack.pop()
            counts = node.class_distribution

            # Stopping criteria
            if (
                node.depth >= self.max_depth
                or len(y_sub) < self.min_samples_split
                or node.impurity == 0.0
            ):
                self._make_leaf(node)
                continue

            feature, threshold, gain = self._best_split(X_sub, y_sub)
            if feature is None or gain <= 1e-12:
                self._make_leaf(node)
                continue

            # Partition the data
            left_mask = X_sub[:, feature] <= threshold
            right_mask = ~left_mask
            if left_mask.sum() < self.min_samples_leaf or right_mask.sum() < self.min_samples_leaf:
                self._make_leaf(node)
                continue

            # Set up internal node
            node.feature_index = feature
            node.threshold = threshold

            left_child = TreeNode(depth=node.depth + 1, n_samples=int(left_mask.sum()))
            left_child.class_distribution = self._compute_class_counts(y_sub[left_mask])
            left_child.impurity = self._impurity(left_child.class_distribution)

            right_child = TreeNode(depth=node.depth + 1, n_samples=int(right_mask.sum()))
            right_child.class_distribution = self._compute_class_counts(y_sub[right_mask])
            right_child.impurity = self._impurity(right_child.class_distribution)

            node.left = left_child
            node.right = right_child

            stack.append((right_child, X_sub[right_mask], y_sub[right_mask]))
            stack.append((left_child, X_sub[left_mask], y_sub[left_mask]))

        return root

    @staticmethod
    def _make_leaf(node: TreeNode) -> None:
        node.is_leaf = True
        node.predicted_class = int(np.argmax(node.class_distribution))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def fit(self, X: np.ndarray, y: np.ndarray) -> "DecisionTreeClassifier":
        import time

        X = np.asarray(X, dtype=np.float64)
        y = np.asarray(y, dtype=np.int64)
        if X.shape[0] != y.shape[0]:
            raise ValueError("X and y have different numbers of samples")
        start = time.time()

        self.n_features_ = X.shape[1]
        self.classes_ = np.unique(y)
        self.n_classes_ = int(self.classes_.max()) + 1  # assumes 0-indexed labels
        self.root_ = self._build_tree(X, y)
        self.is_fitted = True
        self.training_time_ = time.time() - start
        return self

    def _predict_single(self, x: np.ndarray) -> TreeNode:
        node = self.root_
        assert node is not None
        while not node.is_leaf:
            if x[node.feature_index] <= node.threshold:
                node = node.left  # type: ignore[assignment]
            else:
                node = node.right  # type: ignore[assignment]
            assert node is not None
        return node

    def predict(self, X: np.ndarray) -> np.ndarray:
        self._check_fitted()
        X = self._validate_input(X)
        return np.array([self._predict_single(x).predicted_class for x in X], dtype=np.int64)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        self._check_fitted()
        X = self._validate_input(X)
        probas = np.zeros((X.shape[0], self.n_classes_), dtype=np.float64)
        for i, x in enumerate(X):
            leaf = self._predict_single(x)
            total = leaf.class_distribution.sum()
            if total > 0:
                # Laplace smoothing protects against pathological leaves
                probas[i] = (leaf.class_distribution + 1) / (total + self.n_classes_)
            else:
                probas[i] = np.full(self.n_classes_, 1.0 / self.n_classes_)
        return probas

    def tree_depth(self) -> int:
        """Return the depth of the learned tree."""
        self._check_fitted()
        max_d = 0
        stack = [self.root_]
        while stack:
            node = stack.pop()
            if node is None:
                continue
            if node.depth > max_d:
                max_d = node.depth
            if not node.is_leaf:
                stack.append(node.left)
                stack.append(node.right)
        return max_d

    def n_leaves(self) -> int:
        """Return the number of leaves in the tree."""
        self._check_fitted()
        count = 0
        stack = [self.root_]
        while stack:
            node = stack.pop()
            if node is None:
                continue
            if node.is_leaf:
                count += 1
            else:
                stack.append(node.left)
                stack.append(node.right)
        return count
