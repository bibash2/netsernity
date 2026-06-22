"""
Random Forest Classifier — built from scratch on top of our DecisionTree.

Implements:
    - Bootstrap aggregation (bagging) of decision trees
    - Feature subsampling at each split via max_features="sqrt"
    - Out-of-bag (OOB) error estimation
    - Parallel training across trees using multiprocessing
    - Soft-vote class probability aggregation

Only depends on NumPy and Python's standard library.

Reference: Breiman, "Random Forests" (2001).
"""

from __future__ import annotations

import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Optional

import numpy as np

from .base import BaseModel
from .decision_tree import DecisionTreeClassifier


def _train_single_tree(
    args: tuple[np.ndarray, np.ndarray, dict, int, int]
) -> tuple[DecisionTreeClassifier, np.ndarray]:
    """Worker function used by the process pool to train one tree.

    Args are packed as a tuple so it can be pickled across process boundaries.
    Returns (trained_tree, oob_sample_indices).
    """
    X, y, tree_params, seed, n_samples = args
    rng = np.random.default_rng(seed)
    # Bootstrap sample with replacement
    indices = rng.integers(0, n_samples, size=n_samples)
    oob_mask = np.ones(n_samples, dtype=bool)
    oob_mask[indices] = False
    oob_indices = np.where(oob_mask)[0]

    X_boot = X[indices]
    y_boot = y[indices]

    tree = DecisionTreeClassifier(**tree_params, random_state=seed)
    tree.fit(X_boot, y_boot)
    return tree, oob_indices


class RandomForestClassifier(BaseModel):
    """Random Forest classifier built from first principles.

    Parameters
    ----------
    n_estimators : int
        Number of trees in the forest.
    max_depth : int
        Maximum depth of each tree.
    min_samples_split : int
        Minimum samples required to split.
    min_samples_leaf : int
        Minimum samples per leaf.
    max_features : {"sqrt"} or int
        Number of features considered at each split.
    criterion : {"gini", "entropy"}
        Split quality measure.
    oob_score : bool
        Whether to compute an out-of-bag score after training.
    n_jobs : int
        Number of parallel worker processes (1 = sequential).
    random_state : int or None
        Seed for reproducibility.
    verbose : bool
        Print training progress.
    """

    def __init__(
        self,
        n_estimators: int = 100,
        max_depth: int = 15,
        min_samples_split: int = 20,
        min_samples_leaf: int = 5,
        max_features: object = "sqrt",
        criterion: str = "gini",
        oob_score: bool = True,
        n_jobs: int = 1,
        random_state: Optional[int] = None,
        verbose: bool = False,
    ) -> None:
        super().__init__()
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.min_samples_leaf = min_samples_leaf
        self.max_features = max_features
        self.criterion = criterion
        self.oob_score = oob_score
        self.n_jobs = n_jobs
        self.random_state = random_state
        self.verbose = verbose

        self.trees_: list[DecisionTreeClassifier] = []
        self.oob_indices_: list[np.ndarray] = []
        self.oob_score_: Optional[float] = None
        self.feature_importances_: Optional[np.ndarray] = None

    def _tree_params(self) -> dict:
        return {
            "max_depth": self.max_depth,
            "min_samples_split": self.min_samples_split,
            "min_samples_leaf": self.min_samples_leaf,
            "max_features": self.max_features,
            "criterion": self.criterion,
        }

    def fit(self, X: np.ndarray, y: np.ndarray) -> "RandomForestClassifier":
        X = np.asarray(X, dtype=np.float64)
        y = np.asarray(y, dtype=np.int64)
        if X.shape[0] != y.shape[0]:
            raise ValueError("X and y have different numbers of samples")

        start = time.time()
        self.n_features_ = X.shape[1]
        self.classes_ = np.unique(y)
        self.n_classes_ = int(self.classes_.max()) + 1

        base_seed = self.random_state if self.random_state is not None else np.random.randint(0, 2**31 - 1)
        master_rng = np.random.default_rng(base_seed)
        tree_seeds = master_rng.integers(0, 2**31 - 1, size=self.n_estimators).tolist()

        tree_params = self._tree_params()
        n_samples = X.shape[0]

        if self.n_jobs == 1:
            # Sequential training — simpler to debug and avoids IPC overhead.
            for idx, seed in enumerate(tree_seeds):
                tree, oob = _train_single_tree((X, y, tree_params, int(seed), n_samples))
                self.trees_.append(tree)
                self.oob_indices_.append(oob)
                if self.verbose and (idx + 1) % max(1, self.n_estimators // 10) == 0:
                    print(f"  [RF] trained {idx + 1}/{self.n_estimators} trees")
        else:
            # Parallel training across CPU cores.
            work = [(X, y, tree_params, int(seed), n_samples) for seed in tree_seeds]
            with ProcessPoolExecutor(max_workers=self.n_jobs) as pool:
                futures = [pool.submit(_train_single_tree, w) for w in work]
                for idx, fut in enumerate(as_completed(futures)):
                    tree, oob = fut.result()
                    self.trees_.append(tree)
                    self.oob_indices_.append(oob)
                    if self.verbose and (idx + 1) % max(1, self.n_estimators // 10) == 0:
                        print(f"  [RF] trained {idx + 1}/{self.n_estimators} trees")

        if self.oob_score:
            self.oob_score_ = self._compute_oob_score(X, y)

        self.feature_importances_ = self._compute_feature_importances()
        self.is_fitted = True
        self.training_time_ = time.time() - start
        return self

    def _compute_oob_score(self, X: np.ndarray, y: np.ndarray) -> float:
        """Accuracy on samples not seen by each tree during training."""
        n_samples = X.shape[0]
        oob_proba = np.zeros((n_samples, self.n_classes_), dtype=np.float64)
        oob_counts = np.zeros(n_samples, dtype=np.int64)

        for tree, oob_idx in zip(self.trees_, self.oob_indices_):
            if len(oob_idx) == 0:
                continue
            proba = tree.predict_proba(X[oob_idx])
            oob_proba[oob_idx] += proba
            oob_counts[oob_idx] += 1

        valid = oob_counts > 0
        if not valid.any():
            return float("nan")
        oob_pred = np.argmax(oob_proba[valid], axis=1)
        return float(np.mean(oob_pred == y[valid]))

    def _compute_feature_importances(self) -> np.ndarray:
        """Aggregate feature-usage counts across all trees as a rough importance measure.

        A more formal approach (mean decrease in impurity) would weight by the
        impurity reduction at each split; we approximate it here with split counts
        weighted by node sample size, which tracks the MDI metric closely.
        """
        importances = np.zeros(self.n_features_, dtype=np.float64)
        total_samples_seen = 0

        for tree in self.trees_:
            stack = [tree.root_]
            while stack:
                node = stack.pop()
                if node is None or node.is_leaf:
                    continue
                importances[node.feature_index] += node.n_samples * max(node.impurity, 0.0)
                total_samples_seen += node.n_samples
                stack.append(node.left)
                stack.append(node.right)

        if importances.sum() > 0:
            importances = importances / importances.sum()
        return importances

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        self._check_fitted()
        X = self._validate_input(X)
        # Soft voting: average probabilities across all trees.
        accum = np.zeros((X.shape[0], self.n_classes_), dtype=np.float64)
        for tree in self.trees_:
            accum += tree.predict_proba(X)
        accum /= len(self.trees_)
        return accum

    def predict(self, X: np.ndarray) -> np.ndarray:
        proba = self.predict_proba(X)
        return np.argmax(proba, axis=1).astype(np.int64)
