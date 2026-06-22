"""
Base abstract class for all NIDS models.

All models implement a common interface: fit, predict, predict_proba, save, load.
This allows models to be used interchangeably in the ensemble.
"""

from __future__ import annotations

import pickle
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import numpy as np


class BaseModel(ABC):
    """Abstract base class for all from-scratch classifiers.

    Subclasses must implement fit, predict, and predict_proba.
    """

    def __init__(self) -> None:
        self.is_fitted: bool = False
        self.n_features_: int | None = None
        self.classes_: np.ndarray | None = None
        self.training_time_: float = 0.0

    @abstractmethod
    def fit(self, X: np.ndarray, y: np.ndarray) -> "BaseModel":
        """Train the model on (X, y)."""
        raise NotImplementedError

    @abstractmethod
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Return hard class predictions for X."""
        raise NotImplementedError

    @abstractmethod
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Return class probability matrix for X of shape (n_samples, n_classes)."""
        raise NotImplementedError

    def _check_fitted(self) -> None:
        if not self.is_fitted:
            raise RuntimeError(
                f"{self.__class__.__name__} is not fitted yet. Call .fit() first."
            )

    def _validate_input(self, X: np.ndarray) -> np.ndarray:
        X = np.asarray(X, dtype=np.float64)
        if X.ndim == 1:
            X = X.reshape(1, -1)
        if self.n_features_ is not None and X.shape[1] != self.n_features_:
            raise ValueError(
                f"Expected {self.n_features_} features, got {X.shape[1]}"
            )
        return X

    def save(self, path: str | Path) -> None:
        """Pickle the model to disk."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(self, f, protocol=pickle.HIGHEST_PROTOCOL)

    @classmethod
    def load(cls, path: str | Path) -> "BaseModel":
        """Load a pickled model from disk."""
        with open(path, "rb") as f:
            obj: Any = pickle.load(f)
        if not isinstance(obj, cls):
            # Allow loading of any subclass
            if not isinstance(obj, BaseModel):
                raise TypeError(f"Loaded object is not a BaseModel: {type(obj)}")
        return obj

    def __repr__(self) -> str:
        status = "fitted" if self.is_fitted else "not fitted"
        return f"{self.__class__.__name__}({status})"
