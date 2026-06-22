"""Convenience loaders for generating or reading the network flow dataset."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import numpy as np

from ..utils.logger import get_logger
from .generator import (
    CLASS_NAMES,
    FEATURE_NAMES,
    generate_dataset,
    load_dataset_csv,
    save_dataset_csv,
)

logger = get_logger(__name__)


def load_or_generate(
    path: str | Path,
    n_samples: int = 50_000,
    random_state: int = 42,
    force_regenerate: bool = False,
) -> tuple[np.ndarray, np.ndarray, list[str], list[str]]:
    """Load the dataset from disk if it exists, otherwise generate and save it.

    Returns (X, y, feature_names, class_names).
    """
    path = Path(path)
    if path.exists() and not force_regenerate:
        logger.info("Loading dataset from %s", path)
        X, y = load_dataset_csv(path)
        return X, y, FEATURE_NAMES, CLASS_NAMES

    logger.info("Generating %d synthetic flows into %s", n_samples, path)
    X, y, feats = generate_dataset(n_samples=n_samples, random_state=random_state)
    save_dataset_csv(X, y, path)
    return X, y, feats, CLASS_NAMES
