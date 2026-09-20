#!/usr/bin/env python3
"""
Compare two sets of NetSentry artifacts on the SAME held-out test split.

Rebuilds the deterministic stratified split the training pipeline used
(same dataset CSV, same test/val sizes, same random_state), so both models
are scored on identical, unseen rows.

Usage:
    python -m scripts.compare_models --old /path/to/old_artifacts --new models_artifacts
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.data import CLASS_NAMES, Preprocessor  # noqa: E402
from src.data.generator import load_dataset_csv  # noqa: E402
from src.models import EnsembleNIDS  # noqa: E402
from src.utils.config import load_config  # noqa: E402


def score(models_dir: Path, X: np.ndarray, y: np.ndarray) -> dict:
    pre = Preprocessor.load(models_dir / "preprocessor.pkl")
    ens = EnsembleNIDS.load(models_dir / "ensemble.pkl")
    pred = ens.predict(pre.transform(X))
    benign = y == 0
    out = {
        "accuracy": float((pred == y).mean()),
        "fpr": float((pred[benign] != 0).mean()) if benign.any() else float("nan"),
        "detection_rate": float((pred[~benign] != 0).mean()) if (~benign).any() else float("nan"),
        "per_class_recall": {},
        "support": {},
    }
    for cid, name in enumerate(CLASS_NAMES):
        m = y == cid
        out["support"][name] = int(m.sum())
        out["per_class_recall"][name] = float((pred[m] == cid).mean()) if m.any() else float("nan")
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Old-vs-new model comparison on one held-out split")
    ap.add_argument("--old", required=True, help="Directory with the previous artifacts")
    ap.add_argument("--new", default="models_artifacts", help="Directory with the new artifacts")
    ap.add_argument("--config", default="config/config.yaml")
    args = ap.parse_args()

    cfg = load_config(args.config)
    X, y = load_dataset_csv(cfg.data.dataset_path)
    _, _, _, _, X_te, y_te = Preprocessor.stratified_split(
        X, y, test_size=cfg.data.test_size, val_size=cfg.data.val_size,
        random_state=cfg.data.random_state,
    )
    print(f"Held-out test rows: {len(y_te):,}  (from {cfg.data.dataset_path})\n")

    old, new = score(Path(args.old), X_te, y_te), score(Path(args.new), X_te, y_te)

    print(f"{'metric':22s} {'old':>10s} {'new':>10s}")
    print("-" * 46)
    for k in ("accuracy", "fpr", "detection_rate"):
        print(f"{k:22s} {old[k]:>10.4f} {new[k]:>10.4f}")
    print(f"\n{'per-class recall':22s} {'old':>10s} {'new':>10s} {'n_test':>8s}")
    print("-" * 56)
    for name in CLASS_NAMES:
        print(f"{name:22s} {old['per_class_recall'][name]:>10.4f} "
              f"{new['per_class_recall'][name]:>10.4f} {new['support'][name]:>8d}")


if __name__ == "__main__":
    main()
