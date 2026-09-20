#!/usr/bin/env python3
"""
Pick the RF/MLP soft-voting weights on the VALIDATION split, never on test.

Rebuilds the deterministic train/val/test split the pipeline used, scores a
small weight grid on val (macro-F1, so rare classes count), writes the best
weights into the saved ensemble + config.yaml, and re-scores the held-out
test split with the pipeline's own evaluator so training_metrics.json stays
consistent.

Usage:
    python -m scripts.tune_ensemble            # tune + save
    python -m scripts.tune_ensemble --dry-run  # only print the grid
"""

from __future__ import annotations

import argparse
import json
import pickle
import re
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.data import CLASS_NAMES, Preprocessor  # noqa: E402
from src.data.generator import load_dataset_csv  # noqa: E402
from src.models import EnsembleNIDS  # noqa: E402
from src.training.trainer import TrainingPipeline  # noqa: E402
from src.utils import metrics  # noqa: E402
from src.utils.config import load_config  # noqa: E402

GRID = (0.5, 0.6, 0.7, 0.8, 0.9, 1.0)  # RF weight; MLP gets the remainder


def main() -> None:
    ap = argparse.ArgumentParser(description="Tune ensemble weights on the validation split")
    ap.add_argument("--config", default="config/config.yaml")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    cfg = load_config(args.config)
    models_dir = Path(cfg.paths.models_dir)
    pre = Preprocessor.load(models_dir / "preprocessor.pkl")
    ens = EnsembleNIDS.load(models_dir / "ensemble.pkl")

    X, y = load_dataset_csv(cfg.data.dataset_path)
    _, _, X_val, y_val, X_te, y_te = Preprocessor.stratified_split(
        X, y, test_size=cfg.data.test_size, val_size=cfg.data.val_size,
        random_state=cfg.data.random_state,
    )
    X_val_s, X_te_s = pre.transform(X_val), pre.transform(X_te)
    print(f"val rows: {len(y_val):,}   test rows: {len(y_te):,}")

    current = (ens.rf_weight, ens.mlp_weight)
    print(f"\n{'rf_w':>6s} {'mlp_w':>6s} {'val macroF1':>12s} {'val acc':>9s} {'val FPR':>9s}")
    results = {}
    for rf_w in GRID:
        ens.rf_weight, ens.mlp_weight = rf_w, round(1.0 - rf_w, 2)
        pred = ens.predict(X_val_s)
        rpt = metrics.precision_recall_f1(y_val, pred)
        results[rf_w] = rpt["macro"]["f1"]
        print(f"{rf_w:6.2f} {ens.mlp_weight:6.2f} {rpt['macro']['f1']:12.4f} "
              f"{metrics.accuracy(y_val, pred):9.4f} {metrics.false_positive_rate(y_val, pred):9.4f}")

    best_rf = max(results, key=results.get)
    cur_f1 = results.get(round(current[0] / (current[0] + current[1]), 2))
    print(f"\ncurrent weights rf={current[0]} mlp={current[1]}  ->  best on val: rf={best_rf} "
          f"mlp={round(1 - best_rf, 2)} (macroF1 {results[best_rf]:.4f}"
          + (f" vs {cur_f1:.4f})" if cur_f1 is not None else ")"))

    if args.dry_run or best_rf == round(current[0] / (current[0] + current[1]), 2):
        ens.rf_weight, ens.mlp_weight = current
        print("no change" if not args.dry_run else "dry run — nothing written")
        return

    ens.rf_weight, ens.mlp_weight = best_rf, round(1.0 - best_rf, 2)
    ens.save(models_dir / "ensemble.pkl")

    # keep config in sync so a retrain reproduces the tuned ensemble
    cfg_path = Path(args.config)
    text = cfg_path.read_text()
    text = re.sub(r"ensemble_rf_weight:\s*[0-9.]+", f"ensemble_rf_weight: {ens.rf_weight}", text)
    text = re.sub(r"ensemble_mlp_weight:\s*[0-9.]+", f"ensemble_mlp_weight: {ens.mlp_weight}", text)
    cfg_path.write_text(text)

    # re-score TEST with the pipeline's evaluator and merge into the report
    with open(models_dir / "isolation_forest.pkl", "rb") as f:
        iso = pickle.load(f)
    report_path = Path(cfg.paths.reports_dir) / "training_metrics.json"
    report = json.loads(report_path.read_text())
    fresh = TrainingPipeline(cfg)._evaluate_all(ens.rf, ens.mlp, iso, ens, X_te_s, y_te, CLASS_NAMES)
    report["models"]["ensemble"] = fresh["models"]["ensemble"]
    report["ensemble_weights"] = {"rf": ens.rf_weight, "mlp": ens.mlp_weight, "tuned_on": "validation split"}
    report_path.write_text(json.dumps(report, indent=2))

    e = fresh["models"]["ensemble"]
    print(f"\nsaved ensemble.pkl + config.yaml (rf={ens.rf_weight}, mlp={ens.mlp_weight})")
    print(f"test: acc={e['accuracy']:.4f} macroF1={e['macro_f1']:.4f} "
          f"FPR={e['false_positive_rate']:.4f} DR={e['detection_rate']:.4f}")
    for cid, pc in sorted(e["per_class"].items(), key=lambda kv: int(kv[0])):
        print(f"  {CLASS_NAMES[int(cid)]:14s} recall={pc['recall']:.3f} f1={pc['f1']:.3f} n={pc['support']}")


if __name__ == "__main__":
    main()
