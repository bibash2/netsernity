#!/usr/bin/env python3
"""
NIDS — CLI predictor.

Read flows from a CSV (same schema as the training dataset) and print
predictions. Useful for quick offline scoring without running the API.

Usage:
    python -m scripts.predict --input data/sample_flows.csv
    python -m scripts.predict --input sample.csv --output preds.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.data.generator import CLASS_NAMES, FEATURE_NAMES
from src.inference import InferenceEngine
from src.utils.config import load_config


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="NIDS offline predictor")
    p.add_argument("--config", default="config/config.yaml")
    p.add_argument("--input", required=True, help="Input CSV with flow features")
    p.add_argument("--output", default=None, help="Write predictions to CSV instead of stdout")
    p.add_argument("--json", action="store_true", help="Emit JSON lines on stdout")
    return p.parse_args()


def read_flows(path: Path) -> list[dict]:
    rows: list[dict] = []
    with open(path, "r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            out: dict = {}
            for feat in FEATURE_NAMES:
                val = row.get(feat, 0.0)
                try:
                    out[feat] = float(val)
                except (TypeError, ValueError):
                    out[feat] = 0.0
            rows.append(out)
    return rows


def main() -> int:
    args = parse_args()
    cfg = load_config(args.config)
    engine = InferenceEngine(models_dir=cfg.paths.models_dir)

    flows = read_flows(Path(args.input))
    if not flows:
        print(f"No flows found in {args.input}", file=sys.stderr)
        return 1

    result = engine.predict(flows)
    preds = result["results"] if isinstance(result["results"], list) else [result["results"]]

    if args.output:
        with open(args.output, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["index", "prediction", "is_attack", "confidence", "anomaly_score"])
            for i, p in enumerate(preds):
                writer.writerow([
                    i, p["prediction"], p["is_attack"],
                    f"{p['confidence']:.4f}", f"{p['anomaly_score']:.4f}",
                ])
        print(f"Wrote {len(preds)} predictions to {args.output}")
    elif args.json:
        for i, p in enumerate(preds):
            print(json.dumps({"index": i, **p}))
    else:
        print(f"\n{'idx':>5}  {'prediction':<14}  {'attack':<6}  {'conf':>8}  {'anomaly':>8}")
        print("-" * 55)
        for i, p in enumerate(preds):
            print(
                f"{i:>5}  {p['prediction']:<14}  "
                f"{'yes' if p['is_attack'] else 'no':<6}  "
                f"{p['confidence']:>7.4f}  {p['anomaly_score']:>7.4f}"
            )
        # Summary
        attacks = sum(1 for p in preds if p["is_attack"])
        print(f"\n{attacks}/{len(preds)} flows flagged as attacks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
