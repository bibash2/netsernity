#!/usr/bin/env python3
"""
NIDS — training pipeline entry point.

Runs the end-to-end training workflow and writes all artifacts to disk.

Usage:
    python -m scripts.train_pipeline [--config config/config.yaml] [--samples N]

Env var overrides are supported. For example, to train on a smaller dataset:
    NIDS_DATA__N_SAMPLES=5000 python -m scripts.train_pipeline
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Make src importable whether run as module or as a script
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.training import TrainingPipeline
from src.utils.config import ensure_directories, load_config
from src.utils.logger import configure_logging, get_logger


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="NIDS training pipeline")
    p.add_argument("--config", default="config/config.yaml", help="YAML config path")
    p.add_argument("--samples", type=int, default=None, help="Override data.n_samples")
    p.add_argument("--quiet", action="store_true", help="Human console output only")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    cfg = load_config(args.config)
    if args.samples is not None:
        cfg.data.n_samples = args.samples
    ensure_directories(cfg)

    configure_logging(
        level=cfg.logging.level,
        file_path=cfg.logging.file,
        json_format=not args.quiet,
        rotate_bytes=cfg.logging.rotate_bytes,
        backups=cfg.logging.backups,
    )
    log = get_logger("nids.train")

    log.info("=" * 70)
    log.info("NIDS Training Pipeline")
    log.info("Samples: %d  |  Models dir: %s", cfg.data.n_samples, cfg.paths.models_dir)
    log.info("=" * 70)

    try:
        pipeline = TrainingPipeline(cfg)
        report = pipeline.run()
    except Exception as exc:
        log.exception("Training failed: %s", exc)
        return 1

    # Console summary
    print()
    print("=" * 70)
    print("TRAINING COMPLETE")
    print("=" * 70)
    for name, m in report.get("models", {}).items():
        acc = m.get("accuracy", 0.0)
        f1 = m.get("macro_f1") or m.get("binary_f1") or 0.0
        fpr = m.get("false_positive_rate", 0.0)
        dr = m.get("detection_rate", 0.0)
        t = m.get("training_time_sec", 0.0)
        lat = m.get("avg_latency_ms_per_sample", 0.0)
        print(f"  {name:<20}  acc={acc:.4f}  f1={f1:.4f}  FPR={fpr:.4f}  DR={dr:.4f}  train={t:>6.1f}s")
    print(f"  {'total':<20}  {report.get('total_training_time_sec', 0):.1f}s")
    print()
    print(f"Artifacts saved to: {cfg.paths.models_dir}/")
    print(f"Metrics report:      {cfg.paths.reports_dir}/training_metrics.json")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
