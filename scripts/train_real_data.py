"""
Train NetSentry on real CIC-IDS2017 / CIC-IDS2018 datasets.

Usage:
    # Train on downloaded CIC-IDS2017 CSVs
    python -m scripts.train_real_data --dataset-dir data/cic-ids2017/

    # With custom class limits
    python -m scripts.train_real_data --dataset-dir data/cic-ids2017/ \
        --max-per-class 30000 --min-per-class 1000

    # Use a config file
    python -m scripts.train_real_data --dataset-dir data/cic-ids2017/ --config config/config.yaml
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.data.generator import CLASS_NAMES, FEATURE_NAMES, save_dataset_csv
from src.data.real_dataset import load_real_dataset, print_dataset_summary
from src.training.trainer import TrainingPipeline
from src.utils.config import load_config, ensure_directories
from src.utils.logger import get_logger, configure_logging

logger = get_logger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser(description="Train NetSentry on real CIC-IDS2017 data")
    parser.add_argument(
        "--dataset-dir", required=True, type=str,
        help="Directory containing CIC-IDS2017 CSV files",
    )
    parser.add_argument("--config", default="config/config.yaml", help="Config file")
    parser.add_argument("--max-per-class", type=int, default=50_000, help="Max samples per class")
    parser.add_argument("--min-per-class", type=int, default=500,
                        help="Min samples per class (0 = never pad with synthetic data)")
    parser.add_argument("--max-benign", type=int, default=None,
                        help="Separate cap for BENIGN (defaults to --max-per-class)")
    parser.add_argument("--no-dedup", action="store_true", help="Skip deduplication")
    parser.add_argument("--quiet", action="store_true", help="Reduce output")
    args = parser.parse_args()

    cfg = load_config(args.config)
    configure_logging(
        level=cfg.logging.level,
        file_path=cfg.logging.file,
        json_format=True,
        rotate_bytes=cfg.logging.rotate_bytes,
        backups=cfg.logging.backups,
    )
    ensure_directories(cfg)

    print("=" * 70)
    print("NetSentry — Training on Real Dataset")
    print(f"Dataset dir:    {args.dataset_dir}")
    print(f"Max per class:  {args.max_per_class:,}")
    print(f"Min per class:  {args.min_per_class:,}")
    print(f"Max benign:     {args.max_benign or args.max_per_class:,}")
    print(f"Models dir:     {cfg.paths.models_dir}")
    print("=" * 70)

    # 1) Load and prepare the real dataset
    t0 = time.time()
    X, y, feature_names, class_names = load_real_dataset(
        dataset_dir=args.dataset_dir,
        max_samples_per_class=args.max_per_class,
        min_samples_per_class=args.min_per_class,
        deduplicate_rows=not args.no_dedup,
        random_state=cfg.data.random_state,
        max_benign_samples=args.max_benign,
    )
    load_time = time.time() - t0
    print(f"\nDataset loaded in {load_time:.1f}s")
    print_dataset_summary(X, y)

    # 2) Save as the standard training CSV (so the pipeline can reload it)
    dataset_path = Path(cfg.data.dataset_path)
    save_dataset_csv(X, y, dataset_path)
    print(f"Saved prepared dataset to {dataset_path}")

    # 3) Override config to use the real dataset size
    cfg.data.n_samples = len(y)

    # 4) Run the standard training pipeline
    pipeline = TrainingPipeline(cfg)
    report = pipeline.run()

    # 5) Print results
    print("\n" + "=" * 70)
    print("TRAINING COMPLETE (Real Data)")
    print("=" * 70)
    for model_name, model_report in report["models"].items():
        acc = model_report.get("accuracy", 0)
        f1 = model_report.get("macro_f1", model_report.get("binary_f1", 0))
        fpr = model_report.get("false_positive_rate", 0)
        dr = model_report.get("detection_rate", 0)
        train_time = model_report.get("training_time_sec", 0)
        print(
            f"  {model_name:22s} acc={acc:.4f}  f1={f1:.4f}"
            f"  FPR={fpr:.4f}  DR={dr:.4f}  train={train_time:6.1f}s"
        )
    print(f"  {'total':22s} {report['total_training_time_sec']:.1f}s")
    print(f"\nArtifacts saved to: {cfg.paths.models_dir}/")
    print(f"Metrics report:      {cfg.paths.reports_dir}/training_metrics.json")


if __name__ == "__main__":
    main()
