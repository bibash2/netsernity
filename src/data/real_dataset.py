"""
Real-world dataset loader for CIC-IDS2017 and CSE-CIC-IDS2018.

Downloads, cleans, maps column names and labels, balances classes, and
outputs (X, y, feature_names) compatible with the training pipeline.
Supports blending real data with synthetic oversampling for rare classes.
"""

from __future__ import annotations

import csv
import io
import os
import zipfile
from pathlib import Path
from typing import Optional

import numpy as np

from ..utils.logger import get_logger
from .generator import CLASS_NAMES, CLASS_TO_ID, FEATURE_NAMES, generate_dataset

logger = get_logger(__name__)


# ── Column name mapping: CIC-IDS2017 CSV headers → NetSentry feature names ──

CIC_IDS2017_COLUMN_MAP: dict[str, str] = {
    # CIC-IDS2017 header (stripped)       →  NetSentry feature name
    "flow duration":                         "flow_duration",
    "total fwd packets":                     "total_fwd_packets",
    "total backward packets":                "total_bwd_packets",
    "fwd packet length mean":                "fwd_packet_length_mean",
    "bwd packet length mean":                "bwd_packet_length_mean",
    "flow bytes/s":                          "flow_bytes_per_sec",
    "flow packets/s":                        "flow_packets_per_sec",
    "fwd iat mean":                          "fwd_iat_mean",
    "bwd iat mean":                          "bwd_iat_mean",
    "fwd iat std":                           "fwd_iat_std",
    "packet length mean":                    "packet_length_mean",
    "packet length std":                     "packet_length_std",
    "packet length variance":                "packet_length_variance",
    "fin flag count":                        "fin_flag_count",
    "syn flag count":                        "syn_flag_count",
    "rst flag count":                        "rst_flag_count",
    "psh flag count":                        "psh_flag_count",
    "ack flag count":                        "ack_flag_count",
    "urg flag count":                        "urg_flag_count",
    "down/up ratio":                         "down_up_ratio",
    "average packet size":                   "avg_packet_size",
    "avg fwd segment size":                  "fwd_segment_size_avg",
    "avg bwd segment size":                  "bwd_segment_size_avg",
    "subflow fwd packets":                   "subflow_fwd_packets",
    "subflow bwd packets":                   "subflow_bwd_packets",
    "init_win_bytes_forward":                "init_win_bytes_fwd",
    "init_win_bytes_backward":               "init_win_bytes_bwd",
    "active mean":                           "active_mean",
    "idle mean":                             "idle_mean",
    "fwd header length":                     "fwd_header_length",
    # Alternate spellings seen in some CSV versions
    "fwd header length.1":                   "fwd_header_length",
    "total length of fwd packets":           "fwd_packet_length_mean",
}


# ── Label mapping: CIC-IDS2017 fine-grained labels → NetSentry 7 classes ──

CIC_IDS2017_LABEL_MAP: dict[str, str] = {
    # Benign
    "benign":                       "BENIGN",

    # DDoS
    "ddos":                         "DDoS",
    "ddos":                         "DDoS",

    # DoS → mapped to DDoS (denial of service family)
    "dos hulk":                     "DDoS",
    "dos goldeneye":                "DDoS",
    "dos slowloris":                "DDoS",
    "dos slowhttptest":             "DDoS",
    "heartbleed":                   "DDoS",

    # PortScan
    "portscan":                     "PortScan",

    # BruteForce
    "ftp-patator":                  "BruteForce",
    "ssh-patator":                  "BruteForce",

    # Botnet
    "bot":                          "Botnet",

    # Infiltration
    "infiltration":                 "Infiltration",

    # WebAttack
    "web attack – brute force":     "WebAttack",
    "web attack – xss":             "WebAttack",
    "web attack – sql injection":   "WebAttack",
    "web attack \x96 brute force":  "WebAttack",
    "web attack \x96 xss":         "WebAttack",
    "web attack \x96 sql injection": "WebAttack",
}


def _build_column_index(header_row: list[str]) -> dict[str, int]:
    """Map NetSentry feature names to column indices in the CSV header."""
    # Normalize header: strip whitespace, lowercase
    normalized = {col.strip().lower(): i for i, col in enumerate(header_row)}

    feature_to_col: dict[str, int] = {}
    for cic_name, netsentry_name in CIC_IDS2017_COLUMN_MAP.items():
        if cic_name in normalized and netsentry_name not in feature_to_col:
            feature_to_col[netsentry_name] = normalized[cic_name]

    return feature_to_col


def _parse_label(raw_label: str) -> Optional[str]:
    """Map a CIC-IDS2017 label string to a NetSentry class name."""
    cleaned = raw_label.strip().lower()
    return CIC_IDS2017_LABEL_MAP.get(cleaned)


def _safe_float(value: str) -> float:
    """Convert a string to float, handling common bad values in CIC-IDS2017."""
    value = value.strip()
    if not value or value.lower() in ("nan", "infinity", "-infinity", "inf", "-inf"):
        return 0.0
    try:
        result = float(value)
        if np.isinf(result) or np.isnan(result):
            return 0.0
        return result
    except (ValueError, OverflowError):
        return 0.0


def load_cic_ids2017_csv(csv_path: str | Path) -> tuple[np.ndarray, np.ndarray]:
    """Load a single CIC-IDS2017 CSV file and return (X, y) in NetSentry format.

    Handles column name mapping, label mapping, bad values, and missing features.
    Rows with unmappable labels are silently dropped.
    """
    csv_path = Path(csv_path)
    logger.info("Loading CIC-IDS2017 CSV: %s", csv_path)

    X_rows: list[list[float]] = []
    y_labels: list[int] = []
    skipped_labels: dict[str, int] = {}

    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        header = next(reader)
        feature_to_col = _build_column_index(header)

        # Find the label column
        label_col = None
        for i, col in enumerate(header):
            if col.strip().lower() in ("label", "labels"):
                label_col = i
                break
        if label_col is None:
            raise ValueError(f"No 'Label' column found in {csv_path}. Headers: {header[:5]}...")

        mapped_count = len(feature_to_col)
        missing_features = [f for f in FEATURE_NAMES if f not in feature_to_col]
        if missing_features:
            logger.warning(
                "Missing %d/%d features in CSV (will default to 0): %s",
                len(missing_features), len(FEATURE_NAMES), missing_features[:5],
            )

        for row in reader:
            if len(row) <= label_col:
                continue

            # Map label
            netsentry_label = _parse_label(row[label_col])
            if netsentry_label is None:
                raw = row[label_col].strip().lower()
                skipped_labels[raw] = skipped_labels.get(raw, 0) + 1
                continue

            # Extract features in NetSentry order
            features = []
            for feat_name in FEATURE_NAMES:
                col_idx = feature_to_col.get(feat_name)
                if col_idx is not None and col_idx < len(row):
                    features.append(_safe_float(row[col_idx]))
                else:
                    features.append(0.0)

            X_rows.append(features)
            y_labels.append(CLASS_TO_ID[netsentry_label])

    if skipped_labels:
        logger.warning("Skipped unmapped labels: %s", skipped_labels)

    X = np.array(X_rows, dtype=np.float64)
    y = np.array(y_labels, dtype=np.int64)
    logger.info(
        "Loaded %d flows (%d features mapped/%d total) from %s",
        len(y), mapped_count, len(FEATURE_NAMES), csv_path.name,
    )
    return X, y


def load_cic_ids2017_directory(
    directory: str | Path,
) -> tuple[np.ndarray, np.ndarray]:
    """Load all CSV files from a CIC-IDS2017 dataset directory.

    Scans for *.csv files, loads each, and concatenates into a single dataset.
    """
    directory = Path(directory)
    csv_files = sorted(directory.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {directory}")

    all_X: list[np.ndarray] = []
    all_y: list[np.ndarray] = []

    for csv_file in csv_files:
        try:
            X, y = load_cic_ids2017_csv(csv_file)
            if len(y) > 0:
                all_X.append(X)
                all_y.append(y)
        except Exception as e:
            logger.error("Failed to load %s: %s", csv_file.name, e)

    if not all_X:
        raise ValueError(f"No valid data loaded from {directory}")

    X = np.concatenate(all_X, axis=0)
    y = np.concatenate(all_y, axis=0)
    logger.info("Combined dataset: %d total flows from %d files", len(y), len(all_X))
    return X, y


def balance_classes(
    X: np.ndarray,
    y: np.ndarray,
    max_samples_per_class: int = 50_000,
    min_samples_per_class: int = 500,
    synthetic_fill_seed: int = 42,
) -> tuple[np.ndarray, np.ndarray]:
    """Balance a dataset by undersampling majority classes and oversampling rare ones.

    - Classes with more than max_samples_per_class are undersampled.
    - Classes with fewer than min_samples_per_class are augmented with synthetic data.
    """
    rng = np.random.default_rng(synthetic_fill_seed)
    balanced_X: list[np.ndarray] = []
    balanced_y: list[np.ndarray] = []

    for class_id, class_name in enumerate(CLASS_NAMES):
        mask = y == class_id
        class_count = int(mask.sum())

        if class_count == 0:
            # No real samples — fill entirely with synthetic data
            logger.warning(
                "Class '%s' has 0 real samples, generating %d synthetic",
                class_name, min_samples_per_class,
            )
            syn_X, syn_y, _ = generate_dataset(
                n_samples=min_samples_per_class,
                class_mix={cn: (1.0 if cn == class_name else 0.0) for cn in CLASS_NAMES},
                label_noise=0.0,
                random_state=synthetic_fill_seed + class_id,
            )
            # Fix: generate_dataset with single-class mix produces all one class
            # but label_noise=0 and proportions ensure correct labels
            class_mask = syn_y == class_id
            if class_mask.sum() > 0:
                balanced_X.append(syn_X[class_mask])
                balanced_y.append(syn_y[class_mask])
            continue

        class_X = X[mask]

        if class_count > max_samples_per_class:
            # Undersample: randomly select max_samples_per_class
            indices = rng.choice(class_count, size=max_samples_per_class, replace=False)
            class_X = class_X[indices]
            logger.info(
                "Undersampled '%s': %d → %d", class_name, class_count, max_samples_per_class,
            )
        elif class_count < min_samples_per_class:
            # Need more samples — augment with synthetic
            deficit = min_samples_per_class - class_count
            logger.info(
                "Augmenting '%s': %d real + %d synthetic = %d",
                class_name, class_count, deficit, min_samples_per_class,
            )
            syn_X, syn_y, _ = generate_dataset(
                n_samples=deficit,
                class_mix={cn: (1.0 if cn == class_name else 0.0) for cn in CLASS_NAMES},
                label_noise=0.0,
                random_state=synthetic_fill_seed + class_id,
            )
            class_mask = syn_y == class_id
            if class_mask.sum() > 0:
                class_X = np.concatenate([class_X, syn_X[class_mask][:deficit]], axis=0)
        else:
            logger.info("Class '%s': %d samples (kept as-is)", class_name, class_count)

        class_y = np.full(len(class_X), class_id, dtype=np.int64)
        balanced_X.append(class_X)
        balanced_y.append(class_y)

    X_balanced = np.concatenate(balanced_X, axis=0)
    y_balanced = np.concatenate(balanced_y, axis=0)

    # Shuffle
    perm = rng.permutation(len(y_balanced))
    X_balanced = X_balanced[perm]
    y_balanced = y_balanced[perm]

    logger.info("Balanced dataset: %d total flows", len(y_balanced))
    for class_id, class_name in enumerate(CLASS_NAMES):
        count = int((y_balanced == class_id).sum())
        logger.info("  %s: %d samples", class_name, count)

    return X_balanced, y_balanced


def deduplicate(X: np.ndarray, y: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Remove exact duplicate rows from the dataset."""
    combined = np.column_stack([X, y.reshape(-1, 1)])
    _, unique_indices = np.unique(combined, axis=0, return_index=True)
    unique_indices.sort()

    removed = len(y) - len(unique_indices)
    if removed > 0:
        logger.info("Removed %d duplicate rows (%d → %d)", removed, len(y), len(unique_indices))

    return X[unique_indices], y[unique_indices]


def load_real_dataset(
    dataset_dir: str | Path,
    max_samples_per_class: int = 50_000,
    min_samples_per_class: int = 500,
    deduplicate_rows: bool = True,
    random_state: int = 42,
) -> tuple[np.ndarray, np.ndarray, list[str], list[str]]:
    """Full pipeline: load CIC-IDS2017 CSVs → clean → deduplicate → balance.

    Returns (X, y, feature_names, class_names) ready for the training pipeline.
    """
    dataset_dir = Path(dataset_dir)

    # Load all CSVs from directory
    X, y = load_cic_ids2017_directory(dataset_dir)

    # Remove duplicates
    if deduplicate_rows:
        X, y = deduplicate(X, y)

    # Balance classes
    X, y = balance_classes(
        X, y,
        max_samples_per_class=max_samples_per_class,
        min_samples_per_class=min_samples_per_class,
        synthetic_fill_seed=random_state,
    )

    # Report class distribution
    logger.info("Final dataset: %d samples, %d features", X.shape[0], X.shape[1])
    for class_id, class_name in enumerate(CLASS_NAMES):
        count = int((y == class_id).sum())
        pct = count / len(y) * 100
        logger.info("  %-15s %6d  (%.1f%%)", class_name, count, pct)

    return X, y, FEATURE_NAMES, CLASS_NAMES


def print_dataset_summary(X: np.ndarray, y: np.ndarray) -> None:
    """Print a human-readable summary of the dataset distribution."""
    print(f"\n{'='*50}")
    print(f"Dataset Summary: {len(y)} total flows")
    print(f"{'='*50}")
    for class_id, class_name in enumerate(CLASS_NAMES):
        count = int((y == class_id).sum())
        pct = count / len(y) * 100
        bar = "#" * int(pct / 2)
        print(f"  {class_name:15s} {count:>7,d}  ({pct:5.1f}%)  {bar}")
    print(f"{'='*50}\n")
