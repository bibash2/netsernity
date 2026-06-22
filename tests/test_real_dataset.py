"""Tests for the real dataset loader (CIC-IDS2017 format)."""

from __future__ import annotations

import csv
import sys
import tempfile
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.data.generator import CLASS_NAMES, CLASS_TO_ID, FEATURE_NAMES
from src.data.real_dataset import (
    CIC_IDS2017_COLUMN_MAP,
    CIC_IDS2017_LABEL_MAP,
    _build_column_index,
    _parse_label,
    _safe_float,
    balance_classes,
    deduplicate,
    load_cic_ids2017_csv,
    load_cic_ids2017_directory,
)


# ── Helpers ───────────────────────────────────────────────────────────────

# Build a CIC-IDS2017-style header from our column map (reverse mapping)
CIC_HEADER = []
_NETSENTRY_TO_CIC: dict[str, str] = {}
for cic_name, ns_name in CIC_IDS2017_COLUMN_MAP.items():
    if ns_name not in _NETSENTRY_TO_CIC:
        _NETSENTRY_TO_CIC[ns_name] = cic_name

# Build header in a predictable order
CIC_HEADER = [_NETSENTRY_TO_CIC.get(f, f) for f in FEATURE_NAMES] + [" Label"]


def _write_cic_csv(path: Path, rows: list[tuple[list[float], str]]) -> None:
    """Write a fake CIC-IDS2017-format CSV with given rows."""
    # Use title-case header names like the real CIC-IDS2017 CSVs
    header = []
    for f in FEATURE_NAMES:
        cic_name = _NETSENTRY_TO_CIC.get(f, f)
        # Title-case to match real CSVs
        header.append(" " + cic_name.title())
    header.append(" Label")

    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for features, label in rows:
            writer.writerow(features + [label])


def _random_features(rng: np.random.Generator) -> list[float]:
    """Generate random feature values."""
    return [float(rng.uniform(0, 1000)) for _ in FEATURE_NAMES]


# ── Unit tests ────────────────────────────────────────────────────────────


class TestSafeFloat:
    def test_normal_value(self):
        assert _safe_float("42.5") == 42.5

    def test_nan_string(self):
        assert _safe_float("NaN") == 0.0

    def test_infinity(self):
        assert _safe_float("Infinity") == 0.0

    def test_empty_string(self):
        assert _safe_float("") == 0.0

    def test_garbage(self):
        assert _safe_float("abc") == 0.0

    def test_whitespace(self):
        assert _safe_float("  3.14  ") == 3.14


class TestParseLabel:
    def test_benign(self):
        assert _parse_label("BENIGN") == "BENIGN"
        assert _parse_label(" benign ") == "BENIGN"

    def test_ddos(self):
        assert _parse_label("DDoS") == "DDoS"

    def test_dos_variants_map_to_ddos(self):
        assert _parse_label("DoS Hulk") == "DDoS"
        assert _parse_label("DoS GoldenEye") == "DDoS"
        assert _parse_label("DoS slowloris") == "DDoS"
        assert _parse_label("DoS Slowhttptest") == "DDoS"

    def test_brute_force(self):
        assert _parse_label("FTP-Patator") == "BruteForce"
        assert _parse_label("SSH-Patator") == "BruteForce"

    def test_web_attack(self):
        assert _parse_label("Web Attack – Brute Force") == "WebAttack"
        assert _parse_label("Web Attack – XSS") == "WebAttack"

    def test_portscan(self):
        assert _parse_label("PortScan") == "PortScan"

    def test_bot(self):
        assert _parse_label("Bot") == "Botnet"

    def test_infiltration(self):
        assert _parse_label("Infiltration") == "Infiltration"

    def test_unknown_returns_none(self):
        assert _parse_label("SomeNewAttack") is None


class TestBuildColumnIndex:
    def test_maps_known_columns(self):
        header = [" Flow Duration", " Total Fwd Packets", " Label"]
        mapping = _build_column_index(header)
        assert "flow_duration" in mapping
        assert "total_fwd_packets" in mapping

    def test_handles_extra_whitespace(self):
        header = ["  flow duration  ", " total backward packets ", " Label"]
        mapping = _build_column_index(header)
        assert "flow_duration" in mapping
        assert "total_bwd_packets" in mapping


# ── CSV loading tests ─────────────────────────────────────────────────────


class TestLoadCicCsv:
    def test_loads_basic_csv(self, tmp_path):
        rng = np.random.default_rng(42)
        rows = [
            (_random_features(rng), "BENIGN"),
            (_random_features(rng), "DDoS"),
            (_random_features(rng), "BENIGN"),
            (_random_features(rng), "PortScan"),
            (_random_features(rng), "Bot"),
        ]
        csv_path = tmp_path / "test.csv"
        _write_cic_csv(csv_path, rows)

        X, y = load_cic_ids2017_csv(csv_path)
        assert X.shape[0] == 5
        assert X.shape[1] == len(FEATURE_NAMES)
        assert len(y) == 5
        assert set(y.tolist()).issubset(set(range(len(CLASS_NAMES))))

    def test_skips_unknown_labels(self, tmp_path):
        rng = np.random.default_rng(42)
        rows = [
            (_random_features(rng), "BENIGN"),
            (_random_features(rng), "SomethingUnknown"),
            (_random_features(rng), "DDoS"),
        ]
        csv_path = tmp_path / "test.csv"
        _write_cic_csv(csv_path, rows)

        X, y = load_cic_ids2017_csv(csv_path)
        assert len(y) == 2  # Unknown label skipped

    def test_handles_nan_and_inf(self, tmp_path):
        features = [float("nan")] + [0.0] * (len(FEATURE_NAMES) - 1)
        rows = [(features, "BENIGN")]
        csv_path = tmp_path / "test.csv"
        _write_cic_csv(csv_path, rows)

        X, y = load_cic_ids2017_csv(csv_path)
        assert len(y) == 1
        assert not np.isnan(X).any()
        assert not np.isinf(X).any()


class TestLoadDirectory:
    def test_loads_multiple_csvs(self, tmp_path):
        rng = np.random.default_rng(42)
        for day in ["Monday", "Tuesday"]:
            rows = [(_random_features(rng), "BENIGN") for _ in range(10)]
            rows += [(_random_features(rng), "DDoS") for _ in range(5)]
            _write_cic_csv(tmp_path / f"{day}.csv", rows)

        X, y = load_cic_ids2017_directory(tmp_path)
        assert len(y) == 30  # 15 per file × 2 files

    def test_raises_on_empty_dir(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_cic_ids2017_directory(tmp_path)


# ── Balance and dedup tests ───────────────────────────────────────────────


class TestBalanceClasses:
    def test_undersamples_majority(self):
        rng = np.random.default_rng(42)
        # 1000 benign, 50 DDoS
        X_benign = rng.random((1000, 30))
        y_benign = np.zeros(1000, dtype=np.int64)
        X_ddos = rng.random((50, 30))
        y_ddos = np.ones(50, dtype=np.int64)  # DDoS = class 1

        X = np.concatenate([X_benign, X_ddos])
        y = np.concatenate([y_benign, y_ddos])

        X_bal, y_bal = balance_classes(X, y, max_samples_per_class=200, min_samples_per_class=10)

        benign_count = int((y_bal == 0).sum())
        assert benign_count <= 200

    def test_augments_rare_classes(self):
        rng = np.random.default_rng(42)
        # Only 5 Infiltration samples
        X = rng.random((5, 30))
        y = np.full(5, CLASS_TO_ID["Infiltration"], dtype=np.int64)

        X_bal, y_bal = balance_classes(X, y, min_samples_per_class=100)

        infiltration_count = int((y_bal == CLASS_TO_ID["Infiltration"]).sum())
        assert infiltration_count >= 100

    def test_fills_missing_classes_with_synthetic(self):
        rng = np.random.default_rng(42)
        # Only benign — all attack classes are missing
        X = rng.random((100, 30))
        y = np.zeros(100, dtype=np.int64)

        X_bal, y_bal = balance_classes(X, y, min_samples_per_class=50)

        # All 7 classes should be present
        for class_id in range(len(CLASS_NAMES)):
            assert (y_bal == class_id).sum() > 0


class TestDeduplicate:
    def test_removes_exact_duplicates(self):
        X = np.array([[1, 2, 3], [1, 2, 3], [4, 5, 6]], dtype=np.float64)
        y = np.array([0, 0, 1], dtype=np.int64)

        X_dedup, y_dedup = deduplicate(X, y)
        assert len(y_dedup) == 2

    def test_keeps_unique_rows(self):
        X = np.array([[1, 2, 3], [4, 5, 6], [7, 8, 9]], dtype=np.float64)
        y = np.array([0, 1, 2], dtype=np.int64)

        X_dedup, y_dedup = deduplicate(X, y)
        assert len(y_dedup) == 3


# ── Integration test ──────────────────────────────────────────────────────


class TestEndToEnd:
    def test_full_pipeline_with_fake_cic_data(self, tmp_path):
        """Create a realistic fake CIC-IDS2017 dataset and run the full loading pipeline."""
        rng = np.random.default_rng(2024)

        # Simulate a realistic class distribution
        label_counts = {
            "BENIGN": 200,
            "DDoS": 30,
            "DoS Hulk": 20,
            "PortScan": 15,
            "FTP-Patator": 10,
            "SSH-Patator": 5,
            "Bot": 5,
            "Infiltration": 3,
            "Web Attack \xe2\x80\x93 XSS": 2,
        }

        rows = []
        for label, count in label_counts.items():
            for _ in range(count):
                rows.append((_random_features(rng), label))

        rng.shuffle(rows)
        _write_cic_csv(tmp_path / "traffic.csv", rows)

        # Load and balance
        X, y = load_cic_ids2017_directory(tmp_path)
        assert len(y) > 0

        X, y = deduplicate(X, y)
        X_bal, y_bal = balance_classes(
            X, y, max_samples_per_class=100, min_samples_per_class=50,
        )

        # Verify all 7 classes present
        for class_id, class_name in enumerate(CLASS_NAMES):
            count = int((y_bal == class_id).sum())
            assert count >= 50, f"Class {class_name} has only {count} samples"

        # Verify feature shape
        assert X_bal.shape[1] == len(FEATURE_NAMES)
