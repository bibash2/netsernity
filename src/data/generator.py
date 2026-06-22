"""
Synthetic network flow dataset generator.

Produces labelled flows modelled after the CIC-IDS2017 feature schema, covering
benign traffic and six attack classes. The generator samples from per-class
statistical distributions so the resulting dataset has:

    - Class-specific statistical signatures (attack-type fingerprints)
    - Realistic flag-count patterns (SYN floods, RST storms, etc.)
    - Correlated features (duration -> packet count -> bytes)
    - Controlled label noise to avoid trivially-separable artefacts

This keeps the pipeline end-to-end testable without needing to host gigabytes
of real PCAP data. Swap this module out for a real parser (Zeek, CICFlowMeter)
in production.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import numpy as np


# 30 flow-level features, same order as CIC-IDS2017 derived features.
FEATURE_NAMES: list[str] = [
    "flow_duration",         # microseconds
    "total_fwd_packets",
    "total_bwd_packets",
    "fwd_packet_length_mean",
    "bwd_packet_length_mean",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "fwd_iat_mean",          # forward inter-arrival time
    "bwd_iat_mean",
    "fwd_iat_std",
    "packet_length_mean",
    "packet_length_std",
    "packet_length_variance",
    "fin_flag_count",
    "syn_flag_count",
    "rst_flag_count",
    "psh_flag_count",
    "ack_flag_count",
    "urg_flag_count",
    "down_up_ratio",
    "avg_packet_size",
    "fwd_segment_size_avg",
    "bwd_segment_size_avg",
    "subflow_fwd_packets",
    "subflow_bwd_packets",
    "init_win_bytes_fwd",
    "init_win_bytes_bwd",
    "active_mean",
    "idle_mean",
    "fwd_header_length",
]

CLASS_NAMES: list[str] = [
    "BENIGN",       # 0
    "DDoS",         # 1
    "PortScan",     # 2
    "BruteForce",   # 3
    "Botnet",       # 4
    "Infiltration", # 5
    "WebAttack",    # 6
]
CLASS_TO_ID = {name: idx for idx, name in enumerate(CLASS_NAMES)}


# Default class ratios — skewed to benign, matching real-world traffic priors.
DEFAULT_CLASS_MIX: dict[str, float] = {
    "BENIGN": 0.60,
    "DDoS": 0.10,
    "PortScan": 0.08,
    "BruteForce": 0.07,
    "Botnet": 0.06,
    "Infiltration": 0.05,
    "WebAttack": 0.04,
}


@dataclass
class _FeatureRange:
    low: float
    high: float
    log_scale: bool = False

    def sample(self, rng: np.random.Generator, n: int) -> np.ndarray:
        if self.log_scale:
            return np.exp(rng.uniform(np.log(max(self.low, 1e-6)), np.log(max(self.high, 1e-6)), size=n))
        return rng.uniform(self.low, self.high, size=n)


# Per-class feature distributions. These capture the statistical fingerprint
# of each attack class as observed in real CIC-IDS-style datasets.
PROFILES: dict[str, dict[str, _FeatureRange]] = {
    "BENIGN": {
        "flow_duration":       _FeatureRange(50_000, 200_000, log_scale=True),
        "total_fwd_packets":   _FeatureRange(5, 50),
        "total_bwd_packets":   _FeatureRange(5, 40),
        "fwd_packet_length_mean": _FeatureRange(200, 800),
        "bwd_packet_length_mean": _FeatureRange(100, 1200),
        "flow_bytes_per_sec":  _FeatureRange(1_000, 50_000, log_scale=True),
        "flow_packets_per_sec":_FeatureRange(10, 200),
        "syn_flag_count":      _FeatureRange(0, 2),
        "fin_flag_count":      _FeatureRange(0, 2),
        "rst_flag_count":      _FeatureRange(0, 1),
        "psh_flag_count":      _FeatureRange(0, 10),
        "ack_flag_count":      _FeatureRange(1, 50),
        "urg_flag_count":      _FeatureRange(0, 0),
        "down_up_ratio":       _FeatureRange(0.3, 3.0),
        "avg_packet_size":     _FeatureRange(150, 1000),
        "init_win_bytes_fwd":  _FeatureRange(8_000, 65_535),
        "init_win_bytes_bwd":  _FeatureRange(8_000, 65_535),
    },
    "DDoS": {
        "flow_duration":       _FeatureRange(1_000, 30_000, log_scale=True),
        "total_fwd_packets":   _FeatureRange(500, 10_000, log_scale=True),
        "total_bwd_packets":   _FeatureRange(0, 50),
        "fwd_packet_length_mean": _FeatureRange(40, 100),
        "bwd_packet_length_mean": _FeatureRange(0, 60),
        "flow_bytes_per_sec":  _FeatureRange(500_000, 50_000_000, log_scale=True),
        "flow_packets_per_sec":_FeatureRange(5_000, 200_000, log_scale=True),
        "syn_flag_count":      _FeatureRange(100, 5_000, log_scale=True),
        "fin_flag_count":      _FeatureRange(0, 5),
        "rst_flag_count":      _FeatureRange(0, 50),
        "psh_flag_count":      _FeatureRange(0, 20),
        "ack_flag_count":      _FeatureRange(0, 100),
        "urg_flag_count":      _FeatureRange(0, 5),
        "down_up_ratio":       _FeatureRange(0.0, 0.1),
        "avg_packet_size":     _FeatureRange(40, 80),
        "init_win_bytes_fwd":  _FeatureRange(0, 1_024),
        "init_win_bytes_bwd":  _FeatureRange(0, 256),
    },
    "PortScan": {
        "flow_duration":       _FeatureRange(100, 5_000),
        "total_fwd_packets":   _FeatureRange(1, 5),
        "total_bwd_packets":   _FeatureRange(0, 2),
        "fwd_packet_length_mean": _FeatureRange(0, 60),
        "bwd_packet_length_mean": _FeatureRange(0, 60),
        "flow_bytes_per_sec":  _FeatureRange(1_000, 100_000, log_scale=True),
        "flow_packets_per_sec":_FeatureRange(1_000, 50_000, log_scale=True),
        "syn_flag_count":      _FeatureRange(1, 3),
        "fin_flag_count":      _FeatureRange(0, 1),
        "rst_flag_count":      _FeatureRange(1, 3),
        "psh_flag_count":      _FeatureRange(0, 1),
        "ack_flag_count":      _FeatureRange(0, 2),
        "urg_flag_count":      _FeatureRange(0, 0),
        "down_up_ratio":       _FeatureRange(0.0, 0.5),
        "avg_packet_size":     _FeatureRange(20, 70),
        "init_win_bytes_fwd":  _FeatureRange(0, 1_024),
        "init_win_bytes_bwd":  _FeatureRange(0, 256),
    },
    "BruteForce": {
        "flow_duration":       _FeatureRange(10_000_000, 120_000_000, log_scale=True),
        "total_fwd_packets":   _FeatureRange(30, 500),
        "total_bwd_packets":   _FeatureRange(30, 500),
        "fwd_packet_length_mean": _FeatureRange(60, 200),
        "bwd_packet_length_mean": _FeatureRange(60, 300),
        "flow_bytes_per_sec":  _FeatureRange(500, 20_000),
        "flow_packets_per_sec":_FeatureRange(5, 50),
        "syn_flag_count":      _FeatureRange(1, 5),
        "fin_flag_count":      _FeatureRange(0, 3),
        "rst_flag_count":      _FeatureRange(0, 5),
        "psh_flag_count":      _FeatureRange(10, 300),
        "ack_flag_count":      _FeatureRange(30, 500),
        "urg_flag_count":      _FeatureRange(0, 0),
        "down_up_ratio":       _FeatureRange(0.8, 1.5),
        "avg_packet_size":     _FeatureRange(70, 250),
        "init_win_bytes_fwd":  _FeatureRange(8_000, 65_535),
        "init_win_bytes_bwd":  _FeatureRange(8_000, 65_535),
    },
    "Botnet": {
        "flow_duration":       _FeatureRange(100_000, 5_000_000, log_scale=True),
        "total_fwd_packets":   _FeatureRange(2, 30),
        "total_bwd_packets":   _FeatureRange(2, 30),
        "fwd_packet_length_mean": _FeatureRange(50, 300),
        "bwd_packet_length_mean": _FeatureRange(100, 500),
        "flow_bytes_per_sec":  _FeatureRange(200, 10_000),
        "flow_packets_per_sec":_FeatureRange(1, 20),
        "syn_flag_count":      _FeatureRange(1, 3),
        "fin_flag_count":      _FeatureRange(0, 2),
        "rst_flag_count":      _FeatureRange(0, 1),
        "psh_flag_count":      _FeatureRange(1, 10),
        "ack_flag_count":      _FeatureRange(5, 40),
        "urg_flag_count":      _FeatureRange(0, 0),
        "down_up_ratio":       _FeatureRange(1.0, 3.0),
        "avg_packet_size":     _FeatureRange(80, 400),
        "init_win_bytes_fwd":  _FeatureRange(4_000, 32_768),
        "init_win_bytes_bwd":  _FeatureRange(4_000, 32_768),
    },
    "Infiltration": {
        "flow_duration":       _FeatureRange(1_000_000, 60_000_000, log_scale=True),
        "total_fwd_packets":   _FeatureRange(10, 200),
        "total_bwd_packets":   _FeatureRange(10, 200),
        "fwd_packet_length_mean": _FeatureRange(300, 1500),
        "bwd_packet_length_mean": _FeatureRange(300, 1500),
        "flow_bytes_per_sec":  _FeatureRange(5_000, 200_000, log_scale=True),
        "flow_packets_per_sec":_FeatureRange(5, 80),
        "syn_flag_count":      _FeatureRange(1, 3),
        "fin_flag_count":      _FeatureRange(0, 2),
        "rst_flag_count":      _FeatureRange(0, 2),
        "psh_flag_count":      _FeatureRange(5, 50),
        "ack_flag_count":      _FeatureRange(10, 200),
        "urg_flag_count":      _FeatureRange(0, 1),
        "down_up_ratio":       _FeatureRange(0.7, 2.0),
        "avg_packet_size":     _FeatureRange(300, 1200),
        "init_win_bytes_fwd":  _FeatureRange(16_000, 65_535),
        "init_win_bytes_bwd":  _FeatureRange(16_000, 65_535),
    },
    "WebAttack": {
        "flow_duration":       _FeatureRange(50_000, 2_000_000, log_scale=True),
        "total_fwd_packets":   _FeatureRange(5, 60),
        "total_bwd_packets":   _FeatureRange(5, 60),
        "fwd_packet_length_mean": _FeatureRange(200, 1500),
        "bwd_packet_length_mean": _FeatureRange(200, 2000),
        "flow_bytes_per_sec":  _FeatureRange(10_000, 300_000, log_scale=True),
        "flow_packets_per_sec":_FeatureRange(10, 300),
        "syn_flag_count":      _FeatureRange(1, 3),
        "fin_flag_count":      _FeatureRange(0, 2),
        "rst_flag_count":      _FeatureRange(0, 1),
        "psh_flag_count":      _FeatureRange(5, 40),
        "ack_flag_count":      _FeatureRange(10, 100),
        "urg_flag_count":      _FeatureRange(0, 1),
        "down_up_ratio":       _FeatureRange(0.8, 3.0),
        "avg_packet_size":     _FeatureRange(200, 1400),
        "init_win_bytes_fwd":  _FeatureRange(8_000, 65_535),
        "init_win_bytes_bwd":  _FeatureRange(8_000, 65_535),
    },
}


def _sample_flow(class_name: str, rng: np.random.Generator) -> dict:
    """Sample one flow from the given class profile.

    For features not listed in the per-class profile, we derive them from their
    correlated inputs so the resulting row is internally consistent (e.g. bytes/sec
    cannot be huge when packets/sec is tiny and durations are long).
    """
    profile = PROFILES[class_name]
    row: dict[str, float] = {}

    # Primary features explicitly defined in the profile
    for feat in FEATURE_NAMES:
        if feat in profile:
            row[feat] = float(profile[feat].sample(rng, 1)[0])

    # Derive missing features from correlations
    fwd = row.get("total_fwd_packets", rng.integers(1, 50))
    bwd = row.get("total_bwd_packets", rng.integers(1, 50))
    dur = row.get("flow_duration", rng.uniform(1_000, 1_000_000))
    fwd_len = row.get("fwd_packet_length_mean", rng.uniform(40, 800))
    bwd_len = row.get("bwd_packet_length_mean", rng.uniform(40, 800))

    row.setdefault("fwd_iat_mean", dur / max(fwd, 1) * rng.uniform(0.5, 1.5))
    row.setdefault("bwd_iat_mean", dur / max(bwd, 1) * rng.uniform(0.5, 1.5))
    row.setdefault("fwd_iat_std", row["fwd_iat_mean"] * rng.uniform(0.1, 0.8))
    total_pkt_len = fwd * fwd_len + bwd * bwd_len
    total_pkts = max(fwd + bwd, 1)
    row.setdefault("packet_length_mean", total_pkt_len / total_pkts)
    std = row["packet_length_mean"] * rng.uniform(0.1, 0.6)
    row.setdefault("packet_length_std", std)
    row.setdefault("packet_length_variance", std ** 2)
    row.setdefault("avg_packet_size", row["packet_length_mean"])
    row.setdefault("fwd_segment_size_avg", fwd_len)
    row.setdefault("bwd_segment_size_avg", bwd_len)
    row.setdefault("subflow_fwd_packets", fwd)
    row.setdefault("subflow_bwd_packets", bwd)
    row.setdefault("active_mean", rng.uniform(0, dur / 2))
    row.setdefault("idle_mean", rng.uniform(0, dur / 2))
    row.setdefault("fwd_header_length", fwd * 20)  # 20 bytes per TCP header

    # Ensure every feature is present and a plain float.
    for feat in FEATURE_NAMES:
        row[feat] = float(row.get(feat, 0.0))
    return row


def generate_dataset(
    n_samples: int = 50_000,
    class_mix: Optional[dict[str, float]] = None,
    label_noise: float = 0.01,
    random_state: Optional[int] = 42,
) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Generate a (X, y, feature_names) dataset.

    Parameters
    ----------
    n_samples : int
        Total number of flows.
    class_mix : dict or None
        Mapping from class name to proportion. Must sum to 1.0.
    label_noise : float
        Probability that each label is replaced with a random class — models
        regularization stress-test data.
    random_state : int or None
        Seed.
    """
    rng = np.random.default_rng(random_state)
    mix = dict(class_mix or DEFAULT_CLASS_MIX)
    total = sum(mix.values())
    if abs(total - 1.0) > 1e-6:
        raise ValueError(f"class_mix proportions must sum to 1.0, got {total}")

    # Compute per-class counts
    counts = {name: int(round(n_samples * p)) for name, p in mix.items()}
    # Correct rounding to hit n_samples exactly
    diff = n_samples - sum(counts.values())
    if diff != 0:
        # adjust BENIGN to absorb rounding drift
        counts["BENIGN"] += diff

    X_rows: list[list[float]] = []
    y_labels: list[int] = []
    for class_name, count in counts.items():
        label = CLASS_TO_ID[class_name]
        for _ in range(count):
            flow = _sample_flow(class_name, rng)
            X_rows.append([flow[f] for f in FEATURE_NAMES])
            y_labels.append(label)

    X = np.array(X_rows, dtype=np.float64)
    y = np.array(y_labels, dtype=np.int64)

    # Shuffle
    perm = rng.permutation(len(y))
    X = X[perm]
    y = y[perm]

    # Inject label noise
    if label_noise > 0:
        noise_mask = rng.random(len(y)) < label_noise
        n_noisy = int(noise_mask.sum())
        if n_noisy > 0:
            y[noise_mask] = rng.integers(0, len(CLASS_NAMES), size=n_noisy)

    return X, y, FEATURE_NAMES


def save_dataset_csv(X: np.ndarray, y: np.ndarray, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(FEATURE_NAMES + ["label"])
        for row, label in zip(X, y):
            writer.writerow(list(row) + [CLASS_NAMES[label]])


def load_dataset_csv(path: str | Path) -> tuple[np.ndarray, np.ndarray]:
    """Load a CSV produced by save_dataset_csv."""
    X_rows: list[list[float]] = []
    y_labels: list[int] = []
    with open(path, "r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            X_rows.append([float(row[f]) for f in FEATURE_NAMES])
            y_labels.append(CLASS_TO_ID[row["label"]])
    return np.array(X_rows, dtype=np.float64), np.array(y_labels, dtype=np.int64)
