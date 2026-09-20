#!/usr/bin/env python3
"""
Download real NIDS datasets for training NetSentry.

Supports:
  - CIC-IDS2017 improved (RECOMMENDED): the corrected re-extraction by Liu,
    Engelen et al. (IEEE CNS 2022) — fixed CICFlowMeter, relabelled flows,
    "Attempted" attack flows marked. ~2.1M flows, one 343 MB zip.
  - CIC-IDS2017 original day-wise CSVs (UNB mirrors; often offline)
  - Synthetic fallback generator

Usage:
    python -m scripts.download_dataset --dataset cicids2017-improved
    python -m scripts.download_dataset --dataset cicids2017 --output data/cic-ids2017/
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# ── CIC-IDS2017 CSV files hosted on multiple mirrors ──

CICIDS2017_FILES = {
    # Day-wise CSVs from UNB's public hosting and mirrors
    "Monday-WorkingHours.pcap_ISCX.csv": [
        "https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/PCAPs/Monday-WorkingHours.pcap_ISCX.csv",
    ],
    "Tuesday-WorkingHours.pcap_ISCX.csv": [
        "https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/PCAPs/Tuesday-WorkingHours.pcap_ISCX.csv",
    ],
    "Wednesday-workingHours.pcap_ISCX.csv": [
        "https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/PCAPs/Wednesday-workingHours.pcap_ISCX.csv",
    ],
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv": [
        "https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/PCAPs/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    ],
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv": [
        "https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/PCAPs/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    ],
    "Friday-WorkingHours-Morning.pcap_ISCX.csv": [
        "https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/PCAPs/Friday-WorkingHours-Morning.pcap_ISCX.csv",
    ],
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv": [
        "https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/PCAPs/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    ],
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv": [
        "https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/PCAPs/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    ],
}


# Corrected CIC-IDS2017 — https://intrusion-detection.distrinet-research.be/CNS2022/
CICIDS2017_IMPROVED_URL = (
    "https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/CICIDS2017_improved.zip"
)


def download_cicids2017_improved(output_dir: Path) -> bool:
    """Download + unzip the corrected CIC-IDS2017 (monday.csv … friday.csv)."""
    print("=" * 60)
    print("Downloading CIC-IDS2017 (improved / corrected edition)")
    print(f"Output: {output_dir}")
    print("=" * 60)
    output_dir.mkdir(parents=True, exist_ok=True)
    if len(list(output_dir.glob("*.csv"))) >= 5:
        print("  [SKIP] CSVs already present")
        return True
    zip_path = output_dir / "CICIDS2017_improved.zip"
    if not _download_file(CICIDS2017_IMPROVED_URL, zip_path, zip_path.name):
        return False
    print("  [UNZIP] ...")
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(output_dir)
    zip_path.unlink()
    print(f"  Extracted: {', '.join(sorted(p.name for p in output_dir.glob('*.csv')))}")
    return True


def _download_file(url: str, dest: Path, label: str = "") -> bool:
    """Download a file with progress. Returns True on success."""
    if dest.exists():
        print(f"  [SKIP] {label or dest.name} already exists")
        return True

    print(f"  [GET]  {label or dest.name} ...")
    dest.parent.mkdir(parents=True, exist_ok=True)

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetSentry/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            total = int(resp.headers.get("Content-Length", 0))
            downloaded = 0
            block_size = 1024 * 1024  # 1MB chunks

            with open(dest, "wb") as f:
                while True:
                    chunk = resp.read(block_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total > 0:
                        pct = downloaded / total * 100
                        mb = downloaded / (1024 * 1024)
                        print(f"\r         {mb:.1f} MB ({pct:.0f}%)", end="", flush=True)
            print()
        return True
    except Exception as e:
        print(f"\n  [FAIL] {e}")
        if dest.exists():
            dest.unlink()
        return False


def download_cicids2017(output_dir: Path) -> bool:
    """Download CIC-IDS2017 CSV files."""
    print("=" * 60)
    print("Downloading CIC-IDS2017 Dataset")
    print(f"Output: {output_dir}")
    print("=" * 60)

    output_dir.mkdir(parents=True, exist_ok=True)
    success_count = 0

    for filename, urls in CICIDS2017_FILES.items():
        dest = output_dir / filename
        downloaded = False
        for url in urls:
            if _download_file(url, dest, filename):
                downloaded = True
                break
        if downloaded:
            success_count += 1
        else:
            print(f"  [WARN] Failed to download {filename} from all mirrors")

    print(f"\nDownloaded {success_count}/{len(CICIDS2017_FILES)} files")

    if success_count == 0:
        print("\n  CIC-IDS2017 servers may be down. Alternative options:")
        print("  1. Download manually from: https://www.unb.ca/cic/datasets/ids-2017.html")
        print("  2. Use Kaggle: https://www.kaggle.com/datasets/cicdataset/cicids2017")
        print("     → kaggle datasets download -d cicdataset/cicids2017")
        print("  3. Use the generate-and-train fallback:")
        print("     → python -m scripts.train_pipeline --samples 100000")
        return False

    return success_count >= 3  # at least some days


def generate_fallback_dataset(output_dir: Path, n_samples: int = 200_000) -> None:
    """Generate a higher-quality synthetic dataset as fallback when real data unavailable.

    Uses wider, more overlapping distributions than the default generator to produce
    harder-to-classify samples that better stress-test the model.
    """
    from src.data.generator import generate_dataset, save_dataset_csv, CLASS_NAMES, FEATURE_NAMES
    import numpy as np

    print("=" * 60)
    print("Generating High-Quality Synthetic Dataset (fallback)")
    print(f"Samples: {n_samples:,}")
    print(f"Output:  {output_dir}")
    print("=" * 60)

    output_dir.mkdir(parents=True, exist_ok=True)

    # Use realistic class distribution — real traffic is 80%+ benign
    realistic_mix = {
        "BENIGN": 0.80,
        "DDoS": 0.06,
        "PortScan": 0.05,
        "BruteForce": 0.03,
        "Botnet": 0.02,
        "Infiltration": 0.02,
        "WebAttack": 0.02,
    }

    X, y, feats = generate_dataset(
        n_samples=n_samples,
        class_mix=realistic_mix,
        label_noise=0.02,  # slightly more noise for robustness
        random_state=42,
    )

    save_dataset_csv(X, y, output_dir / "synthetic_realistic.csv")
    print(f"Generated {len(y):,} samples")
    for cid, cname in enumerate(CLASS_NAMES):
        cnt = int((y == cid).sum())
        print(f"  {cname:15s} {cnt:>7,d}  ({cnt/len(y)*100:.1f}%)")


def main():
    parser = argparse.ArgumentParser(description="Download NIDS training datasets")
    parser.add_argument(
        "--dataset", choices=["cicids2017-improved", "cicids2017", "synthetic"],
        default="cicids2017-improved",
        help="Dataset to download (default: cicids2017-improved)",
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="Output directory (default: data/<dataset>/)",
    )
    parser.add_argument(
        "--samples", type=int, default=200_000,
        help="Number of samples for synthetic dataset (default: 200000)",
    )
    parser.add_argument(
        "--fallback", action="store_true",
        help="Generate synthetic fallback if download fails",
    )
    args = parser.parse_args()

    if args.output:
        output = Path(args.output)
    else:
        output = Path("data") / args.dataset

    if args.dataset == "cicids2017-improved":
        if not download_cicids2017_improved(output):
            print("\n  Download failed. Manual: https://intrusion-detection.distrinet-research.be/CNS2022/")
            sys.exit(1)
    elif args.dataset == "cicids2017":
        ok = download_cicids2017(output)
        if not ok and args.fallback:
            print("\nFalling back to synthetic dataset...")
            generate_fallback_dataset(Path("data/synthetic"), args.samples)
    elif args.dataset == "synthetic":
        generate_fallback_dataset(output, args.samples)

    print("\nDone. Next steps:")
    if args.dataset == "cicids2017-improved":
        print(f"  NETSENTRY_MODEL__RF_N_JOBS=8 python -m scripts.train_real_data --dataset-dir {output} \\")
        print(f"      --max-per-class 50000 --max-benign 150000 --min-per-class 0")
    elif args.dataset == "cicids2017":
        print(f"  python -m scripts.train_real_data --dataset-dir {output}")
    else:
        print(f"  python -m scripts.train_pipeline --config config/config.yaml")


if __name__ == "__main__":
    main()
