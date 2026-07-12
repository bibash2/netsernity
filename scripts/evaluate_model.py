#!/usr/bin/env python3
"""
Evaluate a trained NetSentry model against real or synthetic traffic.

Reports: FPR, FNR, Detection Rate, per-class metrics, confusion matrix.
Optionally runs against a pcap file to test with actual network traffic.

Usage:
    # Evaluate against the training dataset (quick sanity check)
    python -m scripts.evaluate_model

    # Evaluate against a separate held-out CIC-IDS2017 directory
    python -m scripts.evaluate_model --dataset-dir data/cic-ids2017-test/

    # Evaluate against a pcap file (requires scapy)
    python -m scripts.evaluate_model --pcap captures/test.pcap

    # Evaluate and show per-flow misclassifications
    python -m scripts.evaluate_model --show-errors 20
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.data import CLASS_NAMES, FEATURE_NAMES, Preprocessor
from src.data.generator import load_dataset_csv
from src.data.real_dataset import load_real_dataset
from src.models import EnsembleNIDS
from src.utils import metrics


def load_model_and_preprocessor(models_dir: str = "models_artifacts"):
    models_path = Path(models_dir)
    ensemble = EnsembleNIDS.load(models_path / "ensemble.pkl")
    preprocessor = Preprocessor.load(models_path / "preprocessor.pkl")
    return ensemble, preprocessor


def evaluate_dataset(
    ensemble: EnsembleNIDS,
    preprocessor: Preprocessor,
    X: np.ndarray,
    y: np.ndarray,
    show_errors: int = 0,
) -> dict:
    """Run evaluation and return metrics dict."""
    X_scaled = preprocessor.transform(X)

    t0 = time.time()
    preds = ensemble.predict(X_scaled)
    inference_time = time.time() - t0

    acc = metrics.accuracy(y, preds)
    fpr = metrics.false_positive_rate(y, preds)
    fnr = metrics.false_negative_rate(y, preds)
    dr = metrics.detection_rate(y, preds)
    rpt = metrics.precision_recall_f1(y, preds)

    # Print results
    print("\n" + "=" * 70)
    print("EVALUATION RESULTS")
    print("=" * 70)
    print(f"  Samples:           {len(y):,}")
    print(f"  Inference time:    {inference_time:.2f}s ({inference_time/len(y)*1000:.3f} ms/sample)")
    print()
    print(f"  Accuracy:          {acc:.4f}")
    print(f"  False Positive Rate: {fpr:.4f}  ({fpr*100:.2f}% benign flagged as attack)")
    print(f"  False Negative Rate: {fnr:.4f}  ({fnr*100:.2f}% attacks missed)")
    print(f"  Detection Rate:    {dr:.4f}  ({dr*100:.2f}% attacks caught)")
    print(f"  Macro F1:          {rpt['macro']['f1']:.4f}")
    print()

    # Per-class table
    print(f"  {'Class':<15} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Support':>10}")
    print(f"  {'-'*55}")
    for c, vals in rpt["per_class"].items():
        name = CLASS_NAMES[c] if c < len(CLASS_NAMES) else f"class_{c}"
        if vals["support"] > 0:
            print(
                f"  {name:<15} {vals['precision']:>10.4f} {vals['recall']:>10.4f} "
                f"{vals['f1']:>10.4f} {vals['support']:>10,}"
            )
    print(f"  {'-'*55}")

    # Confusion matrix
    cm = np.array(rpt["confusion_matrix"])
    print(f"\n  Confusion Matrix (rows=true, cols=pred):")
    header = "  " + f"{'':>12}" + "".join(f"{CLASS_NAMES[i][:6]:>8}" for i in range(cm.shape[1]))
    print(header)
    for i in range(cm.shape[0]):
        row = f"  {CLASS_NAMES[i][:12]:>12}" + "".join(f"{cm[i,j]:>8,}" for j in range(cm.shape[1]))
        print(row)

    # Show specific misclassifications
    if show_errors > 0:
        errors = np.where(preds != y)[0]
        print(f"\n  Showing {min(show_errors, len(errors))} misclassified flows:")
        print(f"  {'#':>5} {'True':>12} {'Predicted':>12} {'Key Features'}")
        for idx in errors[:show_errors]:
            true_name = CLASS_NAMES[y[idx]]
            pred_name = CLASS_NAMES[preds[idx]]
            # Show most distinguishing features for this flow
            flow = X[idx]
            key_feats = (
                f"dur={flow[0]:.0f} fwd_pkt={flow[1]:.0f} "
                f"bps={flow[5]:.0f} syn={flow[14]:.0f}"
            )
            print(f"  {idx:>5} {true_name:>12} {pred_name:>12}  {key_feats}")

    print("=" * 70)

    return {
        "accuracy": acc,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "detection_rate": dr,
        "macro_f1": rpt["macro"]["f1"],
        "weighted_f1": rpt["weighted"]["f1"],
        "per_class": rpt["per_class"],
        "confusion_matrix": rpt["confusion_matrix"],
        "samples": len(y),
        "inference_time_sec": round(inference_time, 3),
    }


def evaluate_pcap(ensemble, preprocessor, pcap_path: str, min_packets: int = 3):
    """Evaluate against a pcap file by extracting flows."""
    try:
        from scapy.all import rdpcap, IP, TCP, UDP
    except ImportError:
        print("scapy required for pcap evaluation. Install: pip install scapy")
        sys.exit(1)

    from src.capture.sniffer import FlowAccumulator

    print(f"\nReading pcap: {pcap_path}")
    packets = rdpcap(pcap_path)
    print(f"Loaded {len(packets)} packets")

    # Build flows from packets
    flows: dict[tuple, FlowAccumulator] = {}
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        ip = pkt[IP]
        src_ip, dst_ip, proto = ip.src, ip.dst, ip.proto
        src_port = dst_port = 0
        tcp_flags = win_size = 0
        header_len = ip.ihl * 4

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_port, dst_port = tcp.sport, tcp.dport
            tcp_flags = int(tcp.flags)
            win_size = tcp.window
            header_len += tcp.dataofs * 4 if tcp.dataofs else 20
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            src_port, dst_port = udp.sport, udp.dport
            header_len += 8

        fwd_key = (src_ip, dst_ip, src_port, dst_port, proto)
        bwd_key = (dst_ip, src_ip, dst_port, src_port, proto)
        length = len(pkt)
        timestamp = float(pkt.time)

        if fwd_key in flows:
            flows[fwd_key].add_packet(length, True, timestamp, tcp_flags, win_size, header_len)
        elif bwd_key in flows:
            flows[bwd_key].add_packet(length, False, timestamp, tcp_flags, win_size, header_len)
        else:
            flow = FlowAccumulator(
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port, protocol=proto,
            )
            flow.add_packet(length, True, timestamp, tcp_flags, win_size, header_len)
            flows[fwd_key] = flow

    # Extract features and classify
    results = {"BENIGN": 0}
    for cname in CLASS_NAMES[1:]:
        results[cname] = 0

    classified = 0
    for key, flow in flows.items():
        total_pkts = flow.fwd_packets + flow.bwd_packets
        if total_pkts < min_packets:
            continue

        features = flow.to_features()
        feature_vec = np.array([[features.get(f, 0.0) for f in FEATURE_NAMES]], dtype=np.float64)
        X_scaled = preprocessor.transform(feature_vec)
        pred = ensemble.predict(X_scaled)[0]
        pred_name = CLASS_NAMES[pred] if pred < len(CLASS_NAMES) else f"class_{pred}"
        results[pred_name] = results.get(pred_name, 0) + 1
        classified += 1

        if pred != 0:  # attack
            detail = ensemble.predict_with_detail(X_scaled)
            conf = float(detail["ensemble_proba"][0].max())
            print(
                f"  [{pred_name:12s}] {flow.src_ip}:{flow.src_port} → "
                f"{flow.dst_ip}:{flow.dst_port}  conf={conf:.1%}  pkts={total_pkts}"
            )

    print(f"\n  Flows extracted: {len(flows)}")
    print(f"  Flows classified: {classified}")
    print(f"\n  Classification breakdown:")
    for cname, count in results.items():
        if count > 0:
            pct = count / classified * 100 if classified > 0 else 0
            print(f"    {cname:15s} {count:>6,}  ({pct:.1f}%)")


def main():
    parser = argparse.ArgumentParser(description="Evaluate NetSentry model")
    parser.add_argument("--models-dir", default="models_artifacts", help="Models directory")
    parser.add_argument("--dataset-dir", default=None, help="CIC-IDS2017 directory for evaluation")
    parser.add_argument("--dataset-csv", default=None, help="Single CSV file for evaluation")
    parser.add_argument("--pcap", default=None, help="PCAP file for evaluation")
    parser.add_argument("--show-errors", type=int, default=0, help="Show N misclassified flows")
    parser.add_argument("--output", default=None, help="Save results JSON to this path")
    args = parser.parse_args()

    print("=" * 70)
    print("NetSentry — Model Evaluation")
    print("=" * 70)

    ensemble, preprocessor = load_model_and_preprocessor(args.models_dir)
    print(f"  Model loaded from: {args.models_dir}")

    if args.pcap:
        evaluate_pcap(ensemble, preprocessor, args.pcap)
        return

    # Load evaluation data
    if args.dataset_dir:
        print(f"  Loading CIC-IDS2017 from: {args.dataset_dir}")
        X, y, _, _ = load_real_dataset(args.dataset_dir)
    elif args.dataset_csv:
        print(f"  Loading CSV: {args.dataset_csv}")
        X, y = load_dataset_csv(args.dataset_csv)
    else:
        # Default: use training dataset
        default_path = Path("data/netsentry_dataset.csv")
        if not default_path.exists():
            print("No dataset found. Provide --dataset-dir, --dataset-csv, or --pcap")
            sys.exit(1)
        print(f"  Loading default dataset: {default_path}")
        X, y = load_dataset_csv(str(default_path))

    result = evaluate_dataset(ensemble, preprocessor, X, y, show_errors=args.show_errors)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\n  Results saved to: {args.output}")


if __name__ == "__main__":
    main()
