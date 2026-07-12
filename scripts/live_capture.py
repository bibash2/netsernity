#!/usr/bin/env python3
"""
NetSentry — Live network traffic capture and real-time intrusion detection.

Sniffs packets on a network interface, aggregates them into flows by 5-tuple
(src_ip, dst_ip, src_port, dst_port, protocol), extracts CIC-IDS-style features,
and POSTs each completed flow to the NetSentry API for classification.

When an intrusion is detected with sufficient confidence, the API's enforcement
engine automatically blocks the source IP.

Usage:
    # Capture on default interface (requires sudo for raw sockets)
    sudo python3 -m scripts.live_capture

    # Specify interface and API endpoint
    sudo python3 -m scripts.live_capture --iface en0 --api http://localhost:8000/api/v1

    # Adjust flow timeout (seconds before a flow is flushed for classification)
    sudo python3 -m scripts.live_capture --timeout 30

    # BPF filter (e.g. only TCP)
    sudo python3 -m scripts.live_capture --filter "tcp"
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from scapy.all import IP, TCP, UDP, sniff, conf
except ImportError:
    print("ERROR: scapy required. Install: pip install scapy")
    sys.exit(1)

try:
    import urllib.request
    import urllib.error
except ImportError:
    pass


# ── Flow accumulator ─────────────────────────────────────────────────────


@dataclass
class FlowAccumulator:
    """Collects per-packet stats for a single network flow."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    start_time: float = 0.0
    last_time: float = 0.0

    # Packet counts
    fwd_packets: int = 0
    bwd_packets: int = 0

    # Packet lengths
    fwd_lengths: list = field(default_factory=list)
    bwd_lengths: list = field(default_factory=list)
    all_lengths: list = field(default_factory=list)

    # Inter-arrival times
    fwd_iats: list = field(default_factory=list)
    bwd_iats: list = field(default_factory=list)
    _last_fwd_time: float = 0.0
    _last_bwd_time: float = 0.0

    # TCP flags
    fin_count: int = 0
    syn_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    ack_count: int = 0
    urg_count: int = 0

    # Window sizes (first packet each direction)
    init_win_fwd: int = -1
    init_win_bwd: int = -1

    # Header lengths
    fwd_header_bytes: int = 0

    # Active/idle tracking
    _active_start: float = 0.0
    _idle_start: float = 0.0
    active_times: list = field(default_factory=list)
    idle_times: list = field(default_factory=list)

    # Activity threshold (microseconds of silence = idle)
    _idle_threshold: float = 1.0  # 1 second

    def add_packet(self, length: int, is_forward: bool, timestamp: float,
                   tcp_flags: int = 0, win_size: int = 0, header_len: int = 0):
        now = timestamp

        if self.start_time == 0:
            self.start_time = now
            self._active_start = now
            self._last_fwd_time = now
            self._last_bwd_time = now

        # Active/idle detection
        if self.last_time > 0:
            gap = now - self.last_time
            if gap > self._idle_threshold:
                # Was active, now idle
                if self._active_start > 0:
                    self.active_times.append(now - self._active_start)
                self.idle_times.append(gap)
                self._active_start = now

        self.last_time = now
        self.all_lengths.append(length)

        if is_forward:
            self.fwd_packets += 1
            self.fwd_lengths.append(length)
            self.fwd_header_bytes += header_len
            if self.fwd_packets > 1:
                self.fwd_iats.append(now - self._last_fwd_time)
            self._last_fwd_time = now
            if self.init_win_fwd == -1:
                self.init_win_fwd = win_size
        else:
            self.bwd_packets += 1
            self.bwd_lengths.append(length)
            if self.bwd_packets > 1:
                self.bwd_iats.append(now - self._last_bwd_time)
            self._last_bwd_time = now
            if self.init_win_bwd == -1:
                self.init_win_bwd = win_size

        # TCP flags
        if tcp_flags:
            if tcp_flags & 0x01: self.fin_count += 1
            if tcp_flags & 0x02: self.syn_count += 1
            if tcp_flags & 0x04: self.rst_count += 1
            if tcp_flags & 0x08: self.psh_count += 1
            if tcp_flags & 0x10: self.ack_count += 1
            if tcp_flags & 0x20: self.urg_count += 1

    def to_features(self) -> dict:
        """Extract the 30 CIC-IDS features from accumulated packet data."""
        duration_us = (self.last_time - self.start_time) * 1_000_000  # microseconds
        duration_s = max(self.last_time - self.start_time, 1e-9)
        total_packets = self.fwd_packets + self.bwd_packets
        total_bytes = sum(self.all_lengths)

        def _mean(lst): return sum(lst) / len(lst) if lst else 0.0
        def _std(lst):
            if len(lst) < 2: return 0.0
            m = _mean(lst)
            return math.sqrt(sum((x - m) ** 2 for x in lst) / len(lst))
        def _var(lst):
            s = _std(lst)
            return s * s

        # Convert IATs to microseconds
        fwd_iats_us = [t * 1_000_000 for t in self.fwd_iats]
        bwd_iats_us = [t * 1_000_000 for t in self.bwd_iats]

        down_up = (self.bwd_packets / self.fwd_packets) if self.fwd_packets > 0 else 0.0

        return {
            "flow_duration": duration_us,
            "total_fwd_packets": self.fwd_packets,
            "total_bwd_packets": self.bwd_packets,
            "fwd_packet_length_mean": _mean(self.fwd_lengths),
            "bwd_packet_length_mean": _mean(self.bwd_lengths),
            "flow_bytes_per_sec": total_bytes / duration_s,
            "flow_packets_per_sec": total_packets / duration_s,
            "fwd_iat_mean": _mean(fwd_iats_us),
            "bwd_iat_mean": _mean(bwd_iats_us),
            "fwd_iat_std": _std(fwd_iats_us),
            "packet_length_mean": _mean(self.all_lengths),
            "packet_length_std": _std(self.all_lengths),
            "packet_length_variance": _var(self.all_lengths),
            "fin_flag_count": self.fin_count,
            "syn_flag_count": self.syn_count,
            "rst_flag_count": self.rst_count,
            "psh_flag_count": self.psh_count,
            "ack_flag_count": self.ack_count,
            "urg_flag_count": self.urg_count,
            "down_up_ratio": down_up,
            "avg_packet_size": _mean(self.all_lengths),
            "fwd_segment_size_avg": _mean(self.fwd_lengths),
            "bwd_segment_size_avg": _mean(self.bwd_lengths),
            "subflow_fwd_packets": self.fwd_packets,
            "subflow_bwd_packets": self.bwd_packets,
            "init_win_bytes_fwd": self.init_win_fwd,
            "init_win_bytes_bwd": self.init_win_bwd,
            "active_mean": _mean([t * 1_000_000 for t in self.active_times]),
            "idle_mean": _mean([t * 1_000_000 for t in self.idle_times]),
            "fwd_header_length": self.fwd_header_bytes,
        }


# ── Flow table ────────────────────────────────────────────────────────────


class FlowTable:
    """Thread-safe table of active flows, keyed by 5-tuple."""

    def __init__(self, timeout: float = 60.0):
        self.timeout = timeout
        self._flows: dict[tuple, FlowAccumulator] = {}
        self._lock = threading.Lock()

    def process_packet(self, pkt):
        """Called by scapy for each captured packet."""
        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        proto = ip.proto
        src_port = 0
        dst_port = 0
        tcp_flags = 0
        win_size = 0
        header_len = ip.ihl * 4  # IP header length

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            tcp_flags = int(tcp.flags)
            win_size = tcp.window
            header_len += tcp.dataofs * 4 if tcp.dataofs else 20
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            src_port = udp.sport
            dst_port = udp.dport
            header_len += 8

        length = len(pkt)
        timestamp = float(pkt.time)

        # Determine flow direction — forward key is always the smaller tuple
        fwd_key = (src_ip, dst_ip, src_port, dst_port, proto)
        bwd_key = (dst_ip, src_ip, dst_port, src_port, proto)

        with self._lock:
            if fwd_key in self._flows:
                self._flows[fwd_key].add_packet(length, True, timestamp,
                                                 tcp_flags, win_size, header_len)
            elif bwd_key in self._flows:
                self._flows[bwd_key].add_packet(length, False, timestamp,
                                                 tcp_flags, win_size, header_len)
            else:
                # New flow
                flow = FlowAccumulator(
                    src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port,
                    protocol=proto,
                )
                flow.add_packet(length, True, timestamp, tcp_flags, win_size, header_len)
                self._flows[fwd_key] = flow

    def flush_expired(self, now: float) -> list[FlowAccumulator]:
        """Remove and return flows that have been idle longer than timeout."""
        expired = []
        with self._lock:
            keys_to_remove = []
            for key, flow in self._flows.items():
                if (now - flow.last_time) > self.timeout:
                    keys_to_remove.append(key)
            for key in keys_to_remove:
                expired.append(self._flows.pop(key))
        return expired

    def flush_all(self) -> list[FlowAccumulator]:
        """Flush all flows regardless of age."""
        with self._lock:
            flows = list(self._flows.values())
            self._flows.clear()
        return flows

    @property
    def active_count(self) -> int:
        with self._lock:
            return len(self._flows)


# ── API client ────────────────────────────────────────────────────────────


def send_flow_to_api(api_url: str, flow: FlowAccumulator, verbose: bool = False) -> Optional[dict]:
    """POST a flow to the NetSentry predict API. Returns response dict or None."""
    features = flow.to_features()
    payload = json.dumps({
        "flow": features,
        "source_ip": flow.src_ip,
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{api_url}/predict",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read().decode())

            result = body.get("result", {})
            prediction = result.get("prediction", "?")
            confidence = result.get("confidence", 0)
            is_attack = result.get("is_attack", False)
            alert_id = body.get("alert_id")

            # Color output
            if is_attack:
                severity = "CRITICAL" if confidence > 0.9 else "HIGH" if confidence > 0.7 else "MEDIUM"
                print(
                    f"\033[91m[{severity}]\033[0m {flow.src_ip}:{flow.src_port} → "
                    f"{flow.dst_ip}:{flow.dst_port} | "
                    f"\033[91m{prediction}\033[0m conf={confidence:.1%} "
                    f"alert={alert_id or '—'} "
                    f"pkts={flow.fwd_packets + flow.bwd_packets}"
                )
            elif verbose:
                print(
                    f"\033[92m[BENIGN]\033[0m  {flow.src_ip}:{flow.src_port} → "
                    f"{flow.dst_ip}:{flow.dst_port} | "
                    f"{prediction} conf={confidence:.1%} "
                    f"pkts={flow.fwd_packets + flow.bwd_packets}"
                )

            return body
    except urllib.error.URLError as e:
        print(f"\033[93m[WARN]\033[0m API unreachable: {e.reason}")
        return None
    except Exception as e:
        print(f"\033[93m[WARN]\033[0m API error: {e}")
        return None


# ── Flush loop ────────────────────────────────────────────────────────────


def flush_loop(flow_table: FlowTable, api_url: str, interval: float,
               verbose: bool, min_packets: int, stats: dict):
    """Background thread: periodically flush expired flows and classify them."""
    while stats.get("running", True):
        time.sleep(interval)
        now = time.time()
        expired = flow_table.flush_expired(now)

        for flow in expired:
            total_pkts = flow.fwd_packets + flow.bwd_packets
            if total_pkts < min_packets:
                stats["skipped"] += 1
                continue

            stats["classified"] += 1
            result = send_flow_to_api(api_url, flow, verbose=verbose)
            if result and result.get("result", {}).get("is_attack"):
                stats["attacks"] += 1


# ── Main ──────────────────────────────────────────────────────────────────


def parse_args():
    p = argparse.ArgumentParser(description="NetSentry live traffic capture")
    p.add_argument("--iface", default=None,
                   help="Network interface (default: scapy default)")
    p.add_argument("--pcap", default=None,
                   help="Read from pcap file instead of live capture (no sudo needed)")
    p.add_argument("--api", default="http://localhost:8000/api/v1",
                   help="NetSentry API base URL")
    p.add_argument("--timeout", type=float, default=30.0,
                   help="Flow idle timeout in seconds before classification")
    p.add_argument("--flush-interval", type=float, default=5.0,
                   help="How often to check for expired flows (seconds)")
    p.add_argument("--min-packets", type=int, default=3,
                   help="Minimum packets in a flow before classifying")
    p.add_argument("--filter", default="ip",
                   help="BPF filter (default: 'ip')")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Show benign flows too")
    p.add_argument("--count", type=int, default=0,
                   help="Stop after N packets (0 = unlimited)")
    p.add_argument("--simulate", action="store_true",
                   help="Simulate live traffic from dataset CSV (no sudo needed)")
    return p.parse_args()


def main():
    args = parse_args()

    print("=" * 70)
    print("  NetSentry — Live Traffic Capture & Real-Time Intrusion Detection")
    print("=" * 70)
    print(f"  Interface:      {args.iface or 'default'}")
    print(f"  API endpoint:   {args.api}")
    print(f"  Flow timeout:   {args.timeout}s")
    print(f"  Flush interval: {args.flush_interval}s")
    print(f"  Min packets:    {args.min_packets}")
    print(f"  BPF filter:     {args.filter}")
    print(f"  Verbose:        {args.verbose}")
    print("=" * 70)

    # Check API health
    try:
        req = urllib.request.Request(f"{args.api}/health")
        with urllib.request.urlopen(req, timeout=3) as resp:
            health = json.loads(resp.read().decode())
            if health.get("model_loaded"):
                print(f"\033[92m  API online, model loaded ✓\033[0m")
            else:
                print(f"\033[93m  API online but model NOT loaded\033[0m")
    except Exception:
        print(f"\033[91m  WARNING: API not reachable at {args.api}\033[0m")
        print(f"  Start the server first: python3 -m scripts.run_server")
        print(f"  Continuing anyway — will retry on each flow...\n")

    # ── Simulation mode: replay from dataset CSV ──
    if args.simulate:
        _run_simulation(args)
        return

    print(f"\n  Capturing... (Ctrl+C to stop)\n")

    flow_table = FlowTable(timeout=args.timeout)
    stats = {"running": True, "classified": 0, "attacks": 0, "skipped": 0, "packets": 0}

    # Start flush thread
    flusher = threading.Thread(
        target=flush_loop,
        args=(flow_table, args.api, args.flush_interval, args.verbose, args.min_packets, stats),
        daemon=True,
    )
    flusher.start()

    # Packet counter callback
    def on_packet(pkt):
        stats["packets"] += 1
        flow_table.process_packet(pkt)
        # Print status every 500 packets
        if stats["packets"] % 500 == 0:
            print(
                f"\033[90m  [{stats['packets']} pkts captured | "
                f"{flow_table.active_count} active flows | "
                f"{stats['classified']} classified | "
                f"{stats['attacks']} attacks]\033[0m"
            )

    # Pcap file or live capture
    source = args.pcap or args.iface

    try:
        if args.pcap:
            print(f"  Reading from pcap: {args.pcap}\n")
            sniff(offline=args.pcap, filter=args.filter, prn=on_packet,
                  store=False, count=args.count or 0)
        else:
            sniff(iface=args.iface, filter=args.filter, prn=on_packet,
                  store=False, count=args.count or 0)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("\n\033[91mERROR: Raw packet capture requires root/sudo.\033[0m")
        print("Run: sudo python3 -m scripts.live_capture")
        print("Or use --simulate to replay from dataset CSV (no sudo needed)")
        sys.exit(1)

    # Final flush
    print(f"\n\n  Stopping capture, flushing remaining flows...")
    stats["running"] = False
    remaining = flow_table.flush_all()
    for flow in remaining:
        total_pkts = flow.fwd_packets + flow.bwd_packets
        if total_pkts >= args.min_packets:
            stats["classified"] += 1
            result = send_flow_to_api(args.api, flow, verbose=args.verbose)
            if result and result.get("result", {}).get("is_attack"):
                stats["attacks"] += 1

    print(f"\n{'=' * 70}")
    print(f"  CAPTURE SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Packets captured:  {stats['packets']}")
    print(f"  Flows classified:  {stats['classified']}")
    print(f"  Flows skipped:     {stats['skipped']} (< {args.min_packets} packets)")
    print(f"  Attacks detected:  {stats['attacks']}")
    print(f"{'=' * 70}\n")


def _run_simulation(args):
    """Replay flows from the training dataset CSV as if they were live traffic."""
    import random

    from src.data import FEATURE_NAMES, CLASS_NAMES, CLASS_TO_ID
    from src.data.generator import load_dataset_csv

    dataset_path = Path("data/netsentry_dataset.csv")
    if not dataset_path.exists():
        print(f"\033[91mERROR: Dataset not found at {dataset_path}\033[0m")
        print("Run training first: python3 -m scripts.train_real_data --dataset-dir data/cic-ids2017/")
        sys.exit(1)

    X, y = load_dataset_csv(dataset_path)
    n_flows = args.count if args.count > 0 else 100

    # Sample a mix of benign and attack flows
    indices = list(range(len(y)))
    random.seed(42)
    random.shuffle(indices)
    selected = indices[:n_flows]

    print(f"\n  Simulating {n_flows} flows from real dataset...\n")

    stats = {"classified": 0, "attacks": 0, "blocked": 0}
    fake_ips = {}

    for i, idx in enumerate(selected):
        features = {FEATURE_NAMES[j]: float(X[idx][j]) for j in range(len(FEATURE_NAMES))}
        true_class = CLASS_NAMES[y[idx]]

        # Generate a fake source IP for each flow
        if idx not in fake_ips:
            b2 = (idx // 256) % 256
            b3 = idx % 256
            b4 = (idx * 7 + 3) % 256
            fake_ips[idx] = f"203.0.{b2}.{b3}" if true_class != "BENIGN" else f"10.0.{b2}.{b3}"

        source_ip = fake_ips[idx]
        payload = json.dumps({"flow": features, "source_ip": source_ip}).encode("utf-8")

        req = urllib.request.Request(
            f"{args.api}/predict",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = json.loads(resp.read().decode())
                result = body.get("result", {})
                prediction = result.get("prediction", "?")
                confidence = result.get("confidence", 0)
                is_attack = result.get("is_attack", False)
                alert_id = body.get("alert_id")

                stats["classified"] += 1
                match = prediction == true_class
                marker = "✓" if match else "✗"

                if is_attack:
                    stats["attacks"] += 1
                    severity = "CRITICAL" if confidence > 0.9 else "HIGH" if confidence > 0.7 else "MEDIUM"
                    print(
                        f"  \033[91m[{severity:8s}]\033[0m {source_ip:>15s} → "
                        f"\033[91m{prediction:15s}\033[0m conf={confidence:.1%} "
                        f"true={true_class:15s} {marker} "
                        f"alert={alert_id or '—'}"
                    )
                elif args.verbose:
                    print(
                        f"  \033[92m[BENIGN  ]\033[0m {source_ip:>15s} → "
                        f"\033[92m{prediction:15s}\033[0m conf={confidence:.1%} "
                        f"true={true_class:15s} {marker}"
                    )
        except Exception as e:
            print(f"  \033[93m[ERROR]\033[0m Flow {i}: {e}")

        # Small delay to simulate real-time
        time.sleep(0.05)

    # Check blocked IPs
    try:
        req = urllib.request.Request(f"{args.api}/blocked")
        with urllib.request.urlopen(req, timeout=3) as resp:
            blocked = json.loads(resp.read().decode())
            stats["blocked"] = len(blocked)
    except Exception:
        pass

    print(f"\n{'=' * 70}")
    print(f"  SIMULATION SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Flows classified:  {stats['classified']}")
    print(f"  Attacks detected:  {stats['attacks']}")
    print(f"  IPs blocked:       {stats['blocked']}")
    print(f"{'=' * 70}\n")

    if stats["blocked"] > 0:
        print(f"  Blocked IPs:")
        try:
            req = urllib.request.Request(f"{args.api}/blocked")
            with urllib.request.urlopen(req, timeout=3) as resp:
                blocked = json.loads(resp.read().decode())
                for b in blocked[:20]:
                    print(
                        f"    \033[91m{b['ip_address']:18s}\033[0m "
                        f"{b['attack_type']:15s} {b['action_type']:10s} "
                        f"conf={b['confidence']:.1%} ttl={b['remaining_seconds']}s"
                    )
        except Exception:
            pass
        print()


if __name__ == "__main__":
    main()
