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
import sys
import threading
import time
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

import urllib.request
import urllib.error


# ── Authenticated API client ────────────────────────────────────────────────


class ApiClient:
    """Thin NetSentry API client: logs in for a JWT, attaches it to every
    request, re-logs in on 401, and backs off on 429 (rate limit)."""

    def __init__(self, api_url: str, username: str, password: str,
                 token: Optional[str] = None):
        self.api_url = api_url.rstrip("/")
        self.username = username
        self.password = password
        self._token = token
        self._lock = threading.Lock()

    def _login(self) -> Optional[str]:
        body = json.dumps({"username": self.username, "password": self.password}).encode()
        req = urllib.request.Request(
            f"{self.api_url}/auth/login", data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                # server returns the JWT under "token"
                return json.loads(resp.read().decode()).get("token")
        except Exception as e:
            print(f"\033[91m[AUTH]\033[0m login failed: {e}")
            return None

    def token(self) -> Optional[str]:
        with self._lock:
            if self._token is None:
                self._token = self._login()
            return self._token

    def _request(self, method: str, path: str, body: Optional[dict],
                 retries: int = 5) -> Optional[dict]:
        data = json.dumps(body).encode() if body is not None else None
        for attempt in range(retries):
            tok = self.token()
            headers = {"Content-Type": "application/json"}
            if tok:
                headers["Authorization"] = f"Bearer {tok}"
            req = urllib.request.Request(f"{self.api_url}{path}", data=data,
                                         headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return json.loads(resp.read().decode())
            except urllib.error.HTTPError as e:
                if e.code == 401:  # token expired/invalid — refresh once
                    with self._lock:
                        self._token = None
                    continue
                if e.code == 429 and attempt < retries - 1:  # rate limited
                    time.sleep(2 ** attempt)  # 1,2,4,8s backoff
                    continue
                print(f"\033[93m[WARN]\033[0m {method} {path} -> HTTP {e.code}")
                return None
            except urllib.error.URLError as e:
                print(f"\033[93m[WARN]\033[0m API unreachable: {e.reason}")
                return None
        return None

    def predict(self, features: dict, source_ip: str) -> Optional[dict]:
        return self._request("POST", "/predict",
                             {"flow": features, "source_ip": source_ip})

    def get(self, path: str) -> Optional[dict]:
        return self._request("GET", path, None)


# ── Flow accumulator ─────────────────────────────────────────────────────
# One implementation of the CICFlowMeter feature semantics lives in
# src/capture/sniffer.py; the API server and this script must agree exactly.
from src.capture.sniffer import FlowAccumulator, parse_packet, FLOW_TIMEOUT_S  # noqa: E402


# ── Flow table ────────────────────────────────────────────────────────────


class FlowTable:
    """Thread-safe table of active flows, keyed by 5-tuple."""

    def __init__(self, timeout: float = 60.0):
        self.timeout = timeout
        self._flows: dict[tuple, FlowAccumulator] = {}
        self._lock = threading.Lock()

    def process_packet(self, pkt) -> Optional[FlowAccumulator]:
        """Called by scapy for each captured packet.

        Returns the flow if this packet completed it (RST / both FINs), so the
        caller can classify it immediately; otherwise None.
        """
        rec = parse_packet(pkt)
        if rec is None:
            return None
        (src_ip, dst_ip, src_port, dst_port, proto,
         payload_len, header_len, tcp_flags, win_size, timestamp) = rec

        fwd_key = (src_ip, dst_ip, src_port, dst_port, proto)
        bwd_key = (dst_ip, src_ip, dst_port, src_port, proto)

        with self._lock:
            if fwd_key in self._flows:
                key, flow, is_fwd = fwd_key, self._flows[fwd_key], True
            elif bwd_key in self._flows:
                key, flow, is_fwd = bwd_key, self._flows[bwd_key], False
            else:
                key, is_fwd = fwd_key, True
                flow = FlowAccumulator(src_ip=src_ip, dst_ip=dst_ip,
                                       src_port=src_port, dst_port=dst_port, protocol=proto)
                self._flows[key] = flow
            flow.add_packet(payload_len, is_fwd, timestamp, tcp_flags, win_size, header_len)
            if flow.closed:
                return self._flows.pop(key)
        return None

    def flush_expired(self, now: float) -> list[FlowAccumulator]:
        """Remove and return flows that have been idle longer than timeout."""
        expired = []
        with self._lock:
            keys_to_remove = []
            for key, flow in self._flows.items():
                if (now - flow.last_time) > self.timeout or (now - flow.start_time) > FLOW_TIMEOUT_S:
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


def send_flow_to_api(client: ApiClient, flow: FlowAccumulator, verbose: bool = False) -> Optional[dict]:
    """POST a flow to the NetSentry predict API. Returns response dict or None."""
    body = client.predict(flow.to_features(), flow.src_ip)
    if body is None:
        return None

    result = body.get("result", {})
    prediction = result.get("prediction", "?")
    confidence = result.get("confidence", 0)
    is_attack = result.get("is_attack", False)
    alert_id = body.get("alert_id")

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


# ── Flush loop ────────────────────────────────────────────────────────────


def classify_flow(flow: FlowAccumulator, client: ApiClient, verbose: bool,
                  min_packets: int, stats: dict) -> None:
    """Send one completed flow for classification and update counters."""
    if flow.fwd_packets + flow.bwd_packets < min_packets:
        stats["skipped"] += 1
        return
    stats["classified"] += 1
    result = send_flow_to_api(client, flow, verbose=verbose)
    if result and result.get("result", {}).get("is_attack"):
        stats["attacks"] += 1


def flush_loop(flow_table: FlowTable, client: ApiClient, interval: float,
               verbose: bool, min_packets: int, stats: dict):
    """Background thread: periodically flush expired flows and classify them."""
    while stats.get("running", True):
        time.sleep(interval)
        for flow in flow_table.flush_expired(time.time()):
            classify_flow(flow, client, verbose, min_packets, stats)


# ── Main ──────────────────────────────────────────────────────────────────


def parse_args():
    p = argparse.ArgumentParser(description="NetSentry live traffic capture")
    p.add_argument("--iface", default=None,
                   help="Network interface (default: scapy default)")
    p.add_argument("--pcap", default=None,
                   help="Read from pcap file instead of live capture (no sudo needed)")
    p.add_argument("--api", default="http://localhost:8000/api/v1",
                   help="NetSentry API base URL")
    p.add_argument("--username", default="admin", help="API login username")
    p.add_argument("--password", default="admin123", help="API login password")
    p.add_argument("--token", default=None,
                   help="Use a pre-issued JWT instead of logging in")
    p.add_argument("--rate-delay", type=float, default=0.3,
                   help="Delay between simulated flows (s); keep >0.25 to stay under the API rate limit")
    p.add_argument("--timeout", type=float, default=30.0,
                   help="Flow idle timeout in seconds before classification")
    p.add_argument("--flush-interval", type=float, default=5.0,
                   help="How often to check for expired flows (seconds)")
    p.add_argument("--min-packets", type=int, default=2,
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

    client = ApiClient(args.api, args.username, args.password, token=args.token)
    args_client = client
    if client.token() is None:
        print(f"\033[91m  WARNING: could not authenticate to API — predictions will fail.\033[0m")

    flow_table = FlowTable(timeout=args.timeout)
    stats = {"running": True, "classified": 0, "attacks": 0, "skipped": 0, "packets": 0}

    # Start flush thread
    flusher = threading.Thread(
        target=flush_loop,
        args=(flow_table, client, args.flush_interval, args.verbose, args.min_packets, stats),
        daemon=True,
    )
    flusher.start()

    # Packet counter callback
    def on_packet(pkt):
        stats["packets"] += 1
        closed = flow_table.process_packet(pkt)
        if closed is not None:  # RST / both FINs seen: classify right away
            classify_flow(closed, args_client, args.verbose, args.min_packets, stats)
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
    for flow in flow_table.flush_all():
        classify_flow(flow, client, args.verbose, args.min_packets, stats)

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

    client = ApiClient(args.api, args.username, args.password, token=args.token)
    if client.token() is None:
        print(f"\033[91m  ERROR: could not authenticate to API. Check --username/--password.\033[0m")
        sys.exit(1)

    stats = {"classified": 0, "attacks": 0, "blocked": 0}
    correct = 0
    fake_ips = {}

    for i, idx in enumerate(selected):
        features = {FEATURE_NAMES[j]: float(X[idx][j]) for j in range(len(FEATURE_NAMES))}
        true_class = CLASS_NAMES[y[idx]]

        # Generate a fake source IP for each flow
        if idx not in fake_ips:
            b2 = (idx // 256) % 256
            b3 = idx % 256
            fake_ips[idx] = f"203.0.{b2}.{b3}" if true_class != "BENIGN" else f"10.0.{b2}.{b3}"

        source_ip = fake_ips[idx]
        body = client.predict(features, source_ip)
        if body is None:
            print(f"  \033[93m[ERROR]\033[0m Flow {i}: no response")
            time.sleep(args.rate_delay)
            continue

        result = body.get("result", {})
        prediction = result.get("prediction", "?")
        confidence = result.get("confidence", 0)
        is_attack = result.get("is_attack", False)
        alert_id = body.get("alert_id")

        stats["classified"] += 1
        match = prediction == true_class
        if match:
            correct += 1
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

        # Small delay to simulate real-time (and stay under the API rate limit)
        time.sleep(args.rate_delay)

    stats["accuracy"] = correct / stats["classified"] if stats["classified"] else 0.0

    # Check blocked IPs
    try:
        blocked = client.get("/blocked") or []
        stats["blocked"] = len(blocked)
    except Exception:
        pass

    print(f"\n{'=' * 70}")
    print(f"  SIMULATION SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Flows classified:  {stats['classified']}")
    print(f"  Accuracy vs label: {stats['accuracy']:.1%}")
    print(f"  Attacks detected:  {stats['attacks']}")
    print(f"  IPs blocked:       {stats['blocked']}")
    print(f"{'=' * 70}\n")

    if stats["blocked"] > 0:
        print(f"  Blocked IPs:")
        try:
            for b in (client.get("/blocked") or [])[:20]:
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
