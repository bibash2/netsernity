"""
In-process packet sniffer.

Runs as a background thread, captures packets on a network interface,
aggregates them into flows, extracts CIC-IDS features, and feeds each
completed flow directly to the InferenceEngine + AlertManager (no HTTP).

Designed to start/stop from the API so the dashboard can control it.
"""

from __future__ import annotations

import math
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional, Callable

from ..utils.logger import get_logger

logger = get_logger(__name__)

# Try importing scapy — graceful fallback if not installed
try:
    from scapy.all import IP, TCP, UDP, sniff as scapy_sniff, conf as scapy_conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ── Flow accumulator ─────────────────────────────────────────────────────

@dataclass
class FlowAccumulator:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    start_time: float = 0.0
    last_time: float = 0.0
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_lengths: list = field(default_factory=list)
    bwd_lengths: list = field(default_factory=list)
    all_lengths: list = field(default_factory=list)
    fwd_iats: list = field(default_factory=list)
    bwd_iats: list = field(default_factory=list)
    _last_fwd_time: float = 0.0
    _last_bwd_time: float = 0.0
    fin_count: int = 0
    syn_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    ack_count: int = 0
    urg_count: int = 0
    init_win_fwd: int = -1
    init_win_bwd: int = -1
    fwd_header_bytes: int = 0
    active_times: list = field(default_factory=list)
    idle_times: list = field(default_factory=list)
    _active_start: float = 0.0

    def add_packet(self, length: int, is_forward: bool, timestamp: float,
                   tcp_flags: int = 0, win_size: int = 0, header_len: int = 0):
        now = timestamp
        if self.start_time == 0:
            self.start_time = now
            self._active_start = now
            self._last_fwd_time = now
            self._last_bwd_time = now

        if self.last_time > 0:
            gap = now - self.last_time
            if gap > 1.0:
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

        if tcp_flags:
            if tcp_flags & 0x01: self.fin_count += 1
            if tcp_flags & 0x02: self.syn_count += 1
            if tcp_flags & 0x04: self.rst_count += 1
            if tcp_flags & 0x08: self.psh_count += 1
            if tcp_flags & 0x10: self.ack_count += 1
            if tcp_flags & 0x20: self.urg_count += 1

    def to_features(self) -> dict:
        duration_us = (self.last_time - self.start_time) * 1_000_000
        duration_s = max(self.last_time - self.start_time, 1e-9)
        total_pkts = self.fwd_packets + self.bwd_packets
        total_bytes = sum(self.all_lengths)

        def _mean(lst): return sum(lst) / len(lst) if lst else 0.0
        def _std(lst):
            if len(lst) < 2: return 0.0
            m = _mean(lst)
            return math.sqrt(sum((x - m) ** 2 for x in lst) / len(lst))

        fwd_iats_us = [t * 1e6 for t in self.fwd_iats]
        bwd_iats_us = [t * 1e6 for t in self.bwd_iats]

        return {
            "flow_duration": duration_us,
            "total_fwd_packets": self.fwd_packets,
            "total_bwd_packets": self.bwd_packets,
            "fwd_packet_length_mean": _mean(self.fwd_lengths),
            "bwd_packet_length_mean": _mean(self.bwd_lengths),
            "flow_bytes_per_sec": total_bytes / duration_s,
            "flow_packets_per_sec": total_pkts / duration_s,
            "fwd_iat_mean": _mean(fwd_iats_us),
            "bwd_iat_mean": _mean(bwd_iats_us),
            "fwd_iat_std": _std(fwd_iats_us),
            "packet_length_mean": _mean(self.all_lengths),
            "packet_length_std": _std(self.all_lengths),
            "packet_length_variance": _std(self.all_lengths) ** 2,
            "fin_flag_count": self.fin_count,
            "syn_flag_count": self.syn_count,
            "rst_flag_count": self.rst_count,
            "psh_flag_count": self.psh_count,
            "ack_flag_count": self.ack_count,
            "urg_flag_count": self.urg_count,
            "down_up_ratio": (self.bwd_packets / self.fwd_packets) if self.fwd_packets else 0,
            "avg_packet_size": _mean(self.all_lengths),
            "fwd_segment_size_avg": _mean(self.fwd_lengths),
            "bwd_segment_size_avg": _mean(self.bwd_lengths),
            "subflow_fwd_packets": self.fwd_packets,
            "subflow_bwd_packets": self.bwd_packets,
            "init_win_bytes_fwd": self.init_win_fwd,
            "init_win_bytes_bwd": self.init_win_bwd,
            "active_mean": _mean([t * 1e6 for t in self.active_times]),
            "idle_mean": _mean([t * 1e6 for t in self.idle_times]),
            "fwd_header_length": self.fwd_header_bytes,
        }


# ── Packet sniffer ────────────────────────────────────────────────────────

class PacketSniffer:
    """Background packet sniffer that feeds flows to the inference pipeline."""

    def __init__(
        self,
        on_flow: Callable[[dict, str], None],
        on_packet_cb: Optional[Callable[[str, str, int], None]] = None,
        interface: Optional[str] = None,
        flow_timeout: float = 30.0,
        flush_interval: float = 5.0,
        min_packets: int = 3,
        bpf_filter: str = "ip",
    ):
        self._on_flow = on_flow  # callback(features_dict, source_ip)
        self._on_packet_cb = on_packet_cb  # callback(src_ip, dst_ip, length) — every packet
        self._interface = interface
        self._flow_timeout = flow_timeout
        self._flush_interval = flush_interval
        self._min_packets = min_packets
        self._bpf_filter = bpf_filter

        self._flows: dict[tuple, FlowAccumulator] = {}
        self._flow_lock = threading.Lock()
        self._running = False
        self._sniff_thread: Optional[threading.Thread] = None
        self._flush_thread: Optional[threading.Thread] = None

        # Packet batch for real-time push (batched every N packets)
        self._packet_batch_count = 0
        self._packet_batch_interval = 10  # push every N packets

        # Stats
        self._packets_captured = 0
        self._flows_classified = 0
        self._flows_skipped = 0
        self._attacks_detected = 0
        self._recent_flows: deque[dict] = deque(maxlen=100)
        self._stats_lock = threading.Lock()

    @property
    def available(self) -> bool:
        return SCAPY_AVAILABLE

    @property
    def running(self) -> bool:
        return self._running

    def start(self) -> bool:
        if not SCAPY_AVAILABLE:
            logger.error("scapy not installed — cannot start packet capture")
            return False
        if self._running:
            return True

        self._running = True
        self._sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True, name="sniffer")
        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True, name="flusher")
        self._sniff_thread.start()
        self._flush_thread.start()
        logger.info("Packet capture started on interface=%s filter=%s",
                     self._interface or "default", self._bpf_filter)
        return True

    def stop(self):
        if not self._running:
            return
        self._running = False
        # Flush remaining
        self._flush_all()
        logger.info("Packet capture stopped. packets=%d flows=%d attacks=%d",
                     self._packets_captured, self._flows_classified, self._attacks_detected)

    def stats(self) -> dict:
        with self._stats_lock:
            return {
                "running": self._running,
                "scapy_available": SCAPY_AVAILABLE,
                "interface": self._interface or "default",
                "packets_captured": self._packets_captured,
                "flows_classified": self._flows_classified,
                "flows_skipped": self._flows_skipped,
                "attacks_detected": self._attacks_detected,
                "active_flows": len(self._flows),
                "recent_flows": list(self._recent_flows),
            }

    def _on_packet(self, pkt):
        if not pkt.haslayer(IP):
            return

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

        length = len(pkt)
        timestamp = float(pkt.time)

        fwd_key = (src_ip, dst_ip, src_port, dst_port, proto)
        bwd_key = (dst_ip, src_ip, dst_port, src_port, proto)

        with self._flow_lock:
            if fwd_key in self._flows:
                self._flows[fwd_key].add_packet(length, True, timestamp, tcp_flags, win_size, header_len)
            elif bwd_key in self._flows:
                self._flows[bwd_key].add_packet(length, False, timestamp, tcp_flags, win_size, header_len)
            else:
                flow = FlowAccumulator(src_ip=src_ip, dst_ip=dst_ip,
                                        src_port=src_port, dst_port=dst_port, protocol=proto)
                flow.add_packet(length, True, timestamp, tcp_flags, win_size, header_len)
                self._flows[fwd_key] = flow

        self._packets_captured += 1

        # Push raw packet event in batches
        if self._on_packet_cb:
            self._packet_batch_count += 1
            if self._packet_batch_count >= self._packet_batch_interval:
                self._on_packet_cb(src_ip, dst_ip, self._packet_batch_count)
                self._packet_batch_count = 0

    def _sniff_loop(self):
        try:
            scapy_sniff(
                iface=self._interface,
                filter=self._bpf_filter,
                prn=self._on_packet,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except PermissionError:
            logger.error("Permission denied for packet capture. Run with sudo or grant BPF access.")
            self._running = False
        except Exception as e:
            logger.exception("Sniffer error: %s", e)
            self._running = False

    def _flush_loop(self):
        while self._running:
            time.sleep(self._flush_interval)
            self._flush_expired()

    def _flush_expired(self):
        now = time.time()
        expired = []
        with self._flow_lock:
            to_remove = [k for k, f in self._flows.items() if (now - f.last_time) > self._flow_timeout]
            for k in to_remove:
                expired.append(self._flows.pop(k))

        for flow in expired:
            self._classify_flow(flow)

    def _flush_all(self):
        with self._flow_lock:
            flows = list(self._flows.values())
            self._flows.clear()
        for flow in flows:
            self._classify_flow(flow)

    def _classify_flow(self, flow: FlowAccumulator):
        total_pkts = flow.fwd_packets + flow.bwd_packets
        if total_pkts < self._min_packets:
            self._flows_skipped += 1
            return

        features = flow.to_features()
        self._flows_classified += 1

        try:
            self._on_flow(features, flow.src_ip)
        except Exception as e:
            logger.error("Flow classification error: %s", e)

    def record_result(self, flow_features: dict, source_ip: str,
                      prediction: str, is_attack: bool, confidence: float, alert_id: Optional[str]):
        """Called after classification to record in recent flows for the dashboard."""
        entry = {
            "timestamp": time.time(),
            "source_ip": source_ip,
            "prediction": prediction,
            "is_attack": is_attack,
            "confidence": confidence,
            "alert_id": alert_id,
        }
        with self._stats_lock:
            self._recent_flows.append(entry)
            if is_attack:
                self._attacks_detected += 1
