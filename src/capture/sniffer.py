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

# ── CICFlowMeter conventions ─────────────────────────────────────────────
# The model is trained on CIC-IDS2017 flows produced by CICFlowMeter, so live
# features must be computed the same way or the model sees a shifted
# distribution:
#   * packet "length" features use TRANSPORT PAYLOAD bytes, not frame length
#   * "Fwd Header Length" sums TRANSPORT headers only (TCP data offset / 8 for UDP)
#   * a silence > 5 s splits active/idle periods
#   * a flow is cut 120 s after its first packet
#   * a flow ends on RST, or once both sides have sent FIN
# (verified against CICFlowMeter BasicFlow.java / FlowGenerator.java / Cmd.java)
ACTIVITY_TIMEOUT_S = 5.0
FLOW_TIMEOUT_S = 120.0

TCP_FIN, TCP_SYN, TCP_RST = 0x01, 0x02, 0x04


def parse_packet(pkt) -> Optional[tuple]:
    """Reduce a scapy packet to CICFlowMeter-style fields.

    Returns (src_ip, dst_ip, src_port, dst_port, proto, payload_len,
             header_len, tcp_flags, win_size, timestamp) or None for non-IP.
    payload_len is derived from the IP total length so Ethernet padding on
    tiny frames is never counted.
    """
    if not pkt.haslayer(IP):
        return None
    ip = pkt[IP]
    ip_hdr = ip.ihl * 4
    ip_total = ip.len if ip.len is not None else len(ip)
    src_port = dst_port = 0
    tcp_flags = win_size = 0

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        src_port, dst_port = tcp.sport, tcp.dport
        tcp_flags = int(tcp.flags)
        win_size = tcp.window
        header_len = (tcp.dataofs or 5) * 4
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        src_port, dst_port = udp.sport, udp.dport
        header_len = 8
    else:
        header_len = 0

    payload_len = max(0, ip_total - ip_hdr - header_len)
    return (ip.src, ip.dst, src_port, dst_port, int(ip.proto),
            payload_len, header_len, tcp_flags, win_size, float(pkt.time))


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
    last_classified_pkts: int = 0  # packet count at last in-flight classification
    fwd_fin: bool = False
    bwd_fin: bool = False
    rst: bool = False

    @property
    def closed(self) -> bool:
        """CICFlowMeter ends a flow on RST or once both directions sent FIN."""
        return self.rst or (self.fwd_fin and self.bwd_fin)

    def add_packet(self, length: int, is_forward: bool, timestamp: float,
                   tcp_flags: int = 0, win_size: int = 0, header_len: int = 0):
        """`length` = transport payload bytes, `header_len` = transport header bytes."""
        now = timestamp
        if self.fwd_packets + self.bwd_packets == 0:
            # first packet (don't use 0.0 as a sentinel — pcap/test clocks can be 0)
            self.start_time = now
            self._active_start = now
            self._last_fwd_time = now
            self._last_bwd_time = now
        else:
            gap = now - self.last_time
            if gap > ACTIVITY_TIMEOUT_S:
                # CICFlowMeter: the active period ends at the last packet BEFORE
                # the silence; the silence itself is the idle period. Flows with
                # no such gap keep active/idle at 0 — matches the training data.
                self.active_times.append(self.last_time - self._active_start)
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
            if tcp_flags & TCP_FIN:
                self.fin_count += 1
                if is_forward:
                    self.fwd_fin = True
                else:
                    self.bwd_fin = True
            if tcp_flags & TCP_SYN: self.syn_count += 1
            if tcp_flags & TCP_RST:
                self.rst_count += 1
                self.rst = True
            if tcp_flags & 0x08: self.psh_count += 1
            if tcp_flags & 0x10: self.ack_count += 1
            if tcp_flags & 0x20: self.urg_count += 1

    def to_features(self) -> dict:
        duration_us = (self.last_time - self.start_time) * 1_000_000
        duration_s = self.last_time - self.start_time
        total_pkts = self.fwd_packets + self.bwd_packets
        total_bytes = sum(self.all_lengths)
        # CICFlowMeter divides by a zero duration -> "Infinity" in the CSV, which
        # the dataset loader stores as 0. Emit 0 here too so live flows agree.
        bytes_per_sec = total_bytes / duration_s if duration_s > 0 else 0.0
        pkts_per_sec = total_pkts / duration_s if duration_s > 0 else 0.0

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
            "flow_bytes_per_sec": bytes_per_sec,
            "flow_packets_per_sec": pkts_per_sec,
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
        flush_interval: float = 2.0,
        min_packets: int = 2,  # a probe + its reply is a complete (and telling) flow
        bpf_filter: str = "ip",
        active_classify_min_new_packets: int = 20,
    ):
        self._on_flow = on_flow  # callback(features_dict, source_ip)
        self._on_packet_cb = on_packet_cb  # callback(src_ip, dst_ip, length) — every packet
        self._interface = interface
        self._flow_timeout = flow_timeout
        self._flush_interval = flush_interval
        self._min_packets = min_packets
        self._bpf_filter = bpf_filter
        # Classify long-lived/high-volume flows in-flight (before they expire)
        # so floods and scans are detected live, not 30s after they stop.
        self._active_classify_min_new_packets = active_classify_min_new_packets

        self._flows: dict[tuple, FlowAccumulator] = {}
        self._flow_lock = threading.Lock()
        self._running = False
        self._sniff_thread: Optional[threading.Thread] = None
        self._flush_thread: Optional[threading.Thread] = None

        # Every packet pushed individually for real-time visibility

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
        rec = parse_packet(pkt)
        if rec is None:
            return
        (src_ip, dst_ip, src_port, dst_port, proto,
         payload_len, header_len, tcp_flags, win_size, timestamp) = rec

        fwd_key = (src_ip, dst_ip, src_port, dst_port, proto)
        bwd_key = (dst_ip, src_ip, dst_port, src_port, proto)

        closed_flow = None
        with self._flow_lock:
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
                closed_flow = self._flows.pop(key)

        self._packets_captured += 1

        if self._on_packet_cb:
            proto_name = "TCP" if proto == 6 else ("UDP" if proto == 17 else "OTHER")
            self._on_packet_cb(src_ip, dst_ip, src_port, dst_port, proto_name, len(pkt))

        # RST / bidirectional FIN: the flow is complete — classify it now
        # instead of waiting for the idle timeout (this is how CICFlowMeter
        # cut the training flows, and it makes scan verdicts near-instant).
        if closed_flow is not None:
            self._classify_flow(closed_flow)

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
            self._classify_active()

    def _flush_expired(self):
        """Expire idle flows, and cut long-lived ones at FLOW_TIMEOUT_S like CICFlowMeter."""
        now = time.time()
        expired = []
        with self._flow_lock:
            to_remove = [
                k for k, f in self._flows.items()
                if (now - f.last_time) > self._flow_timeout
                or (now - f.start_time) > FLOW_TIMEOUT_S
            ]
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

    def _classify_active(self):
        """Classify still-open flows that have grown enough since last time.

        Without this, a sustained flood (one long-lived flow that never goes
        idle) is only classified after it stops and expires. Snapshotting
        features under the flow lock avoids racing the sniff thread's list
        appends. ponytail: builds features under the lock — fine for the small
        per-flow lists here; revisit if active_flows gets huge.
        """
        snapshots = []
        with self._flow_lock:
            for flow in self._flows.values():
                total_pkts = flow.fwd_packets + flow.bwd_packets
                if total_pkts < self._min_packets:
                    continue
                if total_pkts - flow.last_classified_pkts < self._active_classify_min_new_packets:
                    continue
                snapshots.append((flow.to_features(), flow.src_ip))
                flow.last_classified_pkts = total_pkts

        for features, src_ip in snapshots:
            self._flows_classified += 1
            try:
                self._on_flow(features, src_ip)
            except Exception as e:
                logger.error("Active flow classification error: %s", e)

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
