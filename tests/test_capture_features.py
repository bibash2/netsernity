"""Live feature extraction must match CICFlowMeter, which produced the training data."""

import pytest

scapy = pytest.importorskip("scapy.all")
from scapy.all import IP, TCP, UDP, Raw  # noqa: E402

from src.capture.sniffer import (  # noqa: E402
    ACTIVITY_TIMEOUT_S, FLOW_TIMEOUT_S, FlowAccumulator, PacketSniffer, parse_packet,
)


def _tcp(flags="S", payload=b"", sport=40000, dport=80, src="10.0.0.1", dst="10.0.0.2", t=0.0):
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, window=1024)
    if payload:
        pkt = pkt / Raw(payload)
    pkt = IP(bytes(pkt))  # re-parse so ip.len is populated like a captured frame
    pkt.time = t
    return pkt


def test_tcp_payload_and_transport_header_only():
    rec = parse_packet(_tcp("PA", b"x" * 100))
    _, _, sport, dport, proto, payload_len, header_len, flags, win, _ = rec
    assert (sport, dport, proto) == (40000, 80, 6)
    assert payload_len == 100          # payload, not the 140-byte frame
    assert header_len == 20            # TCP header only, no IP header
    assert flags & 0x08 and flags & 0x10
    assert win == 1024


def test_ethernet_padding_is_not_payload():
    raw = bytes(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(flags="A")) + b"\x00" * 6
    pkt = IP(raw)  # scapy parses the 6 trailing bytes as Padding
    assert parse_packet(pkt)[5] == 0


def test_udp_header_is_8_bytes():
    pkt = IP(bytes(IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=5353, dport=53) / Raw(b"q" * 30)))
    rec = parse_packet(pkt)
    assert rec[4] == 17 and rec[5] == 30 and rec[6] == 8


def test_non_ip_is_ignored():
    from scapy.all import ARP
    assert parse_packet(ARP()) is None


def test_flow_closes_on_rst_or_both_fins():
    f = FlowAccumulator("a", "b", 1, 2, 6)
    f.add_packet(0, True, 0.0, tcp_flags=0x02)    # SYN
    f.add_packet(0, False, 0.1, tcp_flags=0x12)   # SYN/ACK
    assert not f.closed
    f.add_packet(0, True, 0.2, tcp_flags=0x01)    # FIN one way only
    assert not f.closed
    f.add_packet(0, False, 0.3, tcp_flags=0x11)   # FIN/ACK back
    assert f.closed

    g = FlowAccumulator("a", "b", 1, 2, 6)
    g.add_packet(0, True, 0.0, tcp_flags=0x02)
    g.add_packet(0, False, 0.1, tcp_flags=0x14)   # RST/ACK (closed port)
    assert g.closed


def test_active_idle_split_uses_5s_threshold():
    f = FlowAccumulator("a", "b", 1, 2, 6)
    for t in (0.0, 2.0, 8.0):                     # gap 2 s stays active, gap 6 s is idle
        f.add_packet(10, True, t)
    assert ACTIVITY_TIMEOUT_S == 5.0
    assert f.idle_times == [6.0]
    assert f.active_times == [2.0]
    feats = f.to_features()
    assert feats["idle_mean"] == pytest.approx(6.0e6)      # microseconds
    assert feats["fwd_header_length"] == 0
    assert feats["packet_length_mean"] == 10


def test_sniffer_classifies_closed_flow_immediately_and_cuts_at_120s():
    seen = []
    sn = PacketSniffer(on_flow=lambda feats, ip: seen.append((ip, feats)), min_packets=2)

    sn._on_packet(_tcp("S", t=100.0))                                           # probe
    sn._on_packet(_tcp("RA", sport=80, dport=40000, src="10.0.0.2", dst="10.0.0.1", t=100.01))
    assert len(seen) == 1 and seen[0][0] == "10.0.0.1"   # verdict without waiting for idle timeout
    assert seen[0][1]["syn_flag_count"] == 1 and seen[0][1]["rst_flag_count"] == 1
    assert sn._flows == {}

    # long-lived flow: still active but older than FLOW_TIMEOUT_S -> cut like CICFlowMeter
    import time
    now = time.time()
    sn._on_packet(_tcp("PA", b"x", sport=50000, t=now - FLOW_TIMEOUT_S - 5))
    sn._on_packet(_tcp("PA", b"x", sport=50000, t=now - 1))
    sn._flush_expired()
    assert len(seen) == 2 and sn._flows == {}


def test_zero_duration_flow_has_zero_rates_like_the_dataset():
    f = FlowAccumulator("a", "b", 1, 2, 17)
    f.add_packet(50, True, 10.0)
    f.add_packet(50, False, 10.0)  # same microsecond
    feats = f.to_features()
    assert feats["flow_duration"] == 0
    assert feats["flow_bytes_per_sec"] == 0.0 and feats["flow_packets_per_sec"] == 0.0
