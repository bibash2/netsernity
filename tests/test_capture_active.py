"""Active in-flight flow classification (floods detected before they expire)."""

from src.capture.sniffer import FlowAccumulator, PacketSniffer


def _make_flow(n_packets: int) -> FlowAccumulator:
    flow = FlowAccumulator(src_ip="203.0.113.5", dst_ip="10.0.0.1",
                           src_port=44444, dst_port=80, protocol=6)
    for i in range(n_packets):
        flow.add_packet(length=60, is_forward=True, timestamp=1000.0 + i * 0.001,
                        tcp_flags=0x02, win_size=1024, header_len=40)
    return flow


def test_active_flow_classified_without_eviction():
    seen = []
    sniffer = PacketSniffer(on_flow=lambda feats, ip: seen.append(ip),
                            active_classify_min_new_packets=20)

    key = ("203.0.113.5", "10.0.0.1", 44444, 80, 6)
    sniffer._flows[key] = _make_flow(25)  # long-lived flow, never expired

    sniffer._classify_active()
    assert seen == ["203.0.113.5"]          # classified while still open
    assert key in sniffer._flows            # NOT evicted

    # No new growth -> no duplicate classification.
    sniffer._classify_active()
    assert seen == ["203.0.113.5"]

    # Grow past the threshold -> classified again (ongoing attack stays live).
    for i in range(20):
        sniffer._flows[key].add_packet(60, True, 1001.0 + i * 0.001, 0x02, 1024, 40)
    sniffer._classify_active()
    assert seen == ["203.0.113.5", "203.0.113.5"]


def test_active_skips_tiny_flows():
    seen = []
    sniffer = PacketSniffer(on_flow=lambda feats, ip: seen.append(ip),
                            min_packets=3, active_classify_min_new_packets=20)
    sniffer._flows[("a", "b", 1, 2, 6)] = _make_flow(2)  # below min_packets
    sniffer._classify_active()
    assert seen == []
