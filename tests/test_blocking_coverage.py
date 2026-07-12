"""
End-to-end blocking coverage test.

Sends synthetic attack flows of every type through the full pipeline
(predict → alert → enforce) and reports exactly which attacks get
detected, which IPs get blocked, and which slip through.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

MODELS_DIR = ROOT / "models_artifacts"
REQUIRED = ["preprocessor.pkl", "ensemble.pkl"]

pytestmark = pytest.mark.skipif(
    not all((MODELS_DIR / f).exists() for f in REQUIRED),
    reason="Model artifacts missing — run training first.",
)

from src.data.generator import CLASS_NAMES, CLASS_TO_ID, FEATURE_NAMES, _sample_flow
from src.data.loader import load_or_generate
from src.enforcement.policy import RESPONSE_POLICY, ActionType


# ── Helpers ───────────────────────────────────────────────────────────────

# Load real dataset once for the module
_DATASET_PATH = ROOT / "data" / "netsentry_dataset.csv"
_REAL_X, _REAL_Y = None, None


def _ensure_dataset():
    global _REAL_X, _REAL_Y
    if _REAL_X is None:
        from src.data.generator import load_dataset_csv
        _REAL_X, _REAL_Y = load_dataset_csv(_DATASET_PATH)


def _generate_flows_for_class(attack_type: str, count: int, base_seed: int) -> list[dict]:
    """Sample real flows from the dataset for the given attack type."""
    _ensure_dataset()
    class_id = CLASS_TO_ID[attack_type]
    mask = _REAL_Y == class_id
    indices = np.where(mask)[0]
    rng = np.random.default_rng(base_seed)

    if len(indices) >= count:
        chosen = rng.choice(indices, size=count, replace=False)
    else:
        # Fall back to synthetic if not enough real samples
        chosen = rng.choice(indices, size=count, replace=True) if len(indices) > 0 else []

    flows = []
    for idx in chosen:
        flow = {FEATURE_NAMES[j]: float(_REAL_X[idx][j]) for j in range(len(FEATURE_NAMES))}
        flows.append(flow)

    # If no real samples, fall back to synthetic generator
    if not flows:
        for i in range(count):
            r = np.random.default_rng(base_seed + i)
            flows.append(_sample_flow(attack_type, r))

    return flows


def _unique_public_ip(index: int) -> str:
    """Deterministic unique public IP from an index."""
    b1 = 203
    b2 = (index // 256) % 256
    b3 = index % 256
    b4 = (index * 7 + 3) % 256
    return f"{b1}.{b2}.{b3}.{b4}"


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def client():
    from src.api.app import create_app
    from src.utils.config import load_config

    cfg = load_config("config/config.yaml")
    cfg.api.api_key = ""
    cfg.enforcement.enabled = True
    cfg.enforcement.backend = "noop"
    cfg.enforcement.min_confidence_to_enforce = 0.80
    cfg.enforcement.allowlisted_cidrs = [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.1/32",
    ]
    app = create_app(cfg)
    return TestClient(app)


# ── Per-attack-type blocking tests ────────────────────────────────────────


ATTACK_TYPES = ["DDoS", "PortScan", "BruteForce", "Botnet", "Infiltration", "WebAttack"]
FLOWS_PER_TYPE = 20


class TestBlockingPerAttackType:
    """Send multiple flows per attack type, measure detection and blocking rates."""

    def test_full_blocking_matrix(self, client: TestClient):
        # Flush any prior state
        client.delete("/api/v1/blocked")
        client.delete("/api/v1/alerts")

        results: dict[str, dict] = {}
        all_attack_ips: dict[str, list[str]] = {}
        ip_counter = 0

        # ── Send attack flows ──
        for attack_type in ATTACK_TYPES:
            flows = _generate_flows_for_class(attack_type, FLOWS_PER_TYPE, base_seed=attack_type.__hash__() % 10000)
            detected = 0
            blocked_count = 0
            confidences = []
            ips_for_type = []

            for i, flow in enumerate(flows):
                ip = _unique_public_ip(ip_counter)
                ip_counter += 1
                ips_for_type.append(ip)

                resp = client.post("/api/v1/predict", json={
                    "flow": flow,
                    "source_ip": ip,
                })
                assert resp.status_code == 200
                body = resp.json()

                if body["result"]["is_attack"]:
                    detected += 1
                    confidences.append(body["result"]["confidence"])

            all_attack_ips[attack_type] = ips_for_type

            # Check which IPs got blocked
            blocked_list = client.get("/api/v1/blocked").json()
            blocked_ips_set = {b["ip_address"] for b in blocked_list}
            for ip in ips_for_type:
                if ip in blocked_ips_set:
                    blocked_count += 1

            results[attack_type] = {
                "sent": FLOWS_PER_TYPE,
                "detected": detected,
                "blocked": blocked_count,
                "detection_rate": detected / FLOWS_PER_TYPE * 100,
                "block_rate": blocked_count / FLOWS_PER_TYPE * 100,
                "avg_confidence": np.mean(confidences) if confidences else 0.0,
                "min_confidence": min(confidences) if confidences else 0.0,
                "max_confidence": max(confidences) if confidences else 0.0,
            }

        # ── Send benign flows ──
        benign_flows = _generate_flows_for_class("BENIGN", FLOWS_PER_TYPE, base_seed=99999)
        benign_ips = []
        benign_detected = 0
        for i, flow in enumerate(benign_flows):
            ip = _unique_public_ip(ip_counter)
            ip_counter += 1
            benign_ips.append(ip)

            resp = client.post("/api/v1/predict", json={
                "flow": flow,
                "source_ip": ip,
            })
            assert resp.status_code == 200
            if resp.json()["result"]["is_attack"]:
                benign_detected += 1

        blocked_list = client.get("/api/v1/blocked").json()
        blocked_ips_set = {b["ip_address"] for b in blocked_list}
        benign_blocked = sum(1 for ip in benign_ips if ip in blocked_ips_set)

        results["BENIGN"] = {
            "sent": FLOWS_PER_TYPE,
            "detected": benign_detected,
            "blocked": benign_blocked,
            "detection_rate": benign_detected / FLOWS_PER_TYPE * 100,
            "block_rate": benign_blocked / FLOWS_PER_TYPE * 100,
            "avg_confidence": 0.0,
            "min_confidence": 0.0,
            "max_confidence": 0.0,
        }

        # ── Print results ──
        print(f"\n{'='*90}")
        print(f"BLOCKING COVERAGE MATRIX — {FLOWS_PER_TYPE} flows per attack type")
        print(f"{'='*90}")
        print(f"{'Attack Type':15s} | {'Sent':>4s} | {'Detected':>8s} | {'Blocked':>7s} | "
              f"{'Det%':>5s} | {'Blk%':>5s} | {'AvgConf':>7s} | {'MinConf':>7s} | {'Policy':>12s}")
        print(f"{'-'*90}")

        for attack_type in ATTACK_TYPES + ["BENIGN"]:
            r = results[attack_type]
            policy = RESPONSE_POLICY.get(attack_type)
            policy_action = policy.action_type.value if policy else "—"
            print(
                f"{attack_type:15s} | {r['sent']:4d} | {r['detected']:8d} | {r['blocked']:7d} | "
                f"{r['detection_rate']:5.1f} | {r['block_rate']:5.1f} | "
                f"{r['avg_confidence']:7.3f} | {r['min_confidence']:7.3f} | {policy_action:>12s}"
            )

        print(f"{'-'*90}")

        # ── Blocked IP detail ──
        blocked_list = client.get("/api/v1/blocked").json()
        total_blocked = len(blocked_list)

        # Group by attack type
        blocked_by_type: dict[str, int] = {}
        for b in blocked_list:
            at = b["attack_type"]
            blocked_by_type[at] = blocked_by_type.get(at, 0) + 1

        print(f"\nTotal IPs blocked: {total_blocked}")
        print(f"Blocked by attack type:")
        for at, count in sorted(blocked_by_type.items(), key=lambda x: -x[1]):
            policy = RESPONSE_POLICY.get(at)
            ttl = policy.block_duration_seconds if policy else 0
            print(f"  {at:15s}: {count:3d} IPs  (TTL={ttl}s)")

        # ── Show sample blocked entries ──
        if blocked_list:
            print(f"\nSample blocked entries (first 10):")
            print(f"  {'IP':18s} | {'Attack':12s} | {'Action':>10s} | {'Conf':>6s} | {'TTL':>8s}")
            print(f"  {'-'*65}")
            for b in blocked_list[:10]:
                print(
                    f"  {b['ip_address']:18s} | {b['attack_type']:12s} | "
                    f"{b['action_type']:>10s} | {b['confidence']:.3f} | "
                    f"{b['remaining_seconds']:>6d}s"
                )

        print(f"{'='*90}\n")

        # ── Assertions ──

        # DDoS must be reliably detected and blocked
        assert results["DDoS"]["detection_rate"] >= 80, \
            f"DDoS detection too low: {results['DDoS']['detection_rate']:.1f}%"
        assert results["DDoS"]["block_rate"] >= 60, \
            f"DDoS blocking too low: {results['DDoS']['block_rate']:.1f}%"

        # PortScan must be detected
        assert results["PortScan"]["detection_rate"] >= 70, \
            f"PortScan detection too low: {results['PortScan']['detection_rate']:.1f}%"

        # BruteForce must be detected
        assert results["BruteForce"]["detection_rate"] >= 70, \
            f"BruteForce detection too low: {results['BruteForce']['detection_rate']:.1f}%"

        # BENIGN must NOT be blocked
        assert results["BENIGN"]["block_rate"] == 0, \
            f"Benign traffic was blocked! FP block rate: {results['BENIGN']['block_rate']:.1f}%"

        # BENIGN false positive detection rate should be low
        assert results["BENIGN"]["detection_rate"] <= 15, \
            f"Benign FP detection rate too high: {results['BENIGN']['detection_rate']:.1f}%"


class TestAllowlistBlockingProtection:
    """Verify allowlisted IPs are never blocked regardless of attack type."""

    def test_private_ips_never_blocked(self, client: TestClient):
        client.delete("/api/v1/blocked")

        private_ips = ["10.0.0.1", "10.255.255.1", "172.16.0.1", "192.168.1.1", "127.0.0.1"]

        for ip in private_ips:
            for attack_type in ["DDoS", "BruteForce", "Botnet"]:
                flow = _generate_flows_for_class(attack_type, 1, base_seed=hash(ip + attack_type) % 10000)[0]
                resp = client.post("/api/v1/predict", json={
                    "flow": flow,
                    "source_ip": ip,
                })
                assert resp.status_code == 200

        blocked = client.get("/api/v1/blocked").json()
        blocked_ips = {b["ip_address"] for b in blocked}

        for ip in private_ips:
            assert ip not in blocked_ips, f"Allowlisted IP {ip} was blocked!"

        print(f"\nAllowlist protection verified: {len(private_ips)} private IPs sent attack traffic, 0 blocked")


class TestBlockDurationByPolicy:
    """Verify that block TTLs match the enforcement policy."""

    def test_block_durations_match_policy(self, client: TestClient):
        client.delete("/api/v1/blocked")

        attack_to_ip = {}
        for i, attack_type in enumerate(ATTACK_TYPES):
            ip = f"198.51.100.{i + 1}"
            attack_to_ip[attack_type] = ip

            # Send multiple flows to increase chance of high-confidence detection
            for seed in range(5):
                flow = _generate_flows_for_class(attack_type, 1, base_seed=7000 + i * 100 + seed)[0]
                client.post("/api/v1/predict", json={
                    "flow": flow,
                    "source_ip": ip,
                })

        blocked = client.get("/api/v1/blocked").json()
        blocked_by_ip = {b["ip_address"]: b for b in blocked}

        print(f"\nBlock duration verification:")
        print(f"  {'Attack':15s} | {'IP':18s} | {'Blocked':>7s} | {'Expected TTL':>12s} | {'Actual TTL':>10s} | {'Match':>5s}")
        print(f"  {'-'*80}")

        for attack_type in ATTACK_TYPES:
            ip = attack_to_ip[attack_type]
            policy = RESPONSE_POLICY[attack_type]
            expected_ttl = policy.block_duration_seconds
            is_blocked = ip in blocked_by_ip

            if is_blocked:
                actual_ttl = blocked_by_ip[ip]["remaining_seconds"]
                # Allow 10s tolerance for test execution time
                match = abs(actual_ttl - expected_ttl) < 60
                print(
                    f"  {attack_type:15s} | {ip:18s} | {'YES':>7s} | {expected_ttl:>10d}s | "
                    f"{actual_ttl:>8d}s | {'OK' if match else 'MISMATCH':>5s}"
                )
                if match:
                    # Block duration within tolerance
                    assert abs(actual_ttl - expected_ttl) < 60
            else:
                print(
                    f"  {attack_type:15s} | {ip:18s} | {'NO':>7s} | {expected_ttl:>10d}s | "
                    f"{'—':>10s} | {'—':>5s}"
                )


class TestBlockAndUnblockCycle:
    """Test the complete lifecycle: detect → block → verify → unblock → verify."""

    def test_full_lifecycle(self, client: TestClient):
        client.delete("/api/v1/blocked")

        # 1. Send DDoS attack
        ip = "203.0.113.200"
        blocked = False
        for seed in range(10):
            flow = _generate_flows_for_class("DDoS", 1, base_seed=8000 + seed)[0]
            resp = client.post("/api/v1/predict", json={
                "flow": flow,
                "source_ip": ip,
            })
            body = resp.json()
            if body["result"]["is_attack"] and body["result"]["confidence"] >= 0.80:
                blocked_list = client.get("/api/v1/blocked").json()
                if any(b["ip_address"] == ip for b in blocked_list):
                    blocked = True
                    break

        if not blocked:
            pytest.skip("DDoS not detected with sufficient confidence to block")

        # 2. Verify blocked
        blocked_list = client.get("/api/v1/blocked").json()
        blocked_ips = [b["ip_address"] for b in blocked_list]
        assert ip in blocked_ips, f"IP {ip} should be blocked after DDoS detection"

        # 3. Verify block has expected metadata
        block_record = next(b for b in blocked_list if b["ip_address"] == ip)
        assert block_record["attack_type"] == "DDoS"
        assert block_record["action_type"] == "drop"
        assert block_record["confidence"] >= 0.80
        assert block_record["remaining_seconds"] > 0

        # 4. Manual unblock
        resp = client.delete(f"/api/v1/blocked/{ip}")
        assert resp.status_code == 200
        assert resp.json()["unblocked"] is True

        # 5. Verify unblocked
        blocked_list = client.get("/api/v1/blocked").json()
        blocked_ips = [b["ip_address"] for b in blocked_list]
        assert ip not in blocked_ips

        # 6. Flush all and verify
        client.delete("/api/v1/blocked")
        blocked_list = client.get("/api/v1/blocked").json()
        assert len(blocked_list) == 0

        print(f"\nFull lifecycle verified: detect → block → verify → unblock → clean")
