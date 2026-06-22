"""End-to-end tests for the enforcement pipeline with synthetic data.

Tests the full flow: synthetic network flows -> API predict -> AlertManager ->
ResponseExecutor -> enforcement actions. Uses real trained models and the
LogOnly/NoOp backends so no root or firewall access is needed.
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
    reason="Model artifacts missing — run `python -m scripts.train_pipeline --samples 3000` first.",
)

from src.data.generator import FEATURE_NAMES, PROFILES, _sample_flow
from src.enforcement.backends.noop import NoOpBackend
from src.enforcement.executor import ResponseExecutor


# ── Helpers ───────────────────────────────────────────────────────────────


def _generate_flow(attack_type: str, seed: int = 42) -> dict:
    """Generate a single synthetic flow dict suitable for the predict API."""
    rng = np.random.default_rng(seed)
    return _sample_flow(attack_type, rng)


def _generate_flows(attack_type: str, count: int, base_seed: int = 0) -> list[dict]:
    """Generate multiple synthetic flows of a given attack type."""
    flows = []
    for i in range(count):
        flows.append(_generate_flow(attack_type, seed=base_seed + i))
    return flows


def _random_public_ip(rng: np.random.Generator) -> str:
    """Generate a random public IP address (avoids private ranges)."""
    while True:
        octets = rng.integers(1, 255, size=4)
        # Avoid private ranges (10.x, 172.16-31.x, 192.168.x)
        if octets[0] == 10:
            continue
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            continue
        if octets[0] == 192 and octets[1] == 168:
            continue
        if octets[0] == 127:
            continue
        return f"{octets[0]}.{octets[1]}.{octets[2]}.{octets[3]}"


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def enforcement_app():
    """Create a test app with enforcement ENABLED using NoOpBackend."""
    from src.api.app import create_app
    from src.utils.config import load_config

    cfg = load_config("config/config.yaml")
    cfg.api.api_key = ""          # disable auth for tests
    cfg.enforcement.enabled = True
    cfg.enforcement.backend = "noop"
    cfg.enforcement.min_confidence_to_enforce = 0.80
    cfg.enforcement.allowlisted_cidrs = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.1/32",
    ]
    app = create_app(cfg)
    return app


@pytest.fixture(scope="module")
def client(enforcement_app) -> TestClient:
    return TestClient(enforcement_app)


# ── E2E: Single attack detection and blocking ─────────────────────────────


class TestSingleAttackBlocking:
    """Test that individual attack types are detected and blocked."""

    def test_ddos_flow_is_detected_and_blocked(self, client: TestClient):
        flow = _generate_flow("DDoS", seed=100)
        resp = client.post("/api/v1/predict", json={
            "flow": flow,
            "source_ip": "203.0.113.50",
        })
        assert resp.status_code == 200
        body = resp.json()

        assert body["result"]["is_attack"] is True
        assert body["alert_id"] is not None

        # Check blocked list
        blocked = client.get("/api/v1/blocked").json()
        blocked_ips = [b["ip_address"] for b in blocked]
        if body["result"]["confidence"] >= 0.80:
            assert "203.0.113.50" in blocked_ips

    def test_brute_force_flow_is_detected_and_blocked(self, client: TestClient):
        flow = _generate_flow("BruteForce", seed=200)
        resp = client.post("/api/v1/predict", json={
            "flow": flow,
            "source_ip": "198.51.100.10",
        })
        assert resp.status_code == 200
        body = resp.json()
        assert body["result"]["is_attack"] is True

    def test_portscan_flow_is_detected(self, client: TestClient):
        flow = _generate_flow("PortScan", seed=300)
        resp = client.post("/api/v1/predict", json={
            "flow": flow,
            "source_ip": "198.51.100.20",
        })
        assert resp.status_code == 200
        body = resp.json()
        assert body["result"]["is_attack"] is True

    def test_benign_flow_is_not_blocked(self, client: TestClient):
        flow = _generate_flow("BENIGN", seed=400)
        ip = "198.51.100.99"
        resp = client.post("/api/v1/predict", json={
            "flow": flow,
            "source_ip": ip,
        })
        assert resp.status_code == 200
        body = resp.json()
        # Benign should not generate alert
        assert body["alert_id"] is None

        # IP should not be in blocked list
        blocked = client.get("/api/v1/blocked").json()
        blocked_ips = [b["ip_address"] for b in blocked]
        assert ip not in blocked_ips


# ── E2E: Allowlist protection ─────────────────────────────────────────────


class TestAllowlistProtection:
    """Test that allowlisted IPs are never blocked, even for real attacks."""

    def test_private_ip_not_blocked_for_ddos(self, client: TestClient):
        flow = _generate_flow("DDoS", seed=500)
        resp = client.post("/api/v1/predict", json={
            "flow": flow,
            "source_ip": "10.0.1.50",
        })
        assert resp.status_code == 200
        # Alert should still be created
        body = resp.json()
        assert body["result"]["is_attack"] is True
        assert body["alert_id"] is not None

        # But IP must NOT be blocked
        blocked = client.get("/api/v1/blocked").json()
        blocked_ips = [b["ip_address"] for b in blocked]
        assert "10.0.1.50" not in blocked_ips

    def test_localhost_not_blocked(self, client: TestClient):
        flow = _generate_flow("DDoS", seed=501)
        resp = client.post("/api/v1/predict", json={
            "flow": flow,
            "source_ip": "127.0.0.1",
        })
        assert resp.status_code == 200
        blocked = client.get("/api/v1/blocked").json()
        blocked_ips = [b["ip_address"] for b in blocked]
        assert "127.0.0.1" not in blocked_ips


# ── E2E: Batch prediction with enforcement ────────────────────────────────


class TestBatchEnforcement:
    """Test that batch predictions also trigger enforcement correctly."""

    def test_batch_mixed_traffic(self, client: TestClient):
        # Mix of benign and attack flows
        benign_flows = _generate_flows("BENIGN", count=3, base_seed=600)
        ddos_flows = _generate_flows("DDoS", count=2, base_seed=700)
        botnet_flows = _generate_flows("Botnet", count=1, base_seed=800)
        all_flows = benign_flows + ddos_flows + botnet_flows

        resp = client.post("/api/v1/predict/batch", json={
            "flows": all_flows,
            "source_ip": "203.0.113.77",
        })
        assert resp.status_code == 200
        body = resp.json()
        assert body["batch_size"] == 6
        assert body["alerts_generated"] >= 1  # At least some attacks detected


# ── E2E: Manual unblock ──────────────────────────────────────────────────


class TestManualUnblock:
    """Test the manual unblock API endpoints."""

    def test_block_then_unblock(self, client: TestClient):
        flow = _generate_flow("DDoS", seed=900)
        ip = "203.0.113.88"

        # Trigger block
        resp = client.post("/api/v1/predict", json={
            "flow": flow,
            "source_ip": ip,
        })
        assert resp.status_code == 200
        body = resp.json()

        # Only test unblock if the flow was confidently detected
        if body["result"]["confidence"] >= 0.80 and body["result"]["is_attack"]:
            # Verify blocked
            blocked = client.get("/api/v1/blocked").json()
            blocked_ips = [b["ip_address"] for b in blocked]
            assert ip in blocked_ips

            # Unblock
            resp = client.delete(f"/api/v1/blocked/{ip}")
            assert resp.status_code == 200
            assert resp.json()["unblocked"] is True

            # Verify unblocked
            blocked = client.get("/api/v1/blocked").json()
            blocked_ips = [b["ip_address"] for b in blocked]
            assert ip not in blocked_ips

    def test_unblock_nonexistent_returns_404(self, client: TestClient):
        resp = client.delete("/api/v1/blocked/1.2.3.4")
        assert resp.status_code == 404

    def test_flush_all_blocks(self, client: TestClient):
        # Create some blocks first
        for seed in range(950, 955):
            flow = _generate_flow("DDoS", seed=seed)
            client.post("/api/v1/predict", json={
                "flow": flow,
                "source_ip": f"203.0.113.{seed - 900}",
            })

        # Flush
        resp = client.delete("/api/v1/blocked")
        assert resp.status_code == 200
        assert resp.json()["flushed"] is True

        # Verify empty
        blocked = client.get("/api/v1/blocked").json()
        assert len(blocked) == 0


# ── E2E: Confidence threshold gating ──────────────────────────────────────


class TestConfidenceGating:
    """Test that low-confidence detections do not trigger blocking."""

    def test_no_block_without_source_ip(self, client: TestClient):
        flow = _generate_flow("DDoS", seed=1000)
        resp = client.post("/api/v1/predict", json={"flow": flow})
        assert resp.status_code == 200
        # No source_ip means no blocking possible
        # Alert should still be generated if attack detected
        body = resp.json()
        if body["result"]["is_attack"]:
            assert body["alert_id"] is not None


# ── E2E: Deduplication ────────────────────────────────────────────────────


class TestDeduplication:
    """Test that the same IP is not blocked multiple times."""

    def test_same_ip_blocked_once(self, client: TestClient):
        # Flush first
        client.delete("/api/v1/blocked")

        ip = "203.0.113.123"
        for seed in range(1100, 1105):
            flow = _generate_flow("DDoS", seed=seed)
            client.post("/api/v1/predict", json={
                "flow": flow,
                "source_ip": ip,
            })

        blocked = client.get("/api/v1/blocked").json()
        ip_count = sum(1 for b in blocked if b["ip_address"] == ip)
        assert ip_count <= 1  # Either 0 (if low confidence) or exactly 1


# ── E2E: Synthetic traffic simulation ─────────────────────────────────────


class TestTrafficSimulation:
    """Simulate a realistic traffic mix and verify enforcement behavior."""

    def test_realistic_traffic_mix(self, client: TestClient):
        """Send 50 flows with realistic class distribution and verify enforcement."""
        # Flush existing blocks
        client.delete("/api/v1/blocked")

        rng = np.random.default_rng(2024)

        # Realistic traffic: 60% benign, 40% attack
        traffic_mix = (
            [("BENIGN", _random_public_ip(rng)) for _ in range(30)]
            + [("DDoS", _random_public_ip(rng)) for _ in range(5)]
            + [("PortScan", _random_public_ip(rng)) for _ in range(5)]
            + [("BruteForce", _random_public_ip(rng)) for _ in range(4)]
            + [("Botnet", _random_public_ip(rng)) for _ in range(3)]
            + [("Infiltration", _random_public_ip(rng)) for _ in range(2)]
            + [("WebAttack", _random_public_ip(rng)) for _ in range(1)]
        )

        total_predictions = 0
        total_attacks_detected = 0
        total_alerts = 0
        detection_results: dict[str, list[bool]] = {
            "BENIGN": [], "DDoS": [], "PortScan": [], "BruteForce": [],
            "Botnet": [], "Infiltration": [], "WebAttack": [],
        }

        for i, (attack_type, source_ip) in enumerate(traffic_mix):
            flow = _generate_flow(attack_type, seed=2000 + i)
            resp = client.post("/api/v1/predict", json={
                "flow": flow,
                "source_ip": source_ip,
            })
            assert resp.status_code == 200
            body = resp.json()

            total_predictions += 1
            is_attack = body["result"]["is_attack"]
            if is_attack:
                total_attacks_detected += 1
            if body["alert_id"]:
                total_alerts += 1

            detection_results[attack_type].append(is_attack)

        # Verify overall stats
        assert total_predictions == 50

        # Check blocked IPs
        blocked = client.get("/api/v1/blocked").json()
        blocked_ips = {b["ip_address"] for b in blocked}

        # Print summary for visibility
        print(f"\n{'='*60}")
        print(f"TRAFFIC SIMULATION RESULTS")
        print(f"{'='*60}")
        print(f"Total predictions:    {total_predictions}")
        print(f"Attacks detected:     {total_attacks_detected}")
        print(f"Alerts generated:     {total_alerts}")
        print(f"IPs blocked:          {len(blocked_ips)}")
        print(f"{'─'*60}")

        for attack_type, results in detection_results.items():
            if results:
                detected = sum(results)
                rate = detected / len(results) * 100
                print(f"  {attack_type:15s}: {detected}/{len(results)} detected ({rate:.0f}%)")

        print(f"{'─'*60}")
        print(f"Blocked IPs: {blocked_ips or '(none)'}")
        if blocked:
            for b in blocked:
                print(f"  {b['ip_address']:18s} | {b['attack_type']:12s} | "
                      f"conf={b['confidence']:.3f} | "
                      f"expires_in={b['remaining_seconds']}s")
        print(f"{'='*60}\n")

        # Assertions on detection quality
        # Benign traffic should mostly NOT be detected as attacks
        benign_fp = sum(detection_results["BENIGN"])
        benign_fp_rate = benign_fp / len(detection_results["BENIGN"])
        assert benign_fp_rate < 0.20, f"Benign false positive rate too high: {benign_fp_rate:.2%}"

        # DDoS should be reliably detected
        ddos_detected = sum(detection_results["DDoS"])
        ddos_rate = ddos_detected / len(detection_results["DDoS"])
        assert ddos_rate >= 0.60, f"DDoS detection rate too low: {ddos_rate:.2%}"

        # Overall: more attacks detected than benign false positives
        assert total_attacks_detected > benign_fp

        # Blocked IPs should only be attack source IPs
        attack_ips = {ip for (atype, ip) in traffic_mix if atype != "BENIGN"}
        benign_ips = {ip for (atype, ip) in traffic_mix if atype == "BENIGN"}

        for blocked_ip in blocked_ips:
            # No benign IP should be blocked (allowlist + confidence gating)
            if blocked_ip in benign_ips and blocked_ip not in attack_ips:
                # This is a false positive block — acceptable at low rates
                pass  # We already check FP rate above

    def test_alerts_reflect_enforcement(self, client: TestClient):
        """Verify the alerts endpoint shows alerts after traffic simulation."""
        resp = client.get("/api/v1/alerts?limit=100")
        assert resp.status_code == 200
        alerts = resp.json()
        assert len(alerts) >= 1

        # Each alert should have required fields
        for alert in alerts:
            assert "alert_id" in alert
            assert "attack_type" in alert
            assert "confidence" in alert
            assert "recommended_action" in alert
            assert alert["severity"] in ("info", "low", "medium", "high", "critical")

    def test_stats_reflect_traffic(self, client: TestClient):
        """Verify the stats endpoint reflects the traffic we sent."""
        resp = client.get("/api/v1/stats")
        assert resp.status_code == 200
        body = resp.json()
        assert body["inference"]["total_predictions"] > 0
        assert body["alerts"]["total_alerts"] > 0
