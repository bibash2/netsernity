"""Tests for the enforcement module."""

from __future__ import annotations

import pytest

from src.enforcement.allowlist import Allowlist
from src.enforcement.backends.noop import NoOpBackend
from src.enforcement.executor import ResponseExecutor
from src.enforcement.policy import RESPONSE_POLICY, ActionType


# ── Fixtures ──────────────────────────────────────────────────────────────


def _make_executor(
    enabled: bool = True,
    min_confidence: float = 0.90,
    allowlisted_cidrs: list[str] | None = None,
    max_blocked_ips: int = 10000,
) -> tuple[ResponseExecutor, NoOpBackend]:
    backend = NoOpBackend()
    allowlist = Allowlist(allowlisted_cidrs or ["10.0.0.0/8", "127.0.0.1/32"])
    executor = ResponseExecutor(
        backend=backend,
        allowlist=allowlist,
        enabled=enabled,
        min_confidence_override=min_confidence,
        max_blocked_ips=max_blocked_ips,
    )
    executor.setup()
    return executor, backend


def _make_alert(
    attack_type: str = "DDoS",
    confidence: float = 0.95,
    source_ip: str = "203.0.113.1",
    alert_id: str = "ALT-00000001",
) -> dict:
    return {
        "alert_id": alert_id,
        "timestamp": "2026-04-22T10:00:00Z",
        "severity": "critical",
        "attack_type": attack_type,
        "confidence": confidence,
        "anomaly_score": 0.8,
        "anomaly_flagged": True,
        "source_ip": source_ip,
        "recommended_action": "drop_and_notify_upstream",
        "probabilities": {"BENIGN": 0.02, "DDoS": 0.95},
    }


# ── Policy tests ──────────────────────────────────────────────────────────


class TestResponsePolicy:
    def test_benign_is_allow(self):
        assert RESPONSE_POLICY["BENIGN"].action_type == ActionType.ALLOW
        assert not RESPONSE_POLICY["BENIGN"].is_blocking

    def test_ddos_is_drop(self):
        assert RESPONSE_POLICY["DDoS"].action_type == ActionType.DROP
        assert RESPONSE_POLICY["DDoS"].is_blocking

    def test_all_attack_types_have_policy(self):
        expected = {"BENIGN", "PortScan", "WebAttack", "BruteForce", "Botnet", "Infiltration", "DDoS"}
        assert set(RESPONSE_POLICY.keys()) == expected


# ── Allowlist tests ───────────────────────────────────────────────────────


class TestAllowlist:
    def test_private_ip_is_allowed(self):
        al = Allowlist(["10.0.0.0/8"])
        assert al.is_allowed("10.1.2.3")

    def test_public_ip_is_not_allowed(self):
        al = Allowlist(["10.0.0.0/8"])
        assert not al.is_allowed("203.0.113.1")

    def test_invalid_cidr_is_skipped(self):
        al = Allowlist(["not-a-cidr", "10.0.0.0/8"])
        assert len(al.networks) == 1
        assert al.is_allowed("10.0.0.1")

    def test_invalid_ip_returns_false(self):
        al = Allowlist(["10.0.0.0/8"])
        assert not al.is_allowed("not-an-ip")

    def test_localhost_allowed(self):
        al = Allowlist(["127.0.0.1/32"])
        assert al.is_allowed("127.0.0.1")
        assert not al.is_allowed("127.0.0.2")


# ── Executor tests ────────────────────────────────────────────────────────


class TestResponseExecutor:
    def test_blocks_high_confidence_attack(self):
        executor, backend = _make_executor()
        alert = _make_alert(attack_type="DDoS", confidence=0.95)
        record = executor.enforce(alert)
        assert record is not None
        assert record.ip_address == "203.0.113.1"
        assert "203.0.113.1" in backend.blocked

    def test_skips_low_confidence(self):
        executor, backend = _make_executor(min_confidence=0.90)
        alert = _make_alert(confidence=0.50)
        record = executor.enforce(alert)
        assert record is None
        assert len(backend.blocked) == 0

    def test_skips_benign(self):
        executor, backend = _make_executor()
        alert = _make_alert(attack_type="BENIGN", confidence=0.99)
        record = executor.enforce(alert)
        assert record is None

    def test_skips_allowlisted_ip(self):
        executor, backend = _make_executor()
        alert = _make_alert(source_ip="10.0.0.5")
        record = executor.enforce(alert)
        assert record is None
        assert len(backend.blocked) == 0

    def test_skips_when_disabled(self):
        executor, backend = _make_executor(enabled=False)
        alert = _make_alert()
        record = executor.enforce(alert)
        assert record is None

    def test_skips_missing_source_ip(self):
        executor, backend = _make_executor()
        alert = _make_alert()
        alert["source_ip"] = None
        record = executor.enforce(alert)
        assert record is None

    def test_skips_invalid_source_ip(self):
        executor, backend = _make_executor()
        alert = _make_alert(source_ip="not-an-ip; rm -rf /")
        record = executor.enforce(alert)
        assert record is None

    def test_deduplicates_same_ip(self):
        executor, backend = _make_executor()
        alert1 = _make_alert(alert_id="ALT-00000001")
        alert2 = _make_alert(alert_id="ALT-00000002")
        record1 = executor.enforce(alert1)
        record2 = executor.enforce(alert2)
        assert record1 is not None
        assert record2 is not None
        assert record2.alert_id == "ALT-00000001"  # returns existing

    def test_respects_max_blocked_ips(self):
        executor, backend = _make_executor(max_blocked_ips=2)
        executor.enforce(_make_alert(source_ip="1.1.1.1", alert_id="A1"))
        executor.enforce(_make_alert(source_ip="2.2.2.2", alert_id="A2"))
        record = executor.enforce(_make_alert(source_ip="3.3.3.3", alert_id="A3"))
        assert record is None
        assert len(backend.blocked) == 2

    def test_manual_unblock(self):
        executor, backend = _make_executor()
        executor.enforce(_make_alert(source_ip="203.0.113.1"))
        assert executor.unblock("203.0.113.1")
        assert "203.0.113.1" not in backend.blocked

    def test_unblock_nonexistent_returns_false(self):
        executor, _ = _make_executor()
        assert not executor.unblock("1.2.3.4")

    def test_get_blocked_ips(self):
        executor, _ = _make_executor()
        executor.enforce(_make_alert(source_ip="203.0.113.1"))
        executor.enforce(_make_alert(source_ip="203.0.113.2", alert_id="ALT-2"))
        blocked = executor.get_blocked_ips()
        assert len(blocked) == 2
        ips = {r["ip_address"] for r in blocked}
        assert ips == {"203.0.113.1", "203.0.113.2"}

    def test_flush_all(self):
        executor, backend = _make_executor()
        executor.enforce(_make_alert(source_ip="203.0.113.1"))
        executor.enforce(_make_alert(source_ip="203.0.113.2", alert_id="ALT-2"))
        count = executor.flush_all()
        assert count == 2
        assert len(backend.blocked) == 0
        assert backend.flush_called

    def test_brute_force_uses_block_action(self):
        executor, backend = _make_executor(min_confidence=0.85)
        alert = _make_alert(attack_type="BruteForce", confidence=0.90)
        record = executor.enforce(alert)
        assert record is not None
        assert record.action_type == "block"

    def test_portscan_uses_rate_limit_action(self):
        executor, backend = _make_executor()
        alert = _make_alert(attack_type="PortScan", confidence=0.95)
        record = executor.enforce(alert)
        assert record is not None
        assert record.action_type == "rate_limit"


# ── NoOpBackend tests ────────────────────────────────────────────────────


class TestNoOpBackend:
    def test_tracks_blocked_ips(self):
        backend = NoOpBackend()
        backend.block_ip("1.2.3.4", 3600)
        assert "1.2.3.4" in backend.blocked
        assert backend.blocked["1.2.3.4"] == 3600

    def test_unblock_removes_ip(self):
        backend = NoOpBackend()
        backend.block_ip("1.2.3.4", 3600)
        backend.unblock_ip("1.2.3.4")
        assert "1.2.3.4" not in backend.blocked

    def test_flush_clears_all(self):
        backend = NoOpBackend()
        backend.block_ip("1.2.3.4", 3600)
        backend.block_ip("5.6.7.8", 7200)
        backend.flush()
        assert len(backend.blocked) == 0
