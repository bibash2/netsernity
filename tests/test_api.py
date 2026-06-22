"""Integration tests for the FastAPI server.

These run only after the training pipeline has been executed (so model
artifacts exist). They're marked so CI can skip cleanly on a cold cache.
"""

from __future__ import annotations

import sys
from pathlib import Path

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


@pytest.fixture(scope="module")
def client() -> TestClient:
    from src.api import create_app
    from src.utils.config import load_config

    cfg = load_config("config/config.yaml")
    cfg.api.api_key = ""  # disable auth for tests
    app = create_app(cfg)
    return TestClient(app)


BENIGN_FLOW = {
    "flow_duration": 180000, "total_fwd_packets": 20, "total_bwd_packets": 18,
    "fwd_packet_length_mean": 500, "bwd_packet_length_mean": 700,
    "flow_bytes_per_sec": 20000, "flow_packets_per_sec": 50,
    "packet_length_mean": 600, "packet_length_std": 150,
    "ack_flag_count": 20, "psh_flag_count": 4, "syn_flag_count": 1,
}


DDOS_FLOW = {
    "flow_duration": 6000, "total_fwd_packets": 5000, "total_bwd_packets": 3,
    "fwd_packet_length_mean": 60, "flow_bytes_per_sec": 5000000,
    "flow_packets_per_sec": 80000, "syn_flag_count": 3000,
    "packet_length_mean": 60, "avg_packet_size": 60,
}


def test_health(client: TestClient) -> None:
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["model_loaded"] is True


def test_metrics_endpoint(client: TestClient) -> None:
    r = client.get("/api/v1/metrics")
    assert r.status_code == 200
    assert "netsentry_up" in r.text


def test_predict_benign(client: TestClient) -> None:
    r = client.post("/api/v1/predict", json={"flow": BENIGN_FLOW, "source_ip": "10.0.0.1"})
    assert r.status_code == 200
    body = r.json()
    assert "result" in body
    assert body["result"]["prediction"] in ("BENIGN", "DDoS", "PortScan",
                                             "BruteForce", "Botnet",
                                             "Infiltration", "WebAttack")


def test_predict_ddos_triggers_alert(client: TestClient) -> None:
    r = client.post("/api/v1/predict", json={"flow": DDOS_FLOW, "source_ip": "192.0.2.1"})
    assert r.status_code == 200
    body = r.json()
    # DDoS profile should be classified as an attack and emit an alert
    assert body["result"]["is_attack"] is True
    assert body["alert_id"] is not None


def test_batch_predict(client: TestClient) -> None:
    r = client.post(
        "/api/v1/predict/batch",
        json={"flows": [BENIGN_FLOW, DDOS_FLOW, BENIGN_FLOW]},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["batch_size"] == 3
    assert len(body["results"]) == 3


def test_alerts_listing(client: TestClient) -> None:
    # Ensure at least one alert exists
    client.post("/api/v1/predict", json={"flow": DDOS_FLOW})
    r = client.get("/api/v1/alerts?limit=10")
    assert r.status_code == 200
    alerts = r.json()
    assert isinstance(alerts, list)
    assert len(alerts) >= 1


def test_stats_endpoint(client: TestClient) -> None:
    r = client.get("/api/v1/stats")
    assert r.status_code == 200
    body = r.json()
    assert "inference" in body
    assert "alerts" in body
