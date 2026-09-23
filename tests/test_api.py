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
    cfg.api.api_key = ""    # disable API key auth for tests
    cfg.auth.enabled = False  # disable JWT auth for tests
    app = create_app(cfg)
    return TestClient(app)


BENIGN_FLOW = {
    "flow_duration": 180000, "total_fwd_packets": 20, "total_bwd_packets": 18,
    "fwd_packet_length_mean": 500, "bwd_packet_length_mean": 700,
    "flow_bytes_per_sec": 20000, "flow_packets_per_sec": 50,
    "packet_length_mean": 600, "packet_length_std": 150,
    "ack_flag_count": 20, "psh_flag_count": 4, "syn_flag_count": 1,
}


# A real DDoS (LOIC-HTTP) flow from the corrected CIC-IDS2017 set — the model is
# trained on real traffic, so the fixture must be a real attack shape, not an
# invented one (the previous hand-written flow never occurs in captured data).
DDOS_FLOW = {
    "flow_duration": 254975, "total_fwd_packets": 8, "total_bwd_packets": 8,
    "fwd_packet_length_mean": 45.875, "bwd_packet_length_mean": 1449.375,
    "flow_bytes_per_sec": 46914.4034, "flow_packets_per_sec": 62.7513,
    "fwd_iat_mean": 36425.0, "bwd_iat_mean": 33863.4286, "fwd_iat_std": 77876.1135,
    "packet_length_mean": 747.625, "packet_length_std": 1486.0641,
    "packet_length_variance": 2208386.65,
    "fin_flag_count": 2, "syn_flag_count": 2, "rst_flag_count": 3, "psh_flag_count": 2,
    "ack_flag_count": 12, "urg_flag_count": 0, "down_up_ratio": 1,
    "avg_packet_size": 747.625, "fwd_segment_size_avg": 45.875, "bwd_segment_size_avg": 1449.375,
    "subflow_fwd_packets": 0, "subflow_bwd_packets": 0,
    "init_win_bytes_fwd": 29200, "init_win_bytes_bwd": 235,
    "active_mean": 0, "idle_mean": 0, "fwd_header_length": 228,
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
    assert "nids_up" in r.text


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
