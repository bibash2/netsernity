"""Pydantic schemas for the NIDS REST API."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class FlowFeatures(BaseModel):
    """A single network flow described by CIC-IDS-style features.

    Missing features default to 0 — the inference engine will impute when needed.
    """

    flow_duration: float = Field(0.0, description="Duration in microseconds")
    total_fwd_packets: float = 0.0
    total_bwd_packets: float = 0.0
    fwd_packet_length_mean: float = 0.0
    bwd_packet_length_mean: float = 0.0
    flow_bytes_per_sec: float = 0.0
    flow_packets_per_sec: float = 0.0
    fwd_iat_mean: float = 0.0
    bwd_iat_mean: float = 0.0
    fwd_iat_std: float = 0.0
    packet_length_mean: float = 0.0
    packet_length_std: float = 0.0
    packet_length_variance: float = 0.0
    fin_flag_count: float = 0.0
    syn_flag_count: float = 0.0
    rst_flag_count: float = 0.0
    psh_flag_count: float = 0.0
    ack_flag_count: float = 0.0
    urg_flag_count: float = 0.0
    down_up_ratio: float = 0.0
    avg_packet_size: float = 0.0
    fwd_segment_size_avg: float = 0.0
    bwd_segment_size_avg: float = 0.0
    subflow_fwd_packets: float = 0.0
    subflow_bwd_packets: float = 0.0
    init_win_bytes_fwd: float = 0.0
    init_win_bytes_bwd: float = 0.0
    active_mean: float = 0.0
    idle_mean: float = 0.0
    fwd_header_length: float = 0.0

    class Config:
        extra = "ignore"


class PredictRequest(BaseModel):
    flow: FlowFeatures
    source_ip: Optional[str] = Field(None, description="Optional source IP for alert enrichment")


class BatchPredictRequest(BaseModel):
    flows: list[FlowFeatures] = Field(..., min_length=1, max_length=1000)
    source_ip: Optional[str] = None


class PredictionResult(BaseModel):
    prediction: str
    class_id: int
    is_attack: bool
    confidence: float
    anomaly_score: float
    anomaly_flagged: bool
    probabilities: dict[str, float]


class PredictResponse(BaseModel):
    result: PredictionResult
    alert_id: Optional[str] = None
    total_latency_ms: float


class BatchPredictResponse(BaseModel):
    results: list[PredictionResult]
    alerts_generated: int
    batch_size: int
    total_latency_ms: float
    avg_latency_ms: float


class HealthResponse(BaseModel):
    status: str
    version: str
    model_loaded: bool


class StatsResponse(BaseModel):
    inference: dict
    alerts: dict


class AlertRecord(BaseModel):
    alert_id: str
    timestamp: str
    severity: str
    attack_type: str
    confidence: float
    anomaly_score: float
    anomaly_flagged: bool
    source_ip: Optional[str]
    recommended_action: str
    probabilities: dict[str, float]


class BlockedIPRecord(BaseModel):
    ip_address: str
    attack_type: str
    action_type: str
    confidence: float
    blocked_at: float
    expires_at: float
    remaining_seconds: int
    alert_id: str
