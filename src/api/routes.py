"""HTTP route definitions for the NetSentry API.

Access control matrix (when auth is enabled):
  Public:                health, ready, metrics
  Any authenticated:     stats, alerts list, blocked list, capture status
  Operator or Admin:     predict, batch predict, clear alerts, unblock, flush,
                         capture start/stop
  Admin only:            user management (in auth/routes.py)
"""

from __future__ import annotations

import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import PlainTextResponse

from ..capture import PacketSniffer
from ..enforcement import ResponseExecutor
from ..inference import AlertManager, InferenceEngine
from ..monitoring.metrics import REGISTRY
from ..utils.logger import get_logger, new_request_id
from .dependencies import enforce_rate_limit, get_current_user, require_role
from .schemas import (
    AlertRecord,
    BatchPredictRequest,
    BatchPredictResponse,
    BlockedIPRecord,
    HealthResponse,
    PredictRequest,
    PredictResponse,
    PredictionResult,
    StatsResponse,
)

logger = get_logger(__name__)


def build_router(
    engine: InferenceEngine,
    alerts: AlertManager,
    response_executor: ResponseExecutor,
    version: str,
    sniffer: PacketSniffer = None,
) -> APIRouter:
    router = APIRouter()

    # ── Public ────────────────────────────────────────────────────────
    @router.get("/health", response_model=HealthResponse, tags=["System"])
    def health() -> HealthResponse:
        return HealthResponse(status="ok", version=version, model_loaded=engine.ready())

    @router.get("/ready", tags=["System"])
    def ready() -> dict:
        if engine.ready():
            return {"ready": True}
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Model not loaded"
        )

    @router.get("/metrics", response_class=PlainTextResponse, tags=["System"])
    def metrics() -> str:
        return REGISTRY.render()

    # ── Any authenticated user ────────────────────────────────────────
    @router.get(
        "/stats",
        response_model=StatsResponse,
        tags=["System"],
        dependencies=[Depends(get_current_user)],
    )
    def stats() -> StatsResponse:
        return StatsResponse(inference=engine.stats(), alerts=alerts.summary())

    @router.get(
        "/alerts",
        response_model=list[AlertRecord],
        tags=["Alerts"],
        dependencies=[Depends(get_current_user)],
    )
    def list_alerts(
        limit: int = Query(50, ge=1, le=500),
        severity: Optional[str] = Query(None, pattern="^(info|low|medium|high|critical)$"),
    ) -> list[AlertRecord]:
        recent = alerts.recent(limit=limit, severity=severity)
        return [AlertRecord(**r) for r in recent]

    @router.get(
        "/blocked",
        response_model=list[BlockedIPRecord],
        tags=["Enforcement"],
        dependencies=[Depends(get_current_user)],
    )
    def list_blocked_ips() -> list[BlockedIPRecord]:
        return [BlockedIPRecord(**r) for r in response_executor.get_blocked_ips()]

    @router.get(
        "/capture/status",
        tags=["Live Capture"],
        dependencies=[Depends(get_current_user)],
    )
    def capture_status() -> dict:
        if sniffer is None:
            return {"available": False, "reason": "Sniffer not initialized"}
        return sniffer.stats()

    # ── Operator or Admin ─────────────────────────────────────────────
    @router.post(
        "/predict",
        response_model=PredictResponse,
        tags=["Detection"],
        dependencies=[Depends(enforce_rate_limit), Depends(require_role("admin", "operator"))],
    )
    def predict(req: PredictRequest, request: Request) -> PredictResponse:
        req_id = new_request_id()
        t0 = time.time()
        try:
            raw = engine.predict(req.flow.model_dump())
        except Exception as exc:
            logger.error("request_id=%s inference_error=%s", req_id, exc)
            REGISTRY.inc_counter("netsentry_http_requests_total", {"route": "predict", "status": "500"})
            raise HTTPException(status_code=500, detail=str(exc))

        result_dict = raw["results"]
        alert = alerts.record(result_dict, source_ip=req.source_ip)
        alert_id = alert["alert_id"] if alert else None

        latency_ms = (time.time() - t0) * 1000
        REGISTRY.observe_histogram("netsentry_prediction_latency_ms", latency_ms, {"route": "predict"})
        REGISTRY.inc_counter(
            "netsentry_predictions_total",
            {"result": "attack" if result_dict["is_attack"] else "benign"},
        )
        REGISTRY.inc_counter("netsentry_http_requests_total", {"route": "predict", "status": "200"})
        if alert:
            REGISTRY.inc_counter("netsentry_alerts_total", {"severity": alert["severity"]})

        logger.info(
            "request_id=%s prediction=%s is_attack=%s confidence=%.3f latency_ms=%.1f alert=%s",
            req_id, result_dict["prediction"], result_dict["is_attack"],
            result_dict["confidence"], latency_ms, alert_id,
        )

        return PredictResponse(
            result=PredictionResult(**result_dict),
            alert_id=alert_id,
            total_latency_ms=round(latency_ms, 3),
        )

    @router.post(
        "/predict/batch",
        response_model=BatchPredictResponse,
        tags=["Detection"],
        dependencies=[Depends(enforce_rate_limit), Depends(require_role("admin", "operator"))],
    )
    def predict_batch(req: BatchPredictRequest, request: Request) -> BatchPredictResponse:
        req_id = new_request_id()
        t0 = time.time()
        try:
            raw = engine.predict([f.model_dump() for f in req.flows])
        except Exception as exc:
            logger.error("request_id=%s batch_error=%s", req_id, exc)
            REGISTRY.inc_counter("netsentry_http_requests_total", {"route": "batch", "status": "500"})
            raise HTTPException(status_code=500, detail=str(exc))

        results = raw["results"]
        alerts_generated = 0
        for r in results:
            alert = alerts.record(r, source_ip=req.source_ip)
            if alert:
                alerts_generated += 1
                REGISTRY.inc_counter("netsentry_alerts_total", {"severity": alert["severity"]})
            REGISTRY.inc_counter(
                "netsentry_predictions_total",
                {"result": "attack" if r["is_attack"] else "benign"},
            )

        latency_ms = (time.time() - t0) * 1000
        REGISTRY.observe_histogram("netsentry_prediction_latency_ms", latency_ms / max(1, len(results)), {"route": "batch"})
        REGISTRY.inc_counter("netsentry_http_requests_total", {"route": "batch", "status": "200"})

        logger.info(
            "request_id=%s batch_size=%d alerts=%d latency_ms=%.1f",
            req_id, len(results), alerts_generated, latency_ms,
        )

        return BatchPredictResponse(
            results=[PredictionResult(**r) for r in results],
            alerts_generated=alerts_generated,
            batch_size=len(results),
            total_latency_ms=round(latency_ms, 3),
            avg_latency_ms=round(latency_ms / max(1, len(results)), 3),
        )

    @router.delete(
        "/alerts",
        tags=["Alerts"],
        dependencies=[Depends(require_role("admin", "operator"))],
    )
    def clear_alerts() -> dict:
        alerts.clear()
        return {"cleared": True}

    @router.delete(
        "/blocked/{ip_address}",
        tags=["Enforcement"],
        dependencies=[Depends(require_role("admin", "operator"))],
    )
    def unblock_ip(ip_address: str) -> dict:
        if response_executor.unblock(ip_address):
            return {"unblocked": True, "ip_address": ip_address}
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IP {ip_address} is not currently blocked",
        )

    @router.delete(
        "/blocked",
        tags=["Enforcement"],
        dependencies=[Depends(require_role("admin", "operator"))],
    )
    def flush_all_blocks() -> dict:
        count = response_executor.flush_all()
        return {"flushed": True, "count": count}

    @router.post(
        "/capture/start",
        tags=["Live Capture"],
        dependencies=[Depends(require_role("admin", "operator"))],
    )
    def capture_start(interface: Optional[str] = Query(None)) -> dict:
        if sniffer is None:
            raise HTTPException(400, "Sniffer not initialized")
        if not sniffer.available:
            raise HTTPException(400, "scapy not installed — run: pip install scapy")
        if interface:
            sniffer._interface = interface
        ok = sniffer.start()
        if not ok:
            raise HTTPException(500, "Failed to start capture")
        return {"started": True, "interface": sniffer._interface or "default"}

    @router.post(
        "/capture/stop",
        tags=["Live Capture"],
        dependencies=[Depends(require_role("admin", "operator"))],
    )
    def capture_stop() -> dict:
        if sniffer is None:
            raise HTTPException(400, "Sniffer not initialized")
        sniffer.stop()
        return {"stopped": True}

    return router
