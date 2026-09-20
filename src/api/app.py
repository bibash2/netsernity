"""
NetSentry FastAPI application factory.

Call `create_app(config)` to obtain a fully-wired ASGI app with:
    - Trained-model loading at startup
    - Dashboard UI served at /
    - Login page served at /login (when auth enabled)
    - REST API routes under /api/v1
    - Prometheus /metrics endpoint
    - JWT auth + API-key auth and rate limiting
    - Structured logging per request
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

import asyncio
import json

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from ..capture import PacketSniffer
from ..enforcement import ResponseExecutor
from ..enforcement.allowlist import Allowlist
from ..enforcement.backends.log_only import LogOnlyBackend
from ..enforcement.backends.nftables import NftablesBackend
from ..enforcement.backends.noop import NoOpBackend
from ..inference import AlertManager, InferenceEngine
from ..monitoring.metrics import REGISTRY
from ..utils.config import Config
from ..utils.logger import get_logger
from .dependencies import ApiKeyAuth, RateLimiter, configure_auth, configure_dependencies
from .routes import build_router

VERSION = "1.1.0"
logger = get_logger(__name__)


def create_app(config: Config) -> FastAPI:
    _event_loop = None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        nonlocal _event_loop
        _event_loop = asyncio.get_running_loop()
        REGISTRY.set_gauge("netsentry_up", 1)
        logger.info("NetSentry API started, version=%s models=%s", VERSION, config.paths.models_dir)
        yield
        REGISTRY.set_gauge("netsentry_up", 0)
        logger.info("NetSentry API shutting down")

    app = FastAPI(
        title="NetSentry — Network Intrusion Detection System",
        description="From-scratch ML-based NIDS with real-time inference, alerting, and monitoring.",
        version=VERSION,
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # CORS
    if config.api.enable_cors:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=config.api.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # Wire dependencies
    configure_dependencies(
        rate_limiter=RateLimiter(max_requests=config.api.rate_limit_per_minute, window_seconds=60),
        api_key_auth=ApiKeyAuth(config.api.api_key),
    )

    # Auth — JWT + RBAC
    jwt_handler = None
    if config.auth.enabled:
        from ..auth import JWTHandler, UserStore
        from ..auth.routes import build_auth_router

        expiry_seconds = config.auth.token_expiry_hours * 3600
        jwt_handler = JWTHandler(config.auth.jwt_secret, expiry_seconds)
        user_store = UserStore(config.auth.users_file)
        configure_auth(jwt_handler)

        auth_router = build_auth_router(user_store, jwt_handler, expiry_seconds)
        app.include_router(auth_router, prefix="/api/v1")
        logger.info("Auth enabled — JWT + RBAC, users_file=%s", config.auth.users_file)
    else:
        configure_auth(None)

    # Load models
    engine = InferenceEngine(models_dir=config.paths.models_dir)

    # Set up enforcement
    enforcement_cfg = config.enforcement
    backend_name = enforcement_cfg.backend.lower()
    if backend_name == "nftables":
        firewall_backend = NftablesBackend(
            table_name=enforcement_cfg.nftables_table,
            chain_name=enforcement_cfg.nftables_chain,
        )
    elif backend_name == "log_only":
        firewall_backend = LogOnlyBackend()
    else:
        firewall_backend = NoOpBackend()

    allowlist = Allowlist(enforcement_cfg.allowlisted_cidrs)
    response_executor = ResponseExecutor(
        backend=firewall_backend,
        allowlist=allowlist,
        enabled=enforcement_cfg.enabled,
        min_confidence_override=enforcement_cfg.min_confidence_to_enforce,
        default_block_duration_seconds=enforcement_cfg.default_block_duration_seconds,
        max_blocked_ips=enforcement_cfg.max_blocked_ips,
    )
    response_executor.setup()

    alerts = AlertManager(
        capacity=1000,
        log_file=Path(config.paths.logs_dir) / "alerts.jsonl",
        on_alert=response_executor.enforce,
    )

    # WebSocket hub — push events to all connected dashboards instantly
    ws_clients: set[WebSocket] = set()

    async def _ws_broadcast(event: dict):
        dead = set()
        msg = json.dumps(event)
        for ws in ws_clients:
            try:
                await ws.send_text(msg)
            except Exception:
                dead.add(ws)
        ws_clients.difference_update(dead)

    def ws_broadcast_sync(event: dict):
        """Thread-safe broadcast from the sniffer thread."""
        if _event_loop is not None and _event_loop.is_running():
            asyncio.run_coroutine_threadsafe(_ws_broadcast(event), _event_loop)

    @app.websocket("/ws")
    async def websocket_endpoint(ws: WebSocket):
        if jwt_handler is not None:
            token = ws.query_params.get("token")
            if not token or jwt_handler.verify_token(token) is None:
                await ws.close(code=4001, reason="Authentication required")
                return
        await ws.accept()
        ws_clients.add(ws)
        try:
            while True:
                await ws.receive_text()  # keep alive
        except WebSocketDisconnect:
            ws_clients.discard(ws)

    # Live packet capture — classify flows in-process
    def on_captured_flow(features: dict, source_ip: str):
        """Called by the sniffer for each completed flow."""
        raw = engine.predict(features)
        result = raw["results"]
        alert = alerts.record(result, source_ip=source_ip)
        alert_id = alert["alert_id"] if alert else None

        sniffer.record_result(
            features, source_ip,
            prediction=result.get("prediction", "?"),
            is_attack=result.get("is_attack", False),
            confidence=result.get("confidence", 0),
            alert_id=alert_id,
        )

        ws_broadcast_sync({
            "type": "flow",
            "source_ip": source_ip,
            "prediction": result.get("prediction", "?"),
            "is_attack": result.get("is_attack", False),
            "confidence": result.get("confidence", 0),
            "anomaly_score": result.get("anomaly_score", 0),
            "alert_id": alert_id,
            "severity": alert.get("severity") if alert else None,
        })

    def on_raw_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str, size: int):
        ws_broadcast_sync({
            "type": "packet",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "proto": proto,
            "size": size,
        })

    sniffer = PacketSniffer(on_flow=on_captured_flow, on_packet_cb=on_raw_packet)

    # Register routes under /api/v1
    api_router = build_router(
        engine=engine, alerts=alerts, response_executor=response_executor,
        version=VERSION, sniffer=sniffer, on_broadcast=ws_broadcast_sync,
    )
    app.include_router(api_router, prefix="/api/v1")

    # Dashboard
    dashboard_dir = Path(__file__).resolve().parent.parent / "dashboard"
    static_dir = dashboard_dir / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/", include_in_schema=False)
    def dashboard_root() -> FileResponse:
        index = dashboard_dir / "index.html"
        if index.exists():
            return FileResponse(index)
        return JSONResponse({"message": "NetSentry is running", "docs": "/docs"})

    @app.get("/login", include_in_schema=False)
    def login_page() -> FileResponse:
        login = dashboard_dir / "login.html"
        if login.exists():
            return FileResponse(login)
        return JSONResponse({"message": "Login page not found", "docs": "/docs"})

    # Global error handler so errors emit JSON, not HTML
    @app.exception_handler(Exception)
    async def global_error_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled error on %s: %s", request.url.path, exc)
        return JSONResponse(
            status_code=500,
            content={"error": "internal_server_error", "detail": str(exc)},
        )

    return app
