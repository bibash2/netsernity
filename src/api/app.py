"""
NetSentry FastAPI application factory.

Call `create_app(config)` to obtain a fully-wired ASGI app with:
    - Trained-model loading at startup
    - Dashboard UI served at /
    - REST API routes under /api/v1
    - Prometheus /metrics endpoint
    - API-key auth and rate limiting
    - Structured logging per request
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from ..enforcement import ResponseExecutor
from ..enforcement.allowlist import Allowlist
from ..enforcement.backends.log_only import LogOnlyBackend
from ..enforcement.backends.nftables import NftablesBackend
from ..enforcement.backends.noop import NoOpBackend
from ..inference import AlertManager, InferenceEngine
from ..monitoring.metrics import REGISTRY
from ..utils.config import Config
from ..utils.logger import get_logger
from .dependencies import ApiKeyAuth, RateLimiter, configure_dependencies
from .routes import build_router

VERSION = "1.0.0"
logger = get_logger(__name__)


def create_app(config: Config) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
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

    # Register routes under /api/v1
    api_router = build_router(
        engine=engine, alerts=alerts, response_executor=response_executor, version=VERSION,
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

    # Global error handler so errors emit JSON, not HTML
    @app.exception_handler(Exception)
    async def global_error_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled error on %s: %s", request.url.path, exc)
        return JSONResponse(
            status_code=500,
            content={"error": "internal_server_error", "detail": str(exc)},
        )

    return app
