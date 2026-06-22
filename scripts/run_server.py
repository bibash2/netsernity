#!/usr/bin/env python3
"""
NetSentry — API server entry point.

Starts uvicorn serving the FastAPI app. Expects trained models at
config.paths.models_dir. Run the training pipeline first.

Usage:
    python -m scripts.run_server [--config config/config.yaml] [--reload]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import uvicorn

from src.api import create_app
from src.utils.config import ensure_directories, load_config
from src.utils.logger import configure_logging, get_logger


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="NetSentry API server")
    p.add_argument("--config", default="config/config.yaml")
    p.add_argument("--host", default=None)
    p.add_argument("--port", type=int, default=None)
    p.add_argument("--workers", type=int, default=None)
    p.add_argument("--reload", action="store_true", help="Enable hot reload (dev only)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    cfg = load_config(args.config)
    ensure_directories(cfg)

    host = args.host or cfg.api.host
    port = args.port or cfg.api.port
    workers = args.workers or cfg.api.workers

    configure_logging(level=cfg.logging.level, file_path=cfg.logging.file, json_format=True)
    log = get_logger("netsentry.server")
    log.info("Starting API on %s:%d (workers=%d, reload=%s)", host, port, workers, args.reload)

    app = create_app(cfg)
    # Attach cfg so reload-mode workers can access it via app.state if needed
    app.state.config = cfg

    uvicorn.run(
        app,
        host=host,
        port=port,
        workers=workers if not args.reload else 1,
        reload=args.reload,
        log_level=cfg.logging.level.lower(),
        access_log=False,  # We have structured logs already
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
