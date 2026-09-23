"""
Structured logging for NIDS.

Produces JSON-formatted log lines that play well with Grafana Loki, ELK, CloudWatch,
or any log aggregator. Falls back to a readable console format when a TTY is attached.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Optional


class JsonFormatter(logging.Formatter):
    """Render log records as single-line JSON."""

    RESERVED = {
        "args", "asctime", "created", "exc_info", "exc_text", "filename",
        "funcName", "levelname", "levelno", "lineno", "module", "msecs",
        "message", "msg", "name", "pathname", "process", "processName",
        "relativeCreated", "stack_info", "thread", "threadName",
    }

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
        }
        # Attach any structured extras passed via logger.info("msg", extra={...})
        for key, value in record.__dict__.items():
            if key not in self.RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class HumanFormatter(logging.Formatter):
    """Colorized human-readable formatter for local dev consoles."""

    COLORS = {
        "DEBUG": "\033[36m",
        "INFO": "\033[32m",
        "WARNING": "\033[33m",
        "ERROR": "\033[31m",
        "CRITICAL": "\033[35m",
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        ts = time.strftime("%H:%M:%S", time.localtime(record.created))
        color = self.COLORS.get(record.levelname, "")
        return f"{color}{ts} [{record.levelname:<7}] {record.name}: {record.getMessage()}{self.RESET}"


def configure_logging(
    level: str = "INFO",
    file_path: Optional[str] = None,
    json_format: bool = True,
    rotate_bytes: int = 10_485_760,
    backups: int = 5,
) -> None:
    """Configure the root logger. Call once at process startup."""
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    # Remove any pre-existing handlers so repeated calls don't duplicate output
    for h in list(root.handlers):
        root.removeHandler(h)

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    if json_format and not sys.stdout.isatty():
        console.setFormatter(JsonFormatter())
    else:
        console.setFormatter(HumanFormatter())
    root.addHandler(console)

    # File handler with rotation
    if file_path:
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            file_path, maxBytes=rotate_bytes, backupCount=backups
        )
        file_handler.setFormatter(JsonFormatter())
        root.addHandler(file_handler)

    # Quiet some noisy third-party loggers
    for noisy in ("urllib3", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def new_request_id() -> str:
    """Generate a short correlation ID for tracing one request through the system."""
    return uuid.uuid4().hex[:12]
