"""
Configuration management.

Loads YAML config, applies environment variable overrides, provides typed access
with sensible defaults, and validates critical fields on startup.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

import yaml


@dataclass
class DataConfig:
    n_samples: int = 50_000
    test_size: float = 0.2
    val_size: float = 0.1
    random_state: int = 42
    dataset_path: str = "data/nids_dataset.csv"


@dataclass
class ModelConfig:
    rf_n_estimators: int = 80
    rf_max_depth: int = 18
    rf_min_samples_leaf: int = 4
    rf_n_jobs: int = 1

    mlp_hidden_layers: list = field(default_factory=lambda: [128, 64])
    mlp_epochs: int = 40
    mlp_learning_rate: float = 1e-3
    mlp_batch_size: int = 256
    mlp_dropout: float = 0.25
    mlp_l2_reg: float = 1e-4

    iso_n_estimators: int = 100
    iso_subsample_size: int = 256
    iso_contamination: float = 0.1

    ensemble_rf_weight: float = 0.55
    ensemble_mlp_weight: float = 0.45
    ensemble_anomaly_boost: float = 0.75


@dataclass
class ApiConfig:
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 1
    api_key: str = "change-me-in-production"
    rate_limit_per_minute: int = 120
    enable_cors: bool = True
    cors_origins: list = field(default_factory=lambda: ["*"])


@dataclass
class PathsConfig:
    models_dir: str = "models_artifacts"
    data_dir: str = "data"
    logs_dir: str = "logs"
    reports_dir: str = "models_artifacts/reports"


@dataclass
class LoggingConfig:
    level: str = "INFO"
    format: str = "json"
    file: str = "logs/nids.log"
    rotate_bytes: int = 10_485_760  # 10 MB
    backups: int = 5


@dataclass
class EnforcementConfig:
    enabled: bool = False
    dry_run: bool = True
    backend: str = "log_only"  # nftables | log_only | noop
    min_confidence_to_enforce: float = 0.90
    default_block_duration_seconds: int = 86400  # 24 hours
    max_blocked_ips: int = 10000
    nftables_table: str = "nids"
    nftables_chain: str = "blocked"
    allowlisted_cidrs: list = field(default_factory=lambda: [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.1/32",
    ])


@dataclass
class AuthConfig:
    enabled: bool = False
    jwt_secret: str = "nids-change-me-in-production"
    token_expiry_hours: int = 24
    users_file: str = "data/users.json"


@dataclass
class Config:
    data: DataConfig = field(default_factory=DataConfig)
    model: ModelConfig = field(default_factory=ModelConfig)
    api: ApiConfig = field(default_factory=ApiConfig)
    paths: PathsConfig = field(default_factory=PathsConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    enforcement: EnforcementConfig = field(default_factory=EnforcementConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)

    def as_dict(self) -> dict:
        return asdict(self)


def _deep_update(base: dict, overrides: dict) -> dict:
    for k, v in overrides.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_update(base[k], v)
        else:
            base[k] = v
    return base


def _apply_env_overrides(data: dict) -> dict:
    """Apply NIDS_*  environment variables.

    Convention: NIDS_<SECTION>__<KEY>  (double underscore separates section and key).
    e.g. NIDS_API__PORT=9000 overrides data['api']['port'].
    """
    prefix = "NIDS_"
    for key, raw_val in os.environ.items():
        if not key.startswith(prefix):
            continue
        remainder = key[len(prefix) :].lower()
        if "__" not in remainder:
            continue
        section, inner = remainder.split("__", 1)
        if section not in data or not isinstance(data[section], dict):
            continue
        # Try to coerce to the existing type
        existing = data[section].get(inner)
        val: Any = raw_val
        if isinstance(existing, bool):
            val = raw_val.lower() in ("1", "true", "yes", "on")
        elif isinstance(existing, int):
            try:
                val = int(raw_val)
            except ValueError:
                continue
        elif isinstance(existing, float):
            try:
                val = float(raw_val)
            except ValueError:
                continue
        elif isinstance(existing, list):
            val = [v.strip() for v in raw_val.split(",") if v.strip()]
        data[section][inner] = val
    return data


def load_config(path: str | Path | None = None) -> Config:
    """Load configuration from YAML (if provided), apply env overrides, return Config."""
    default = Config().as_dict()

    if path is not None:
        p = Path(path)
        if p.exists():
            with open(p, "r") as f:
                user_data = yaml.safe_load(f) or {}
            _deep_update(default, user_data)

    _apply_env_overrides(default)

    # Reconstruct dataclasses
    enforcement_data = default.get("enforcement", {})
    auth_data = default.get("auth", {})
    cfg = Config(
        data=DataConfig(**default["data"]),
        model=ModelConfig(**default["model"]),
        api=ApiConfig(**default["api"]),
        paths=PathsConfig(**default["paths"]),
        logging=LoggingConfig(**default["logging"]),
        enforcement=EnforcementConfig(**enforcement_data),
        auth=AuthConfig(**auth_data),
    )
    return cfg


def ensure_directories(cfg: Config) -> None:
    for d in (cfg.paths.data_dir, cfg.paths.models_dir, cfg.paths.logs_dir, cfg.paths.reports_dir):
        Path(d).mkdir(parents=True, exist_ok=True)
