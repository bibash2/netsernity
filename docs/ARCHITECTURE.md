# NIDS — Architecture

## Design principles

1. **Transparency.** Every ML computation must be auditable. No external model library masks the math.
2. **Separation of concerns.** Data pipeline, training, inference, transport, and observability are independent modules with clean interfaces.
3. **Production posture.** The system boots from a config file, runs under a non-root user in a container, exposes health probes, rate-limits at the edge, and emits structured logs + Prometheus metrics.
4. **Incremental adoption.** You can run any layer in isolation: train without serving, serve without Docker, deploy without Kubernetes.

## System context

NIDS sits between a traffic sensor (Zeek, CICFlowMeter, a packet capture parser, or a production telemetry bus) and a SOC workflow (alerting, ticketing, automated response). This repo implements the detection + alerting service; the sensor and downstream integrations are pluggable at the edges.

```
     network ─► [sensor/flow-extractor] ─► HTTP/Kafka ─► NIDS ─► [SOC/SOAR]
```

A synthetic flow generator is bundled for demos and CI; in production you replace it with real flow records from whatever sensor you use, as long as they follow the 30-feature CIC-IDS schema.

## Module boundaries

| Layer          | Responsibility                                                  | Direction |
| -------------- | --------------------------------------------------------------- | :-------: |
| `src/data`     | Generate / load / preprocess flows                              |     →     |
| `src/models`   | Train and predict from NumPy arrays                             |    ↔      |
| `src/training` | Orchestrate data → preprocessor → model → evaluation            |     →     |
| `src/inference`| Serve predictions from trained artifacts; emit alerts           |     →     |
| `src/auth`     | JWT tokens, user store, RBAC, password hashing                  |     ↔     |
| `src/api`      | HTTP transport, auth integration, rate limit, schemas           |     ↔     |
| `src/monitoring`| Counters, gauges, histograms in Prometheus text format         |     ↔     |
| `src/utils`    | Config loading, structured logging, from-scratch metrics        |     ↔     |
| `src/dashboard`| Read-only operator UI                                           |     ←     |

A strict dependency rule: inner layers (`utils`, `models`, `data`) **never** import from outer layers (`api`, `auth`, `training`, `inference`). This keeps `src/models/` independently importable for research or notebook work.

## Data flow — training

```
                    ┌──────────────────────────────┐
                    │ scripts/train_pipeline.py    │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────▼───────────────┐
                    │  load_or_generate(...)       │─── CSV or synthetic
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────▼───────────────┐
                    │  Preprocessor.stratified_split│
                    │  → (train, val, test)        │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────▼───────────────┐
                    │  Preprocessor.fit() on train │
                    │  → mean/std, selected feats  │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────┬───────┴───────┬───────┐
                    ▼      ▼               ▼       ▼
                    RF     MLP             IF      Ensemble
                    .fit() .fit(X_val,...) .fit()  (composes the others)
                                   │
                    ┌──────────────▼───────────────┐
                    │  Evaluate on TEST set        │
                    │  Persist pickles + JSON report│
                    └──────────────────────────────┘
```

Artifacts written on a successful run:
- `models_artifacts/preprocessor.pkl` — fitted scaler + feature index
- `models_artifacts/random_forest.pkl`, `mlp.pkl`, `isolation_forest.pkl`, `ensemble.pkl`
- `models_artifacts/reports/training_metrics.json` — per-class F1, confusion matrix, latency

## Data flow — inference

```
POST /api/v1/predict
   │
   ▼
FastAPI → JWT/API-key auth → RBAC check → Pydantic validation → InferenceEngine.predict()
                                      │
                                      ▼
                         Preprocessor.transform(X)
                                      │
                                      ▼
                       EnsembleNIDS.predict_with_detail()
                          RF.proba  +  MLP.proba  →  weighted vote
                          IsolationForest.anomaly_score → override?
                                      │
                                      ▼
                           AlertManager.record()
                                      │
            ┌────────────────┬────────┴────────┬───────────────────┐
            ▼                ▼                 ▼                   ▼
     alerts.jsonl     metrics registry    in-memory ring      HTTP response
```

Latency budget on a laptop with `N_SAMPLES=20000` training: p50 < 1 ms/flow, p95 < 3 ms/flow end-to-end including Pydantic validation.

## Threading and concurrency

- **Model objects are immutable after `fit()`.** All prediction methods read-only against them, so many uvicorn workers can share the same loaded models without coordination.
- **`InferenceEngine` holds a lock** only for the statistics aggregation (latency deque, counters), not for the actual prediction pass.
- **`AlertManager` uses a `threading.Lock`** around the bounded deque and file append.
- **FastAPI + uvicorn** run the prediction synchronously inside an async endpoint; NumPy releases the GIL for matrix ops so multiple requests overlap naturally.

## Configuration and secrets

The single source of truth is `config/config.yaml`, loaded once at startup by `src/utils/config.load_config()`. Environment variables of the form `NIDS_<SECTION>__<KEY>` override individual fields at deploy time — so the same image runs in dev, staging, and production without code changes.

Secrets (API keys) are never read from the YAML file in production — they are injected through environment variables or Kubernetes Secrets.

## Failure modes and recovery

| Failure                            | Detection                                 | Response                                             |
| ---------------------------------- | ----------------------------------------- | ---------------------------------------------------- |
| Missing model artifacts at boot    | `InferenceEngine._load` raises            | Container CrashLoopBackOff → K8s retries             |
| Model file corruption              | Pickle load exception                     | Same — retrain job produces fresh artifacts          |
| Malformed request payload          | Pydantic validation error                 | HTTP 422 with field-level diagnostics                |
| Client floods the API              | `RateLimiter` rejects                     | HTTP 429                                             |
| Unhandled exception in endpoint    | Global error handler                      | HTTP 500 + structured log with stack trace           |
| OOM on large batch                 | `max_length=1000` on `BatchPredictRequest`| HTTP 422 before any work happens                     |

## Observability stack

Three signals, all emitted by the API process itself:

1. **Structured logs** — JSON to stdout (picked up by Docker/K8s) and to a rotating file, with `request_id` correlation across prediction → alert → metric increments.
2. **Metrics** — Prometheus text exposition at `/api/v1/metrics`. The exporter lives at `src/monitoring/metrics.py`; see `docs/API.md` for the full metric list.
3. **Alerts** — per-prediction JSON lines appended to `logs/alerts.jsonl` (tail-able, grep-able, shippable to anything).

## Authentication and authorization

The `src/auth` module implements JWT-based authentication and RBAC entirely from scratch using the Python standard library:

- **`JWTHandler`** — creates and verifies tokens using HMAC-SHA256 (`hmac` + `hashlib`). Tokens carry `sub` (username), `role`, `name`, and `exp` claims, base64url-encoded.
- **`UserStore`** — manages user accounts in a JSON file with thread-safe read/write. Passwords are hashed with PBKDF2-SHA256 (100,000 iterations, 32-byte random salt via `os.urandom`). Atomic writes via tmp-file rename.
- **`Role` enum** — `admin`, `operator`, `viewer`. The `require_role()` factory returns a FastAPI dependency that rejects requests from insufficient roles with 403.
- **Backward compatibility** — existing API-key auth (`X-API-Key` header) still works; it grants the `operator` role when JWT auth is also enabled.
- **Auth disabled mode** — when `auth.enabled: false`, the `get_current_user` dependency returns an anonymous admin user, preserving backward compatibility with tests and development.

## Security considerations

- JWT tokens signed with HMAC-SHA256; secret injected via environment variable in production (`NIDS_AUTH__JWT_SECRET`).
- Passwords stored as PBKDF2-SHA256 hashes with 100,000 iterations — never in plain text. User data file excluded from version control via `.gitignore`.
- API keys validated via constant-time-ish `set` lookup (`src/api/dependencies.py`).
- Rate limiter is in-process; acceptable for single-node deployments. For horizontal scale, swap the token bucket for Redis — the interface is already isolated.
- Containers run as UID 1000, read-only root FS, all Linux capabilities dropped.
- CORS allow-list is configurable; default `["*"]` is only for dev — tighten in production.
- Inputs pass through Pydantic, then bounds-clipped in `Preprocessor._clean()` to prevent adversarial NaN/inf injection.
