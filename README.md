# NetSentry

**A production-grade Network Intrusion Detection System with machine-learning models written from scratch in NumPy.**

NetSentry detects network intrusions (DDoS, port scans, brute-force, botnets, infiltration, web attacks) in real time using an ensemble of three classifiers — a Random Forest, a Multi-Layer Perceptron, and an Isolation Forest — **all implemented from mathematical first principles without any pre-built ML libraries**. Around that core the project ships a complete production stack: REST API, operator dashboard, Prometheus metrics, structured logging, Docker images, Kubernetes manifests, Nginx reverse proxy, and CI/CD.

---

## Table of Contents

1. [Why this project](#why-this-project)
2. [What's built from scratch](#whats-built-from-scratch)
3. [Architecture](#architecture)
4. [Results](#results)
5. [Quick start](#quick-start)
6. [Project layout](#project-layout)
7. [Configuration](#configuration)
8. [REST API](#rest-api)
9. [Dashboard](#dashboard)
10. [Monitoring](#monitoring)
11. [Docker deployment](#docker-deployment)
12. [Kubernetes deployment](#kubernetes-deployment)
13. [Testing](#testing)
14. [Development](#development)

---

## Why this project

A typical student NIDS project calls `sklearn.ensemble.RandomForestClassifier` and prints an accuracy number. NetSentry does the opposite: **every model is implemented from the math upward**. There is no scikit-learn, no XGBoost, no LightGBM, no PyTorch. A decision tree splits on Gini impurity computed by hand. A neural network trains with backpropagation and Adam written out line by line. An isolation forest scores anomalies using the exact path-length formula from the 2008 ICDM paper.

Around those models is a full production harness — because an ML model without deployment, monitoring, or alerting is not a system. You can go from a clean checkout to a running API with a live threat dashboard in under five minutes on a laptop.

## What's built from scratch

| Component                   | Implementation                                                                      | File                                   |
| --------------------------- | ----------------------------------------------------------------------------------- | -------------------------------------- |
| **Decision Tree**           | CART algorithm, Gini & entropy splitting, sorted-sweep best-split search            | `src/models/decision_tree.py`          |
| **Random Forest**           | Bagging, feature subsampling, OOB error, process-pool parallelism, MDI importances  | `src/models/random_forest.py`          |
| **Multi-Layer Perceptron**  | Forward/backward pass, Adam w/ bias correction, L2, dropout, He/Xavier init, early stopping | `src/models/neural_network.py`  |
| **Isolation Forest**        | Anomaly score via expected path length (ICDM 2008), contamination threshold calibration | `src/models/isolation_forest.py`    |
| **Ensemble fusion**         | Weighted soft-voting + anomaly override on benign predictions                        | `src/models/ensemble.py`               |
| **Preprocessing**           | Stratified split, z-score scaling, ANOVA F-ratio feature selection, NaN/inf handling | `src/data/preprocessor.py`             |
| **Metrics**                 | Confusion matrix, precision/recall/F1 (macro/micro/weighted), ROC-AUC (trapezoidal)  | `src/utils/metrics.py`                 |
| **Prometheus exporter**     | Counters, gauges, histograms in text exposition format — no `prometheus_client` dep | `src/monitoring/metrics.py`            |

External libraries used only for infrastructure: `numpy` (arrays), `fastapi` + `uvicorn` (web), `pydantic` (request validation), `pyyaml` (config), `pytest` + `httpx` (tests). None of them contain ML models.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Nginx (rate-limit, TLS)                    │
└───────────────────────────────────┬─────────────────────────────────┘
                                    │
                          ┌─────────▼──────────┐
                          │   FastAPI service  │   /api/v1/predict
                          │   (Uvicorn workers)│   /api/v1/alerts
                          │                    │   /api/v1/metrics
                          │ ┌────────────────┐ │
                          │ │ InferenceEngine│ │
                          │ └────────┬───────┘ │
                          └──────────┼─────────┘
                                     │
                    ┌────────────────┼────────────────┐
                    ▼                ▼                ▼
           ┌────────────────┐  ┌───────────┐   ┌─────────────────┐
           │ RandomForest   │  │    MLP    │   │ IsolationForest │
           │ (known attacks)│  │ (nonlinear│   │  (zero-day      │
           │                │  │  patterns)│   │   anomalies)    │
           └────────┬───────┘  └─────┬─────┘   └────────┬────────┘
                    └────────┬───────┴─────────┬────────┘
                             ▼                 ▼
                     ┌───────────────┐   ┌──────────────┐
                     │ Weighted vote │   │ Anomaly      │
                     │ 0.55 · 0.45   │   │ override     │
                     └───────┬───────┘   └──────┬───────┘
                             └────────┬─────────┘
                                      ▼
                             ┌─────────────────┐
                             │  AlertManager   │──► logs/alerts.jsonl
                             │  severity +     │──► Grafana
                             │  action mapping │──► (Slack/SOAR webhook)
                             └─────────────────┘
```

## Results

Full-scale run on 50,000 synthetic CIC-IDS-style flows, 30 features, seven classes:

| Model                  | Accuracy | Macro F1 | Training | Inference      |
| ---------------------- | :------: | :------: | :------: | :------------: |
| Random Forest          |  99.3%   |  99.2%   |   ~76 s  |  0.30 ms/flow  |
| MLP (from scratch)     |  98.2%   |  96.8%   |    1.4 s |  0.002 ms/flow |
| **Ensemble**           |**99.1%** |**98.5%** |     —    |  0.63 ms/flow  |
| Isolation Forest (AUC) |  98.3%   |     —    |    0.5 s |       —        |

Numbers measured by the training pipeline itself — reproduce with `make train && cat models_artifacts/reports/training_metrics.json`.

## Quick start

### One command, end-to-end

```bash
git clone <repo>
cd netsentry
pip install -r requirements.txt
make demo            # trains on 20k flows, then starts the API on :8000
```

Open **http://localhost:8000** for the operator dashboard, or **http://localhost:8000/docs** for the OpenAPI docs.

### Step by step

```bash
# 1) Install dependencies
pip install -r requirements.txt

# 2) Train all models end-to-end
python -m scripts.train_pipeline --samples 20000
# → writes random_forest.pkl, mlp.pkl, isolation_forest.pkl, ensemble.pkl,
#   preprocessor.pkl, plus a JSON metrics report

# 3) Start the API
python -m scripts.run_server --port 8000

# 4) Send a prediction
curl -X POST http://localhost:8000/api/v1/predict \
     -H "Content-Type: application/json" \
     -d '{"flow": {"flow_duration": 6000, "total_fwd_packets": 5000, "syn_flag_count": 3000, "flow_packets_per_sec": 80000, "fwd_packet_length_mean": 60}, "source_ip": "192.0.2.1"}'
```

## Project layout

```
netsentry/
├── src/
│   ├── models/              ← From-scratch ML models (NumPy only)
│   │   ├── base.py            BaseModel abstract interface
│   │   ├── decision_tree.py   CART decision tree
│   │   ├── random_forest.py   Bagging ensemble with OOB
│   │   ├── neural_network.py  MLP + backprop + Adam
│   │   ├── isolation_forest.py Isolation-based anomaly detection
│   │   └── ensemble.py        Weighted-vote fusion head
│   ├── data/                ← Dataset generation + preprocessing
│   ├── training/            ← TrainingPipeline orchestration
│   ├── inference/           ← Real-time engine + alert manager
│   ├── api/                 ← FastAPI app, routes, schemas, auth
│   ├── dashboard/           ← Operator UI (HTML + CSS + JS)
│   ├── monitoring/          ← Prometheus exporter
│   └── utils/               ← Config, logging, metrics
│
├── scripts/
│   ├── train_pipeline.py    ← End-to-end training
│   ├── run_server.py        ← Boot the API
│   └── predict.py           ← Offline CSV prediction
│
├── config/config.yaml       ← All tunable knobs
├── tests/                   ← 30 unit + integration tests
├── docker/                  ← Dockerfile + docker-compose + Prometheus
├── deployment/
│   ├── kubernetes/          ← Namespace, Deployment, HPA, Ingress, Job, CronJob
│   └── nginx/               ← Reverse-proxy config
├── .github/workflows/ci.yml ← Lint → tests → build pipeline
├── docs/                    ← Architecture, API, model, deployment docs
└── Makefile                 ← Developer command shortcuts
```

## Configuration

Every tunable lives in `config/config.yaml`. Any field can be overridden with an environment variable of the form `NETSENTRY_<SECTION>__<KEY>` (double underscore). Examples:

```bash
NETSENTRY_DATA__N_SAMPLES=100000 python -m scripts.train_pipeline
NETSENTRY_API__PORT=9090 python -m scripts.run_server
NETSENTRY_API__API_KEY=$(openssl rand -hex 32) python -m scripts.run_server
```

See `.env.example` for the full list.

## REST API

All endpoints are under `/api/v1/`. Full OpenAPI spec at `/docs`.

| Method | Path             | Purpose                                               |
| :----- | :--------------- | :---------------------------------------------------- |
| GET    | `/health`        | Liveness + version + model-loaded flag                |
| GET    | `/ready`         | Readiness (503 until artifacts loaded)                |
| GET    | `/metrics`       | Prometheus exposition text                            |
| POST   | `/predict`       | Classify a single flow                                |
| POST   | `/predict/batch` | Classify up to 1000 flows at once                     |
| GET    | `/stats`         | Inference telemetry + alert summary                   |
| GET    | `/alerts`        | Recent alerts, filterable by severity                 |
| DELETE | `/alerts`        | Clear the alert ring buffer (auth required)           |

Auth is via `X-API-Key` header when `api.api_key` is set.

Example response from `/predict`:

```json
{
  "result": {
    "prediction": "DDoS",
    "class_id": 1,
    "is_attack": true,
    "confidence": 0.994,
    "anomaly_score": 0.761,
    "anomaly_flagged": true,
    "probabilities": {"BENIGN": 0.003, "DDoS": 0.994, "PortScan": 0.002, "...": "..."}
  },
  "alert_id": "ALT-00000042",
  "total_latency_ms": 2.731
}
```

## Dashboard

A live operator console runs at `/`. It polls `/stats` and `/alerts` every 2.5 s and supports manual probes — click any of seven attack-class presets (BENIGN, DDoS, PortScan, BruteForce, Botnet, Infiltration, WebAttack), fire the probe, and watch the alert stream update in real time. Pure HTML + CSS + vanilla JS with no build step.

## Monitoring

The API exports Prometheus metrics without any external client library. Out of the box you get:

- `netsentry_predictions_total{result="attack|benign"}` — prediction counts
- `netsentry_alerts_total{severity="low|medium|high|critical"}` — alert counts
- `netsentry_prediction_latency_ms_bucket{le="..."}` — p50/p95/p99 latency histogram
- `netsentry_http_requests_total{route,status}` — request rate per route
- `netsentry_up` — service up gauge

`docker-compose` brings up Prometheus and Grafana pre-wired to scrape these.

## Docker deployment

```bash
cd docker
docker compose up -d --build      # builds image, runs trainer Job, then starts API, nginx, prom, grafana
```

Services:
- `http://localhost:8000` — API + dashboard (direct)
- `http://localhost/`     — API + dashboard (behind nginx)
- `http://localhost:9090` — Prometheus
- `http://localhost:3000` — Grafana (admin / admin)

The `trainer` service runs once to populate a shared models volume, then the API container starts. Scale API replicas with `docker compose up -d --scale api=4`.

## Kubernetes deployment

Manifests live in `deployment/kubernetes/`. See that directory's `README.md` for a step-by-step walkthrough. Highlights:

- `Deployment` with liveness/readiness/startup probes, non-root user, read-only root FS, dropped capabilities
- `HorizontalPodAutoscaler` scaling 2 → 10 pods on CPU + memory
- `PodDisruptionBudget` ensuring at least one pod during disruptions
- `Job` for the first-time training, plus a weekly `CronJob` for automated retraining
- `Ingress` for external exposure
- `ConfigMap` for config, optional `Secret` for API key

## Testing

```bash
make test          # all 30 tests
make unit-test     # models + preprocessing + metrics only
make api-test      # requires trained artifacts
```

The test suite covers:

- Decision tree correctness on toy data, Gini/entropy math, proba-sum-to-one invariants, not-fitted guards
- Random forest OOB score within [0, 1], feature-importance normalization, accuracy on separable classes
- MLP end-to-end training, early stopping, output-layer probability distribution
- Isolation forest separating normal vs. clearly-anomalous distributions
- Ensemble end-to-end fusion
- Synthetic data generator shape, class mix, label noise
- Preprocessor stratified split, z-score normalization, NaN/inf imputation, feature selection
- All metric formulas (confusion matrix, accuracy, precision/recall/F1, ROC-AUC) validated on known inputs
- API integration: health, predict single + batch, alert generation, stats, metrics endpoint

## Development

```bash
make install-dev             # extras for lint/format/typecheck
make lint                    # ruff check
make format                  # ruff format
make clean                   # wipe artifacts and caches
make serve-dev               # uvicorn with --reload
```

A GitHub Actions workflow runs the whole lint → unit test → train → API test → Docker build chain on every push.

---

## License

MIT — see `LICENSE`.

## Documentation

- `docs/ARCHITECTURE.md` — system design, data flow, threading model
- `docs/MODELS.md` — math & implementation notes for each model
- `docs/API.md` — endpoint-level reference
- `docs/DEPLOYMENT.md` — production deployment runbook
# netsernity
