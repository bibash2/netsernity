# NIDS — Deployment Runbook

Practical steps for getting NIDS from a clean machine to a production cluster. Each section is standalone — you can stop after "local Python" if that's all you need.

---

## 1. Local Python (zero infrastructure)

Prerequisite: Python 3.10+.

```bash
git clone <repo> && cd nids
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python -m scripts.train_pipeline --samples 20000
python -m scripts.run_server
```

Verify:
```bash
curl http://localhost:8000/api/v1/health
open http://localhost:8000                    # dashboard (redirects to /login when auth enabled)
```

Auth is enabled by default. Default credentials:

| Username | Password | Role |
| -------- | -------- | ---- |
| admin | admin123 | Administrator |
| operator | operator123 | Operator |
| viewer | viewer123 | Viewer |

Change the JWT secret and default passwords before any non-local deployment.

Training on 20 k samples takes ~90 s on a laptop. For a quick smoke-test, drop to `--samples 3000` (~15 s).

---

## 2. Docker — single host

Prerequisites: Docker 24+, Docker Compose v2.

```bash
cp .env.example .env
# Optional: set NIDS_API__API_KEY=<openssl rand -hex 32>

cd docker
docker compose up -d --build
```

What happens:

1. `trainer` container builds and runs once to populate the shared `models` volume.
2. Once training finishes, the `api` container starts (declaratively blocked by `depends_on.service_completed_successfully`).
3. `nginx`, `prometheus`, `grafana` come up alongside.

Endpoints after the stack is up:

| Service    | URL                               | Credentials     |
| ---------- | --------------------------------- | --------------- |
| Dashboard  | http://localhost                  | —               |
| API docs   | http://localhost/docs             | —               |
| Prometheus | http://localhost:9090             | —               |
| Grafana    | http://localhost:3000             | admin / admin   |

Scale horizontally: `docker compose up -d --scale api=4`. Nginx least-connection load-balances automatically.

Retrain on demand: `docker compose run --rm trainer`. Restart the API afterwards (`docker compose restart api`) so workers pick up the new artifacts.

---

## 3. Kubernetes — multi-node cluster

Prerequisites: a cluster with an ingress controller (nginx-ingress or similar) and a RWX-capable storage class for model artifacts shared across replicas.

### 3.1 Build and push the image

```bash
docker build -t your-registry/nids:1.0.0 -f docker/Dockerfile .
docker push your-registry/nids:1.0.0
```

Update image references in `deployment/kubernetes/deployment.yaml` and `training-job.yaml`.

### 3.2 Apply the manifests

```bash
kubectl apply -f deployment/kubernetes/namespace.yaml         # namespace, configmap, PVCs
kubectl apply -f deployment/kubernetes/training-job.yaml      # trainer Job + CronJob + Ingress
kubectl apply -f deployment/kubernetes/deployment.yaml        # API Deployment + Service + HPA + PDB
```

### 3.3 Secrets (API key and JWT)

```bash
kubectl create secret generic nids-secret \
        --namespace nids \
        --from-literal=api-key="$(openssl rand -hex 32)" \
        --from-literal=jwt-secret="$(openssl rand -hex 32)"
```

Map the JWT secret to `NIDS_AUTH__JWT_SECRET` in the Deployment env. Absent the secrets, the Deployment's `optional: true` reference still succeeds and auth uses the default dev secret — fine for a private cluster, never for public exposure.

### 3.4 Watch progress

```bash
kubectl -n nids logs -f job/nids-trainer
kubectl -n nids rollout status deployment/nids-api
kubectl -n nids get hpa
```

The readiness probe hits `/api/v1/ready`, which returns 503 until the model pickles exist on the mounted PVC. No race between training and serving — the `Job → Deployment` dependency is enforced by probes.

### 3.5 Scaling behavior

The HPA auto-scales 2 → 10 pods on 70% CPU or 80% memory, with a 30 s scale-up window and 300 s scale-down window. For manual overrides:

```bash
kubectl -n nids scale deployment/nids-api --replicas=8
```

### 3.6 Weekly retraining

A `CronJob` (`nids-retrain`) runs Sundays at 02:00 UTC. It writes fresh artifacts to the same shared volume. Trigger a rolling restart if you want the API to pick them up immediately:

```bash
kubectl -n nids rollout restart deployment/nids-api
```

---

## 4. Operations

### Logs

Every API request emits a structured JSON log line to stdout, captured by Docker or K8s. Alerts are also appended to `logs/alerts.jsonl` for audit. Example query with `jq`:

```bash
kubectl -n nids logs deployment/nids-api -f | \
    jq 'select(.prediction == "DDoS")'
```

### Metrics

Prometheus scrapes `/api/v1/metrics` every 15 s. Key series to alert on:

| Series                                                   | Alert when                    |
| -------------------------------------------------------- | ----------------------------- |
| `nids_up`                                           | drops to 0                    |
| `histogram_quantile(0.95, …latency_ms_bucket)`           | exceeds 10 ms                 |
| `rate(nids_alerts_total{severity="critical"}[5m])`  | non-zero for > 2 min          |
| `rate(nids_predictions_total[1m])`                  | falls below baseline (sensor outage) |

### Dashboards

Import the Grafana dashboard from `deployment/grafana/` (if shipped) or build panels using the metric catalog in `docs/API.md`. At a minimum, track: requests/s, p95 latency, attack rate, alert counts by severity, per-attack-class breakdown.

---

## 5. Rollbacks

### Docker
```bash
docker compose down
docker image tag nids:previous nids:latest
docker compose up -d
```

### Kubernetes
```bash
kubectl -n nids rollout undo deployment/nids-api
kubectl -n nids rollout history deployment/nids-api
```

### Model rollback

The artifacts volume is mutable — if a retrain produces a worse model, restore from backup:

```bash
# Keep a backup before each retrain
kubectl -n nids exec deploy/nids-api -- \
    tar czf /tmp/models-$(date +%F).tar.gz /app/models_artifacts
```

---

## 6. Hardening checklist

Before exposing publicly:

- [ ] Set `NIDS_AUTH__JWT_SECRET` to a random 64-hex secret (never use the default dev secret)
- [ ] Change all default user passwords (`admin123`, `operator123`, `viewer123`)
- [ ] Set `NIDS_API__API_KEY` to a random 64-hex secret
- [ ] Restrict `api.cors_origins` from `["*"]` to your actual origin(s)
- [ ] Put the API behind TLS (ingress-nginx + cert-manager, or a CDN/WAF)
- [ ] Tighten `api.rate_limit_per_minute` for your expected traffic
- [ ] Review `logs/alerts.jsonl` rotation — ship to your SIEM if one exists
- [ ] Set resource limits (already templated — adjust to your node sizes)
- [ ] Run a penetration test against the `/predict` endpoint to probe for edge cases
- [ ] Verify the container runs as non-root (`kubectl exec` and run `id` — must show uid=1000)
- [ ] Ensure `data/users.json` is excluded from version control and backed up

---

## 7. Troubleshooting

| Symptom                                              | Cause                                       | Fix                                                   |
| ---------------------------------------------------- | ------------------------------------------- | ----------------------------------------------------- |
| API pod CrashLoopBackOff with `FileNotFoundError`    | Training Job hasn't completed               | Wait or re-run the Job; check `kubectl logs job/…`    |
| `/predict` returns 500 with "expected N features"    | Preprocessor artifact mismatches model      | Retrain — artifacts must be produced together         |
| All predictions return BENIGN                        | Ensemble weights zeroed or anomaly_boost=1.0| Inspect `config.yaml` — restore defaults              |
| p95 latency spikes above 20 ms                       | Cold process; first request per worker      | Warm-up hook or prefetch on startup                   |
| HPA stays at `minReplicas` despite load              | Metrics server not installed                | `kubectl apply -f metrics-server.yaml`                |
| 429 on every request                                 | Rate limit too tight for real traffic       | Raise `NIDS_API__RATE_LIMIT_PER_MINUTE`          |
| 401 on all requests after restart                    | JWT secret changed; old tokens are invalid  | Users must re-login; keep secret stable across deploys|
| Cannot login — default credentials rejected          | Passwords were changed or `users.json` lost | Delete `data/users.json` to re-seed defaults, then change passwords |
