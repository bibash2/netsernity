# NetSentry — API Reference

Base URL: `http://<host>:<port>/api/v1`

Interactive OpenAPI docs: `GET /docs`

## Authentication

NIDS supports two authentication methods:

1. **JWT (primary)** — when `auth.enabled: true` in config, users authenticate via `POST /auth/login` to obtain a JWT token. Include it in subsequent requests as `Authorization: Bearer <token>`. Tokens expire after the configured `token_expiry_hours` (default 24h).

2. **API key (backward-compatible)** — when `api.api_key` is set, external systems can authenticate with `X-API-Key: <key>`. API-key auth grants the `operator` role.

When `auth.enabled: false` and `api.api_key` is empty, authentication is disabled — only safe for private deployments.

### Roles and permissions

| Role | Can do |
| ---- | ------ |
| `admin` | Everything, including user management |
| `operator` | Submit flows, manage alerts and blocks, view dashboard |
| `viewer` | View dashboard, alerts, blocked IPs, stats (read-only) |

Rate limiting: fixed-window (default 240 requests / minute per client IP). On excess the API returns `429 Too Many Requests`.

---

## Auth endpoints

### `POST /auth/login`

Public. Authenticate with username and password.

**Request**
```json
{
  "username": "operator",
  "password": "operator123"
}
```

**Response — 200 OK**
```json
{
  "token": "eyJ0eXAiOiJKV1QiLC...",
  "username": "operator",
  "role": "operator",
  "full_name": "Default Operator",
  "expires_in": 86400
}
```

**Errors:** `401` — invalid credentials.

### `GET /auth/me`

Returns the current authenticated user's profile.

**Response — 200 OK**
```json
{
  "username": "operator",
  "role": "operator",
  "full_name": "Default Operator"
}
```

### `PUT /auth/me/password`

Change your own password. Any authenticated role.

**Request**
```json
{
  "current_password": "old_password",
  "new_password": "new_password"
}
```

### `GET /auth/users` *(admin only)*

List all user accounts. Returns an array of `{username, role, full_name, active}`.

### `POST /auth/users` *(admin only)*

Create a new user.

**Request**
```json
{
  "username": "analyst1",
  "password": "secure_pass",
  "role": "viewer",
  "full_name": "Security Analyst"
}
```

**Response — 201 Created**

**Errors:** `409` — username already exists.

### `DELETE /auth/users/{username}` *(admin only)*

Delete a user account. Cannot delete yourself.

**Errors:** `400` — cannot delete self; `404` — user not found.

---

## System endpoints

### `GET /health`

Liveness check. Always 200 unless the process is crashing.

```json
{
  "status": "ok",
  "version": "1.1.0",
  "model_loaded": true
}
```

### `GET /ready`

Readiness check. Returns 200 once the ensemble is loaded, otherwise 503. Use this as the K8s readiness probe so traffic doesn't hit a pod that hasn't finished boot.

### `GET /metrics`

Prometheus text exposition. Scrape with the default Prometheus agent — no content-type negotiation needed.

```
# TYPE netsentry_up gauge
netsentry_up 1
# TYPE netsentry_predictions_total counter
netsentry_predictions_total{result="benign"} 143
netsentry_predictions_total{result="attack"} 27
# TYPE netsentry_prediction_latency_ms histogram
netsentry_prediction_latency_ms_bucket{route="predict",le="1"} 55
netsentry_prediction_latency_ms_bucket{route="predict",le="5"} 170
...
```

---

## Detection endpoints

### `POST /predict`

Classify a single network flow.

**Request**
```json
{
  "flow": {
    "flow_duration": 6000,
    "total_fwd_packets": 5000,
    "total_bwd_packets": 3,
    "flow_packets_per_sec": 80000,
    "syn_flag_count": 3000,
    "fwd_packet_length_mean": 60
  },
  "source_ip": "192.0.2.1"
}
```

All 30 CIC-IDS features are accepted; any you omit default to 0. `source_ip` is optional metadata — it's attached to any generated alert for attribution but never fed to the model.

**Response — 200 OK**
```json
{
  "result": {
    "prediction": "DDoS",
    "class_id": 1,
    "is_attack": true,
    "confidence": 0.994,
    "anomaly_score": 0.761,
    "anomaly_flagged": true,
    "probabilities": {
      "BENIGN": 0.003,
      "DDoS": 0.994,
      "PortScan": 0.002,
      "BruteForce": 0.0005,
      "Botnet": 0.0003,
      "Infiltration": 0.0001,
      "WebAttack": 0.0001
    }
  },
  "alert_id": "ALT-00000042",
  "total_latency_ms": 2.731
}
```

`alert_id` is null for benign traffic. `confidence` is the ensemble probability of the winning class.

### `POST /predict/batch`

Classify up to 1000 flows in one call.

**Request**
```json
{
  "flows": [
    { "flow_duration": 6000, "syn_flag_count": 3000 },
    { "flow_duration": 180000, "ack_flag_count": 20 }
  ],
  "source_ip": "10.0.0.42"
}
```

**Response**
```json
{
  "results": [ /* array of PredictionResult */ ],
  "alerts_generated": 1,
  "batch_size": 2,
  "total_latency_ms": 4.18,
  "avg_latency_ms": 2.09
}
```

Larger batches amortize Python overhead and scale linearly. Reject anything over 1000 to keep a single request bounded in memory.

---

## Alert endpoints

### `GET /alerts?limit=50&severity=high`

Read the ring buffer of recent alerts. Supports:

- `limit` (1–500) — how many to return, newest first
- `severity` — filter by one of `info`, `low`, `medium`, `high`, `critical`

**Response**
```json
[
  {
    "alert_id": "ALT-00000042",
    "timestamp": "2026-04-19T10:42:11.213Z",
    "severity": "critical",
    "attack_type": "DDoS",
    "confidence": 0.994,
    "anomaly_score": 0.761,
    "anomaly_flagged": true,
    "source_ip": "192.0.2.1",
    "recommended_action": "drop_and_notify_upstream",
    "probabilities": { "BENIGN": 0.003, "DDoS": 0.994, "...": "..." }
  }
]
```

### `DELETE /alerts`

Clear the in-memory ring buffer. Requires auth. Does not delete the persisted `logs/alerts.jsonl` — that's the audit trail.

### `GET /stats`

Aggregated telemetry snapshot.

```json
{
  "inference": {
    "total_predictions": 12843,
    "total_attacks_detected": 471,
    "attack_rate": 0.0367,
    "latency_ms": {
      "p50": 0.82,
      "p95": 2.11,
      "p99": 4.63,
      "mean": 1.05
    }
  },
  "alerts": {
    "total_alerts": 471,
    "by_type":     {"DDoS": 189, "PortScan": 142, "BruteForce": 66, "Botnet": 43, "Infiltration": 21, "WebAttack": 10},
    "by_severity": {"critical": 189, "high": 64, "medium": 208, "low": 10}
  }
}
```

---

## Severity and response mapping

Defined in `src/inference/alert_manager.py`. Overridable for your SOC's policies.

| Attack class | Severity | Recommended action                   |
| ------------ | -------- | ------------------------------------ |
| BENIGN       | info     | allow                                |
| PortScan     | low      | rate_limit_source                    |
| WebAttack    | medium   | rate_limit_source                    |
| BruteForce   | medium   | block_source_24h                     |
| Botnet       | high     | isolate_host                         |
| Infiltration | high     | isolate_host_and_investigate         |
| DDoS         | critical | drop_and_notify_upstream             |

---

## Error responses

All errors are JSON:

```json
{"error": "internal_server_error", "detail": "…"}
```

Standard status codes:

- `401 Unauthorized` — missing/invalid JWT token or API key
- `403 Forbidden` — authenticated but insufficient role for this endpoint
- `409 Conflict` — resource already exists (e.g., duplicate username)
- `422 Unprocessable Entity` — Pydantic validation failed
- `429 Too Many Requests` — rate limiter engaged
- `500 Internal Server Error` — unhandled exception (logged with full stack)
- `503 Service Unavailable` — model not loaded (only on `/ready`)
