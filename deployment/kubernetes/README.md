# NIDS — Kubernetes deployment

This directory contains everything needed to run NIDS on a Kubernetes
cluster. Files are organized so you can apply them incrementally.

## Prerequisites

- A cluster with a working ingress controller (nginx-ingress or similar)
- A storage class that supports `ReadWriteOnce` (any cloud provider) and
  ideally `ReadWriteMany` (EFS, CephFS, NFS) — the model PVC uses RWX so
  multiple API replicas can share read-only artifacts

## First deployment

```bash
# 1) Build and push the image
docker build -t your-registry/nids:1.0.0 -f docker/Dockerfile .
docker push your-registry/nids:1.0.0
# Update image references in deployment.yaml and training-job.yaml

# 2) Apply manifests in order
kubectl apply -f namespace.yaml
kubectl apply -f training-job.yaml     # starts trainer Job
kubectl apply -f deployment.yaml        # API Deployment + Service + HPA
```

## Create the API-key secret (optional)

```bash
kubectl create secret generic nids-secret \
    --namespace nids \
    --from-literal=api-key="$(openssl rand -hex 32)"
```

Leave the secret absent and the API runs with auth disabled — fine for
private clusters, not for public exposure.

## Check progress

```bash
kubectl -n nids logs -f job/nids-trainer
kubectl -n nids get pods
kubectl -n nids rollout status deployment/nids-api
```

## Scaling

HPA auto-scales API pods between 2 and 10 based on CPU and memory. To push
harder manually:

```bash
kubectl -n nids scale deployment/nids-api --replicas=8
```

## Weekly retraining

`training-job.yaml` also defines a `CronJob` (`nids-retrain`) that
reruns training every Sunday at 02:00 UTC. The API Deployment will reload
updated artifacts on next pod restart — trigger a rollout manually if you
want it applied immediately:

```bash
kubectl -n nids rollout restart deployment/nids-api
```

## Observability

Pods expose Prometheus metrics at `/api/v1/metrics` with the annotations
set on the Deployment, so a Prometheus Operator in the cluster will scrape
them automatically. Grafana dashboards live in `deployment/grafana/` (see
main README).
