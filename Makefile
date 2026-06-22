# NetSentry — development command shortcuts.
# Use `make help` to see everything.

.DEFAULT_GOAL := help
.PHONY: help install install-dev test unit-test api-test lint format clean train serve predict \
        docker-build docker-up docker-down docker-logs k8s-apply k8s-delete

PYTHON  ?= python
PIP     ?= pip
SAMPLES ?= 20000
PORT    ?= 8000

help:                                   ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\n\033[1mNetSentry — Makefile targets\033[0m\n\n"} \
	/^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# ─── Environment ─────────────────────────────────────
install:                                ## Install runtime dependencies
	$(PIP) install -r requirements.txt

install-dev: install                    ## Install dev + runtime dependencies
	$(PIP) install ruff black mypy

clean:                                  ## Remove generated artifacts and caches
	rm -rf models_artifacts/*.pkl models_artifacts/reports/*.json data/*.csv logs/*.log logs/*.jsonl
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true

# ─── Testing ─────────────────────────────────────────
test:                                   ## Run the full test suite
	$(PYTHON) -m pytest tests/ -v

unit-test:                              ## Run unit tests only (no API)
	$(PYTHON) -m pytest tests/test_models.py tests/test_data_and_metrics.py -v

api-test:                               ## Run API integration tests (needs trained models)
	$(PYTHON) -m pytest tests/test_api.py -v

# ─── Quality ─────────────────────────────────────────
lint:                                   ## Run ruff linter
	ruff check src/ scripts/ tests/

format:                                 ## Auto-format with ruff
	ruff format src/ scripts/ tests/

# ─── Runtime ─────────────────────────────────────────
train:                                  ## Train all models end-to-end  (override: make train SAMPLES=50000)
	$(PYTHON) -m scripts.train_pipeline --samples $(SAMPLES) --quiet

serve:                                  ## Run the API server  (override: make serve PORT=8080)
	$(PYTHON) -m scripts.run_server --port $(PORT)

serve-dev:                              ## Run API with hot-reload
	$(PYTHON) -m scripts.run_server --port $(PORT) --reload

predict:                                ## Predict on a CSV (override: make predict INPUT=file.csv)
	@test -n "$(INPUT)" || (echo "Usage: make predict INPUT=file.csv"; exit 1)
	$(PYTHON) -m scripts.predict --input $(INPUT)

# ─── Docker ──────────────────────────────────────────
docker-build:                           ## Build the API container image
	docker build -t netsentry:latest -f docker/Dockerfile .

docker-up:                              ## Start the full stack (API, trainer, nginx, prom, grafana)
	cd docker && docker compose up -d --build

docker-down:                            ## Tear down the stack
	cd docker && docker compose down

docker-logs:                            ## Tail API logs
	cd docker && docker compose logs -f api

# ─── Kubernetes ──────────────────────────────────────
k8s-apply:                              ## Apply all manifests to the current cluster
	kubectl apply -f deployment/kubernetes/namespace.yaml
	kubectl apply -f deployment/kubernetes/training-job.yaml
	kubectl apply -f deployment/kubernetes/deployment.yaml

k8s-delete:                             ## Tear down the NetSentry namespace and everything in it
	kubectl delete namespace netsentry --ignore-not-found

# ─── One-shot demo ──────────────────────────────────
demo: install train serve               ## Install deps, train on 20k flows, then serve the API
