# syntax=docker/dockerfile:1.6
# Multi-stage build for NIDS.
# Stage 1: build a slim venv with only the runtime deps.
# Stage 2: copy the venv + source into a minimal final image.

ARG PYTHON_VERSION=3.11-slim

# ──────────────────────────────────────────────────────────────────────
FROM python:${PYTHON_VERSION} AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

# System deps needed only for building wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        g++ \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Set up virtualenv that we'll copy to the final image
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt


# ──────────────────────────────────────────────────────────────────────
FROM python:${PYTHON_VERSION} AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH=/app

# Run as non-root for basic container hardening
RUN groupadd --system --gid 1000 nids \
    && useradd --system --uid 1000 --gid nids --create-home --shell /bin/bash nids

WORKDIR /app

# Copy venv and source
COPY --from=builder /opt/venv /opt/venv
COPY --chown=nids:nids src /app/src
COPY --chown=nids:nids scripts /app/scripts
COPY --chown=nids:nids config /app/config
COPY --chown=nids:nids setup.py requirements.txt /app/

# Directories the runtime will write to
RUN mkdir -p /app/data /app/models_artifacts /app/logs \
    && chown -R nids:nids /app

USER nids

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; \
        r=urllib.request.urlopen('http://localhost:8000/api/v1/health',timeout=3); \
        sys.exit(0 if r.status==200 else 1)"

# Default = serve. Override with `docker run ... python -m scripts.train_pipeline` to train.
CMD ["python", "-m", "scripts.run_server", "--config", "config/config.yaml"]
