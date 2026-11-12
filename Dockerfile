# ==============================================================================
# Multi-Stage Production Dockerfile for LogMorph Backend API
# ==============================================================================

# --- Stage 1: Builder ---
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependencies manifest
COPY requirements.txt pyproject.toml ./

# Build wheels for all dependencies into /build/wheels
RUN pip install --no-cache-dir --upgrade pip wheel && \
    pip wheel --no-cache-dir --wheel-dir=/build/wheels -r requirements.txt


# --- Stage 2: Production Runtime ---
FROM python:3.11-slim AS runner

WORKDIR /app

# Install minimal runtime libraries (curl for container healthcheck ping)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Security: Create unprivileged system group and user (UID 1000 for Hugging Face Spaces & standard Linux)
RUN groupadd -g 1000 logmorph && \
    useradd -u 1000 -g logmorph -s /bin/bash -m logmorph

# Environment configuration
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src \
    PORT=7860

# Copy pre-built wheels from builder stage and install
COPY --from=builder /build/wheels /wheels
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir /wheels/* && \
    rm -rf /wheels

# Copy source code and configuration
COPY src ./src
COPY pyproject.toml ./

# Ensure correct file permissions for unprivileged user
RUN chown -R logmorph:logmorph /app

# Switch to non-root user
USER logmorph

# Expose HTTP ports (7860 for Hugging Face Spaces, 8000 for local docker compose)
EXPOSE 7860 8000

# Docker Healthcheck pinging /health
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT:-7860}/health || exit 1

# Production entrypoint supporting dynamic cloud $PORT (Hugging Face 7860, Render 10000, Compose 8000)
CMD ["sh", "-c", "uvicorn logmorph.main:app --host 0.0.0.0 --port ${PORT:-7860} --workers 2 --proxy-headers"]
