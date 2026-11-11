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

# Security: Create unprivileged system group and user
RUN groupadd -g 10001 logmorph && \
    useradd -u 10001 -g logmorph -s /bin/bash -m logmorph

# Environment configuration
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src \
    PORT=8000

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

# Expose HTTP port
EXPOSE 8000

# Docker Healthcheck pinging /health
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/health || exit 1

# Production entrypoint supporting dynamic cloud $PORT
CMD ["sh", "-c", "uvicorn logmorph.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 2 --proxy-headers"]
