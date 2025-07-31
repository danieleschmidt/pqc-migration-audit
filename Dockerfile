# Multi-stage Dockerfile for PQC Migration Audit
# Security-hardened container for cryptography audit tool

# Build stage
FROM python:3.11-slim as builder

# Security: Create non-root user
RUN groupadd -r pqcaudit && useradd -r -g pqcaudit pqcaudit

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml requirements*.txt ./
COPY src/ src/

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir . \
    && pip install --no-cache-dir -e .[test]

# Production stage
FROM python:3.11-slim as production

# Security hardening
RUN groupadd -r pqcaudit && useradd -r -g pqcaudit pqcaudit \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get purge -y --auto-remove

# Copy from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/pqc-audit /usr/local/bin/

# Set working directory and ownership
WORKDIR /workspace
RUN chown pqcaudit:pqcaudit /workspace

# Switch to non-root user
USER pqcaudit

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pqc-audit --version || exit 1

# Default command
ENTRYPOINT ["pqc-audit"]
CMD ["--help"]