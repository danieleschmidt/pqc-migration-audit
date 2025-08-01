# Multi-stage Dockerfile for PQC Migration Audit
# Security-hardened container for cryptography audit tool

# Build stage
FROM python:3.11-slim as builder

# Security: Create non-root user with specific UID/GID
RUN groupadd -r -g 1000 pqcaudit && useradd -r -u 1000 -g pqcaudit pqcaudit

# Install build dependencies and security updates
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get autoremove -y \
    && apt-get autoclean

WORKDIR /app
COPY pyproject.toml requirements*.txt ./
COPY src/ src/

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir . \
    && pip install --no-cache-dir -e .[test]

# Production stage
FROM python:3.11-slim as production

# Security hardening and system setup
RUN groupadd -r -g 1000 pqcaudit && useradd -r -u 1000 -g pqcaudit pqcaudit \
    && apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get autoremove -y \
    && apt-get autoclean

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

# Security labels and metadata
LABEL maintainer="daniel@terragonlabs.com" \
      version="1.0.0" \
      description="PQC Migration Audit - Post-Quantum Cryptography Analysis Tool" \
      org.opencontainers.image.source="https://github.com/danieleschmidt/pqc-migration-audit" \
      org.opencontainers.image.documentation="https://pqc-migration-audit.readthedocs.io" \
      org.opencontainers.image.licenses="MIT"

# Use tini as init system for proper signal handling
ENTRYPOINT ["tini", "--", "pqc-audit"]
CMD ["--help"]