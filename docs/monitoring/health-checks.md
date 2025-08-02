# Health Check Configuration

## Overview

This document outlines the health check endpoints and monitoring configuration for the PQC Migration Audit system.

## Health Check Endpoints

### Primary Application Health
- **Endpoint**: `/health`
- **Method**: GET
- **Response Format**: JSON
- **Check Frequency**: 30 seconds

```json
{
  "status": "healthy",
  "timestamp": "2025-01-15T10:30:00Z",
  "version": "1.0.0",
  "checks": {
    "database": "healthy",
    "crypto_library": "healthy",
    "disk_space": "healthy",
    "memory_usage": "healthy"
  },
  "uptime": 86400,
  "environment": "production"
}
```

### Detailed Health Check
- **Endpoint**: `/health/detailed`
- **Method**: GET
- **Response Format**: JSON
- **Check Frequency**: 60 seconds

```json
{
  "status": "healthy",
  "timestamp": "2025-01-15T10:30:00Z",
  "components": {
    "crypto_engine": {
      "status": "healthy",
      "algorithms_loaded": ["ML-KEM-768", "ML-DSA-65", "SLH-DSA"],
      "last_scan_time": "2025-01-15T10:25:00Z"
    },
    "file_scanner": {
      "status": "healthy",
      "supported_languages": ["python", "java", "go", "javascript"],
      "scan_queue_size": 0
    },
    "metrics_collector": {
      "status": "healthy",
      "metrics_exported": 142,
      "last_export": "2025-01-15T10:29:45Z"
    }
  }
}
```

### Readiness Check
- **Endpoint**: `/health/ready`
- **Method**: GET
- **Purpose**: Kubernetes readiness probe
- **Response**: HTTP 200 (ready) or 503 (not ready)

### Liveness Check  
- **Endpoint**: `/health/live`
- **Method**: GET
- **Purpose**: Kubernetes liveness probe
- **Response**: HTTP 200 (alive) or 503 (dead)

## Prometheus Metrics Endpoints

### Application Metrics
- **Endpoint**: `/metrics`
- **Format**: Prometheus exposition format
- **Scrape Interval**: 30 seconds

### Custom PQC Metrics
```
# Cryptographic scanning metrics
pqc_scans_total{status="completed|failed|in_progress"}
pqc_vulnerabilities_found{severity="critical|high|medium|low", algorithm="rsa|ecc|other"}
pqc_scan_duration_seconds{scan_type="full|incremental"}
pqc_files_processed_total
pqc_lines_scanned_total

# Migration metrics
pqc_migration_progress{component="authentication|encryption|signing"}
pqc_algorithms_migrated_total{from_algorithm="", to_algorithm=""}
pqc_compatibility_score{integration=""}

# Performance metrics
pqc_scan_performance_score
pqc_memory_usage_bytes
pqc_cpu_utilization_percent
pqc_disk_io_operations_total

# Security metrics
pqc_security_violations_total{type="weak_key|deprecated_algorithm|insecure_implementation"}
pqc_compliance_score{framework="nist|fips|cc"}
```

## Structured Logging Configuration

### Log Levels
- **DEBUG**: Detailed scanning information
- **INFO**: General operational messages
- **WARN**: Potential issues or deprecated usage
- **ERROR**: Scan failures or system errors
- **CRITICAL**: Security violations or system failures

### Log Format
```json
{
  "timestamp": "2025-01-15T10:30:00.123Z",
  "level": "INFO",
  "service": "pqc-audit",
  "component": "crypto_scanner",
  "message": "RSA-1024 vulnerability detected",
  "context": {
    "file_path": "/src/crypto/keys.py",
    "line_number": 42,
    "algorithm": "RSA",
    "key_size": 1024,
    "severity": "critical",
    "scan_id": "scan-uuid-123",
    "user_id": "anonymous"
  },
  "trace_id": "trace-uuid-456",
  "span_id": "span-uuid-789"
}
```

### Security-Sensitive Logging
- **NO** private keys or sensitive cryptographic material
- **NO** user credentials or tokens
- **YES** algorithm types and parameters
- **YES** file paths and line numbers
- **YES** vulnerability classifications

## Container Health Checks

### Docker Health Check
```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1
```

### Kubernetes Probes
```yaml
livenessProbe:
  httpGet:
    path: /health/live
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /health/ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 2
```

## Alerting Health Checks

### Critical Alerts
- Service unavailable for >5 minutes
- Memory usage >85%
- Disk space <10%
- Critical security vulnerabilities found
- Crypto library initialization failures

### Warning Alerts  
- Response time >2 seconds
- Memory usage >70%
- Scan queue backlog >100 items
- Deprecated algorithm usage detected

## Implementation Examples

### Python Flask Health Endpoint
```python
from flask import Flask, jsonify
import psutil
import time
from datetime import datetime

app = Flask(__name__)
start_time = time.time()

@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'version': '1.0.0',
        'uptime': int(time.time() - start_time),
        'checks': {
            'memory': 'healthy' if psutil.virtual_memory().percent < 85 else 'unhealthy',
            'disk': 'healthy' if psutil.disk_usage('/').percent < 90 else 'unhealthy',
            'crypto_library': check_crypto_library_status()
        }
    })

@app.route('/health/ready')
def readiness_check():
    if not is_crypto_library_loaded():
        return '', 503
    return '', 200

@app.route('/health/live') 
def liveness_check():
    return '', 200
```

### Go HTTP Health Endpoint
```go
func healthHandler(w http.ResponseWriter, r *http.Request) {
    health := HealthCheck{
        Status:    "healthy",
        Timestamp: time.Now().UTC().Format(time.RFC3339),
        Version:   "1.0.0",
        Uptime:    int64(time.Since(startTime).Seconds()),
        Checks: CheckResults{
            Database:     checkDatabase(),
            CryptoEngine: checkCryptoEngine(),
            Memory:       checkMemoryUsage(),
        },
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(health)
}
```