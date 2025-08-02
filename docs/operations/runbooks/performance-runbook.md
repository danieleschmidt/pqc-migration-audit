# PQC Performance Degradation Runbook

## Overview
This runbook addresses performance issues in the PQC Migration Audit system, including slow scans, high resource usage, and throughput problems.

## Alert Details
**Alert Name**: `PQCPerformanceDegradation`  
**Severity**: Medium  
**Threshold**: P95 scan time > 30 seconds OR throughput < 100 files/minute  

## Immediate Assessment (First 10 minutes)

### 1. Identify Performance Bottleneck
```bash
# Check current performance metrics
curl -s "http://prometheus:9090/api/v1/query?query=pqc:scan_duration_p95_5m" | jq '.data.result[0].value[1]'

# Check throughput
curl -s "http://prometheus:9090/api/v1/query?query=rate(pqc_files_processed_total[5m])*60" | jq '.data.result[0].value[1]'

# Identify slow operations
kubectl logs -l app=pqc-audit --tail=100 | grep -E "SLOW|TIMEOUT|duration"
```

### 2. Check System Resources
```bash
# CPU utilization
kubectl top pods -l app=pqc-audit

# Memory usage patterns
curl -s "http://prometheus:9090/api/v1/query?query=pqc:memory_utilization_percentage"

# I/O wait times
kubectl exec -it $(kubectl get pods -l app=pqc-audit -o name | head -1) -- iostat -x 1 5
```

## Detailed Diagnosis

### CPU Performance Issues

#### Symptoms
- High CPU utilization (>80%)
- Slow cryptographic operations
- Thread contention

#### Diagnosis
```bash
# Check CPU metrics
curl -s "http://prometheus:9090/api/v1/query?query=rate(process_cpu_seconds_total{job=\"pqc-audit-app\"}[5m])*100"

# Profile CPU usage
kubectl exec -it $(kubectl get pods -l app=pqc-audit -o name | head -1) -- top -p 1

# Check for CPU throttling
kubectl describe pod -l app=pqc-audit | grep -A 5 "cpu"
```

#### Resolution
```bash
# Increase CPU limits
kubectl patch deployment pqc-audit -p '{"spec":{"template":{"spec":{"containers":[{"name":"pqc-audit","resources":{"limits":{"cpu":"2000m"},"requests":{"cpu":"1000m"}}}]}}}}'

# Enable CPU affinity for crypto operations
kubectl patch deployment pqc-audit -p '{"spec":{"template":{"spec":{"affinity":{"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"node.kubernetes.io/instance-type","operator":"In","values":["c5.xlarge","c5.2xlarge"]}]}]}}}}}}}'

# Optimize threading for crypto libraries
kubectl set env deployment/pqc-audit OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=4
```

### Memory Performance Issues

#### Symptoms
- High memory usage
- Frequent garbage collection
- Memory allocation failures
- Swap usage

#### Diagnosis
```bash
# Check memory patterns
curl -s "http://prometheus:9090/api/v1/query_range?query=process_resident_memory_bytes{job=\"pqc-audit-app\"}&start=$(date -d '1 hour ago' -Iseconds)&end=$(date -Iseconds)&step=300s"

# Analyze memory leaks
kubectl exec -it $(kubectl get pods -l app=pqc-audit -o name | head -1) -- python -c "
import psutil
import time
for i in range(10):
    print(f'Memory: {psutil.virtual_memory().percent}%')
    time.sleep(30)
"

# Check for memory fragmentation
kubectl exec -it $(kubectl get pods -l app=pqc-audit -o name | head -1) -- cat /proc/buddyinfo
```

#### Resolution
```bash
# Increase memory limits
kubectl patch deployment pqc-audit -p '{"spec":{"template":{"spec":{"containers":[{"name":"pqc-audit","resources":{"limits":{"memory":"4Gi"},"requests":{"memory":"2Gi"}}}]}}}}'

# Enable memory optimization
kubectl set env deployment/pqc-audit PYTHONOPTIMIZE=1 MALLOC_TRIM_THRESHOLD_=100000

# Configure garbage collection
kubectl set env deployment/pqc-audit PYTHONGC=1 GC_THRESHOLD="700,10,10"

# Add memory-mapped file caching
kubectl patch deployment pqc-audit -p '{"spec":{"template":{"spec":{"containers":[{"name":"pqc-audit","volumeMounts":[{"name":"tmp-cache","mountPath":"/tmp/pqc-cache","subPath":"cache"}]}],"volumes":[{"name":"tmp-cache","emptyDir":{"sizeLimit":"1Gi"}}]}}}}'
```

### I/O Performance Issues

#### Symptoms
- High disk I/O wait times
- Slow file scanning
- Network timeouts
- Database query slowdowns

#### Diagnosis
```bash
# Check I/O metrics
kubectl exec -it $(kubectl get pods -l app=pqc-audit -o name | head -1) -- iotop -ao

# Analyze file access patterns
kubectl logs -l app=pqc-audit | grep -E "scanning|reading" | tail -100

# Check network latency
kubectl exec -it $(kubectl get pods -l app=pqc-audit -o name | head -1) -- ping -c 5 api.github.com

# Database performance
curl -s http://pqc-audit:8080/health/detailed | jq '.components.database.response_time'
```

#### Resolution
```bash
# Add SSD storage class for better I/O
kubectl patch deployment pqc-audit -p '{"spec":{"template":{"spec":{"volumes":[{"name":"cache-volume","persistentVolumeClaim":{"claimName":"pqc-cache-ssd"}}]}}}}'

# Enable read-ahead optimization
kubectl set env deployment/pqc-audit READAHEAD_KB=4096

# Configure async I/O
kubectl set env deployment/pqc-audit ASYNC_IO_ENABLED=true MAX_CONCURRENT_FILES=50

# Add connection pooling
kubectl set env deployment/pqc-audit DB_POOL_SIZE=20 DB_MAX_CONNECTIONS=100
```

### Algorithmic Performance Issues

#### Symptoms
- Exponential time complexity on large files
- Regex timeout errors
- Infinite loops in scanning logic

#### Diagnosis
```bash
# Profile scanning operations
curl -X POST http://pqc-audit:8080/admin/enable-profiling

# Check for timeout patterns
kubectl logs -l app=pqc-audit | grep -E "timeout|abort|kill" | tail -50

# Analyze scan times by file size
curl -s "http://prometheus:9090/api/v1/query?query=pqc_scan_duration_seconds by (file_size_mb)"
```

#### Resolution
```bash
# Add scan timeouts
kubectl set env deployment/pqc-audit SCAN_TIMEOUT_SECONDS=300 MAX_FILE_SIZE_MB=100

# Enable incremental scanning
kubectl set env deployment/pqc-audit INCREMENTAL_SCAN=true CACHE_SCAN_RESULTS=true

# Optimize regex patterns
curl -X POST http://pqc-audit:8080/admin/update-regex-patterns -d '{"optimize_for_performance": true}'

# Add file filtering
kubectl set env deployment/pqc-audit SKIP_BINARY_FILES=true SKIP_LARGE_FILES=true
```

## Performance Optimization Strategies

### 1. Horizontal Scaling
```bash
# Scale out for better throughput
kubectl scale deployment pqc-audit --replicas=5

# Add pod anti-affinity for distribution
kubectl patch deployment pqc-audit -p '{"spec":{"template":{"spec":{"affinity":{"podAntiAffinity":{"preferredDuringSchedulingIgnoredDuringExecution":[{"weight":100,"podAffinityTerm":{"labelSelector":{"matchExpressions":[{"key":"app","operator":"In","values":["pqc-audit"]}]},"topologyKey":"kubernetes.io/hostname"}}]}}}}}}'

# Configure load balancing
kubectl patch service pqc-audit -p '{"spec":{"sessionAffinity":"None"}}'
```

### 2. Caching Strategies
```bash
# Enable result caching
kubectl set env deployment/pqc-audit CACHE_ENABLED=true CACHE_TTL_HOURS=24

# Add Redis for distributed caching
helm install redis bitnami/redis --set auth.enabled=false --set replica.replicaCount=1

# Configure cache warming
kubectl create job pqc-cache-warm --image=pqc-audit:latest -- python -m pqc_migration_audit.cache_warmer
```

### 3. Database Optimization
```bash
# Add database indexes
kubectl exec -it postgres-pod -- psql -U postgres -c "CREATE INDEX CONCURRENTLY idx_scan_results_created_at ON scan_results(created_at);"

# Enable connection pooling
kubectl set env deployment/pqc-audit DB_POOL_SIZE=20 DB_POOL_TIMEOUT=30

# Configure read replicas
kubectl apply -f postgres-read-replica.yaml
kubectl set env deployment/pqc-audit DB_READ_REPLICA_URL="postgres://read-replica:5432/pqc_audit"
```

### 4. Algorithm Optimization
```bash
# Enable parallel processing
kubectl set env deployment/pqc-audit PARALLEL_WORKERS=4 WORKER_THREADS=2

# Optimize crypto operations
kubectl set env deployment/pqc-audit CRYPTO_ACCELERATION=true USE_HARDWARE_RNG=true

# Configure batch processing
kubectl set env deployment/pqc-audit BATCH_SIZE=100 BATCH_TIMEOUT=60
```

## Monitoring and Alerting

### Performance SLIs/SLOs
```yaml
# Add performance monitoring
apiVersion: v1
kind: ConfigMap
metadata:
  name: performance-slos
data:
  slos.yaml: |
    objectives:
      - name: scan_latency
        target: 0.95
        indicator: pqc:scan_duration_p95_5m < 30
      - name: throughput
        target: 0.99
        indicator: pqc:scan_rate_5m > 1.67  # 100 files/minute
      - name: resource_efficiency
        target: 0.90
        indicator: pqc:cpu_utilization_percentage < 80
```

### Custom Alerts
```yaml
# Performance degradation alerts
groups:
- name: performance-alerts
  rules:
  - alert: ScanLatencyHigh
    expr: pqc:scan_duration_p95_5m > 30
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "High scan latency detected"
      description: "P95 scan latency is {{ $value }}s"
      
  - alert: ThroughputLow  
    expr: rate(pqc_files_processed_total[5m]) * 60 < 100
    for: 15m
    labels:
      severity: warning
    annotations:
      summary: "Low scan throughput"
      description: "Processing {{ $value }} files per minute"
```

## Capacity Planning

### Resource Scaling Guidelines
```bash
# Calculate resource requirements
FILES_PER_HOUR=10000
AVG_FILE_SIZE_KB=50
PROCESSING_TIME_MS=100

# CPU requirements (cores)
CPU_CORES=$((FILES_PER_HOUR * PROCESSING_TIME_MS / 3600000))

# Memory requirements (GB)  
MEMORY_GB=$((FILES_PER_HOUR * AVG_FILE_SIZE_KB / 1000000))

echo "Recommended: ${CPU_CORES} CPU cores, ${MEMORY_GB}GB RAM"
```

### Auto-scaling Configuration
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: pqc-audit-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: pqc-audit
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
```

## Testing and Validation

### Performance Testing
```bash
# Load testing with scan workload
kubectl create job pqc-load-test --image=pqc-audit:latest -- python -m pqc_migration_audit.load_test --files=1000 --concurrency=10

# Benchmark crypto operations
kubectl exec -it $(kubectl get pods -l app=pqc-audit -o name | head -1) -- python -m pqc_migration_audit.benchmark

# Stress test memory usage
kubectl create job pqc-stress-test --image=pqc-audit:latest -- stress-ng --vm 2 --vm-bytes 2G --timeout 300s
```

### Performance Regression Testing
```bash
# Automated performance testing in CI
cat > .github/workflows/performance-test.yml << 'EOF'
name: Performance Regression Test
on:
  pull_request:
    branches: [main]
jobs:
  performance-test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Run Performance Tests
      run: |
        docker run --rm pqc-audit:test python -m pytest tests/performance/ --benchmark-json=results.json
    - name: Compare with Baseline
      run: |
        python scripts/compare_performance.py results.json baseline_performance.json
EOF
```

## Related Documentation
- [System Resource Monitoring](../monitoring/resource-monitoring.md)
- [Database Performance Tuning](database-performance.md)
- [Network Optimization](network-optimization.md)
- [Capacity Planning Guide](capacity-planning.md)