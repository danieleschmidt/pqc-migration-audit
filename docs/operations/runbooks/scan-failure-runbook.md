# PQC Scan Failure Runbook

## Overview
This runbook provides step-by-step procedures for diagnosing and resolving PQC scanning failures.

## Alert Details
**Alert Name**: `PQCScanFailure`  
**Severity**: High  
**Threshold**: Scan failure rate > 5% over 10 minutes  

## Immediate Response (First 5 minutes)

### 1. Assess Severity
```bash
# Check current failure rate
curl -s "http://prometheus:9090/api/v1/query?query=rate(pqc_scan_errors_total[5m])" | jq '.data.result[0].value[1]'

# Check if service is up
curl -f http://pqc-audit:8080/health || echo "Service Down"

# Check recent error logs
kubectl logs -l app=pqc-audit --tail=100 | grep ERROR
```

### 2. Check System Resources
```bash
# Memory usage
kubectl top pods -l app=pqc-audit

# CPU usage  
kubectl describe pod -l app=pqc-audit | grep -A 5 "Limits\|Requests"

# Disk space
kubectl exec -it $(kubectl get pods -l app=pqc-audit -o name | head -1) -- df -h
```

## Diagnosis Procedures

### Common Failure Patterns

#### 1. Memory Exhaustion
**Symptoms**: 
- OOMKilled events
- Scan timeouts on large files
- Gradual memory leak over time

**Diagnosis**:
```bash
# Check memory metrics
curl -s "http://prometheus:9090/api/v1/query?query=process_resident_memory_bytes{job=\"pqc-audit-app\"}"

# Check for memory leaks
kubectl logs -l app=pqc-audit | grep -i "memory\|oom"

# Analyze memory usage patterns
kubectl exec -it $(kubectl get pods -l app=pqc-audit -o name | head -1) -- cat /proc/meminfo
```

**Resolution**:
```bash
# Restart service to clear memory
kubectl rollout restart deployment/pqc-audit

# Increase memory limits if needed
kubectl patch deployment pqc-audit -p '{"spec":{"template":{"spec":{"containers":[{"name":"pqc-audit","resources":{"limits":{"memory":"4Gi"}}}]}}}}'
```

#### 2. Crypto Library Issues
**Symptoms**:
- Initialization failures
- Algorithm not found errors
- Segmentation faults

**Diagnosis**:
```bash
# Check crypto library status
curl -s http://pqc-audit:8080/health/detailed | jq '.components.crypto_engine'

# Verify library loading
kubectl exec -it $(kubectl get pods -l app=pqc-audit -o name | head -1) -- python -c "import liboqs; print(liboqs.get_enabled_algorithms())"

# Check library versions
kubectl exec -it $(kubectl get pods -l app=pqc-audit -o name | head -1) -- pip list | grep -E "(liboqs|cryptography|pqcrypto)"
```

**Resolution**:
```bash
# Rebuild with updated libraries
docker build --no-cache -t pqc-audit:latest .

# Update crypto dependencies
pip install --upgrade liboqs cryptography

# Restart with fresh libraries
kubectl delete pod -l app=pqc-audit
```

#### 3. File System Access Issues
**Symptoms**:
- Permission denied errors
- File not found for existing files
- Scan hangs on specific directories

**Diagnosis**:
```bash
# Check file permissions
kubectl exec -it $(kubectl get pods -l app=pqc-audit -o name | head -1) -- ls -la /scan-target/

# Verify mount points
kubectl describe pod -l app=pqc-audit | grep -A 10 "Mounts\|Volumes"

# Test file system access
kubectl exec -it $(kubectl get pods -l app=pqc-audit -o name | head -1) -- touch /tmp/test-write && rm /tmp/test-write
```

**Resolution**:
```bash
# Fix volume mounts
kubectl patch deployment pqc-audit -p '{"spec":{"template":{"spec":{"containers":[{"name":"pqc-audit","volumeMounts":[{"name":"scan-volume","mountPath":"/scan-target","readOnly":true}]}]}}}}'

# Update security context
kubectl patch deployment pqc-audit -p '{"spec":{"template":{"spec":{"securityContext":{"runAsUser":1000,"runAsGroup":1000,"fsGroup":1000}}}}}'
```

#### 4. Network Connectivity Issues
**Symptoms**:
- API timeouts
- Database connection failures
- Metrics export failures

**Diagnosis**:
```bash
# Test internal connectivity
kubectl exec -it $(kubectl get pods -l app=pqc-audit -o name | head -1) -- nslookup kubernetes.default

# Check network policies
kubectl get networkpolicy -A

# Test external connectivity
kubectl exec -it $(kubectl get pods -l app=pqc-audit -o name | head -1) -- curl -I https://api.github.com
```

**Resolution**:
```bash
# Restart networking
kubectl delete pod -l app=pqc-audit

# Update network policies if needed
kubectl apply -f network-policy.yaml

# Check service endpoints
kubectl get endpoints pqc-audit-service
```

## Recovery Procedures

### 1. Service Recovery
```bash
# Quick restart
kubectl rollout restart deployment/pqc-audit

# Full reset with config reload
kubectl delete configmap pqc-audit-config
kubectl apply -f k8s/configmap.yaml
kubectl rollout restart deployment/pqc-audit

# Scale down and up
kubectl scale deployment pqc-audit --replicas=0
kubectl scale deployment pqc-audit --replicas=3
```

### 2. Data Recovery
```bash
# Restore from backup if scan data corrupted
kubectl exec -it $(kubectl get pods -l app=pqc-audit -o name | head -1) -- cp /backup/scan-results.json /data/

# Clear corrupted cache
kubectl exec -it $(kubectl get pods -l app=pqc-audit -o name | head -1) -- rm -rf /tmp/pqc-cache/*

# Reset scan queue
curl -X POST http://pqc-audit:8080/admin/reset-queue
```

### 3. Configuration Recovery
```bash
# Restore default configuration
kubectl apply -f k8s/default-config.yaml

# Validate configuration
kubectl exec -it $(kubectl get pods -l app=pqc-audit -o name | head -1) -- python -m pqc_migration_audit.config --validate

# Reload configuration without restart
curl -X POST http://pqc-audit:8080/admin/reload-config
```

## Escalation Procedures

### When to Escalate
- Multiple recovery attempts fail
- Data corruption suspected
- Security implications identified
- Service down for >30 minutes

### Escalation Contacts
1. **Primary On-Call**: pager-security@company.com
2. **Secondary**: security-team@company.com  
3. **Management**: security-manager@company.com

### Information to Gather
```bash
# Collect diagnostic bundle
kubectl logs -l app=pqc-audit --previous > pqc-audit-logs.txt
kubectl describe pod -l app=pqc-audit > pqc-audit-pods.txt
kubectl get events --sort-by='.lastTimestamp' > pqc-audit-events.txt

# Performance metrics
curl -s "http://prometheus:9090/api/v1/query_range?query=rate(pqc_scan_errors_total[5m])&start=$(date -d '1 hour ago' -Iseconds)&end=$(date -Iseconds)&step=60s" > error-metrics.json

# System status
kubectl get pods,services,configmaps,secrets -l app=pqc-audit -o yaml > pqc-audit-resources.yaml
```

## Post-Incident Actions

### 1. Root Cause Analysis
- Review logs and metrics for failure triggers
- Identify configuration or code issues
- Document timeline and impact
- Update monitoring thresholds if needed

### 2. Preventive Measures
```bash
# Add more comprehensive health checks
kubectl patch deployment pqc-audit -p '{"spec":{"template":{"spec":{"containers":[{"name":"pqc-audit","livenessProbe":{"httpGet":{"path":"/health/deep","port":8080},"initialDelaySeconds":60,"periodSeconds":30}}]}}}}'

# Implement circuit breakers
curl -X POST http://pqc-audit:8080/admin/enable-circuit-breaker

# Add resource limits
kubectl patch deployment pqc-audit -p '{"spec":{"template":{"spec":{"containers":[{"name":"pqc-audit","resources":{"limits":{"memory":"2Gi","cpu":"1000m"},"requests":{"memory":"1Gi","cpu":"500m"}}}]}}}}'
```

### 3. Documentation Updates
- Update runbook with new failure patterns
- Add monitoring for identified gaps
- Create additional automated remediation
- Train team on new procedures

## Testing Recovery Procedures

### Monthly Testing
```bash
# Test failure simulation
kubectl patch deployment pqc-audit -p '{"spec":{"template":{"spec":{"containers":[{"name":"pqc-audit","env":[{"name":"SIMULATE_FAILURE","value":"true"}]}]}}}}'

# Verify alert firing
sleep 300 && curl -s http://alertmanager:9093/api/v1/alerts | jq '.data[] | select(.labels.alertname == "PQCScanFailure")'

# Test recovery procedures
kubectl rollout restart deployment/pqc-audit

# Validate service restoration
curl -f http://pqc-audit:8080/health
```

## Related Runbooks
- [Memory Issues Runbook](memory-issues-runbook.md)
- [Performance Degradation Runbook](performance-runbook.md)
- [Security Incident Runbook](security-incident-runbook.md)
- [Backup and Recovery Runbook](backup-recovery-runbook.md)