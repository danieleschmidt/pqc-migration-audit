# Maintenance and Operational Procedures

## Overview

This document outlines routine maintenance procedures for the PQC Migration Audit system to ensure optimal performance, security, and reliability.

## Scheduled Maintenance

### Daily Maintenance (Automated)

#### System Health Checks
```bash
#!/bin/bash
# Daily health check script

# Check service availability
curl -f http://pqc-audit:8080/health || echo "ALERT: Service health check failed"

# Verify crypto library integrity
kubectl exec -it $(kubectl get pods -l app=pqc-audit -o name | head -1) -- python -c "
import liboqs
print('Crypto libraries OK' if liboqs.get_enabled_algorithms() else 'ALERT: Crypto library issue')
"

# Check resource usage
kubectl top pods -l app=pqc-audit | awk 'NR>1 && ($3+0) > 80 {print "ALERT: High CPU on " $1}'
kubectl top pods -l app=pqc-audit | awk 'NR>1 && ($4+0) > 80 {print "ALERT: High memory on " $1}'

# Verify backup integrity
find /backup -name "*.tar.gz" -mtime -1 | head -1 | xargs -I {} tar -tzf {} > /dev/null && echo "Backup integrity OK"
```

#### Log Rotation and Cleanup
```bash
#!/bin/bash
# Daily log cleanup

# Compress old logs
find /var/log/pqc-audit -name "*.log" -mtime +7 -exec gzip {} \;

# Remove old compressed logs
find /var/log/pqc-audit -name "*.log.gz" -mtime +30 -delete

# Clean temporary scan files
kubectl exec -it $(kubectl get pods -l app=pqc-audit -o name | head -1) -- find /tmp/pqc-cache -type f -mtime +1 -delete

# Vacuum database (if using PostgreSQL)
kubectl exec -it postgres-pod -- psql -U postgres -d pqc_audit -c "VACUUM ANALYZE;"
```

### Weekly Maintenance

#### Security Updates
```bash
#!/bin/bash
# Weekly security maintenance

# Update base container images
docker pull python:3.11-slim
docker pull postgres:15-alpine
docker pull redis:7-alpine

# Rebuild with security patches
docker build -t pqc-audit:latest --no-cache .

# Update Kubernetes deployments
kubectl set image deployment/pqc-audit pqc-audit=pqc-audit:latest
kubectl rollout status deployment/pqc-audit

# Security scan of new images
trivy image pqc-audit:latest --severity HIGH,CRITICAL
```

#### Performance Analysis
```bash
#!/bin/bash
# Weekly performance review

# Generate performance report
curl -s "http://prometheus:9090/api/v1/query_range?query=pqc:scan_duration_p95_5m&start=$(date -d '7 days ago' -Iseconds)&end=$(date -Iseconds)&step=3600s" > performance_report.json

# Check for performance degradation
python3 << 'EOF'
import json
import statistics

with open('performance_report.json') as f:
    data = json.load(f)

values = [float(v[1]) for v in data['data']['result'][0]['values']]
current_avg = statistics.mean(values[-24:])  # Last 24 hours
previous_avg = statistics.mean(values[-168:-24])  # Previous week

if current_avg > previous_avg * 1.2:
    print(f"ALERT: Performance degradation detected - {current_avg:.2f}s vs {previous_avg:.2f}s")
else:
    print(f"Performance stable - {current_avg:.2f}s average")
EOF

# Resource utilization analysis
kubectl top nodes
kubectl describe nodes | grep -A 5 "Allocated resources"
```

#### Backup Verification
```bash
#!/bin/bash
# Weekly backup verification

# Test backup restoration
BACKUP_FILE=$(ls -t /backup/pqc-audit-*.tar.gz | head -1)
mkdir -p /tmp/backup-test
tar -xzf $BACKUP_FILE -C /tmp/backup-test

# Verify backup contents
if [ -f "/tmp/backup-test/database.sql" ] && [ -f "/tmp/backup-test/config.yaml" ]; then
    echo "Backup verification successful"
else
    echo "ALERT: Backup verification failed"
fi

rm -rf /tmp/backup-test

# Test database backup
kubectl exec -it postgres-pod -- pg_dump -U postgres pqc_audit | head -20 | grep -q "PostgreSQL database dump" && echo "Database backup OK"
```

### Monthly Maintenance

#### Capacity Planning Review
```bash
#!/bin/bash
# Monthly capacity review

# Resource growth analysis
curl -s "http://prometheus:9090/api/v1/query_range?query=pqc:memory_utilization_percentage&start=$(date -d '30 days ago' -Iseconds)&end=$(date -Iseconds)&step=86400s" > capacity_data.json

# Storage usage analysis
kubectl exec -it $(kubectl get pods -l app=pqc-audit -o name | head -1) -- df -h | grep -E "(/var|/tmp|/data)" 

# Network traffic analysis
curl -s "http://prometheus:9090/api/v1/query_range?query=rate(container_network_transmit_bytes_total[5m])&start=$(date -d '30 days ago' -Iseconds)&end=$(date -Iseconds)&step=86400s" > network_data.json

# Generate capacity report
python3 capacity_analysis.py > monthly_capacity_report.txt
```

#### Certificate Rotation
```bash
#!/bin/bash
# Monthly certificate maintenance

# Check certificate expiration
kubectl get certificates -A -o custom-columns=NAME:.metadata.name,READY:.status.conditions[0].status,EXPIRES:.status.notAfter

# Rotate certificates expiring within 60 days
kubectl get certificates -A -o json | jq -r '.items[] | select(.status.notAfter | strptime("%Y-%m-%dT%H:%M:%SZ") | mktime < (now + 5184000)) | .metadata.name' | while read cert; do
    kubectl delete certificate $cert
    kubectl apply -f certificates/$cert.yaml
done

# Update internal CA if needed
openssl x509 -in /etc/ssl/certs/ca-certificates.crt -text -noout | grep "Not After"
```

#### Compliance Audit
```bash
#!/bin/bash
# Monthly compliance check

# Security compliance scan
kubectl exec -it $(kubectl get pods -l app=pqc-audit -o name | head -1) -- python -m pqc_migration_audit.compliance_check

# NIST framework compliance
curl -X POST http://pqc-audit:8080/admin/compliance-report -H "Content-Type: application/json" -d '{"framework": "nist", "output": "detailed"}'

# Generate compliance report
kubectl logs -l app=pqc-audit | grep COMPLIANCE | tail -100 > monthly_compliance_report.txt

# Check for policy violations
kubectl get networkpolicies,podsecuritypolicies -A
kubectl auth can-i --list --as=system:serviceaccount:default:pqc-audit
```

### Quarterly Maintenance

#### Major Version Updates
```bash
#!/bin/bash
# Quarterly major updates

# Update Python dependencies
pip list --outdated > outdated_packages.txt
pip install --upgrade -r requirements.txt

# Update Kubernetes components
kubectl version --client
kubectl cluster-info

# Update monitoring stack
helm upgrade prometheus prometheus-community/kube-prometheus-stack
helm upgrade grafana grafana/grafana

# Update security tools
trivy --version
docker pull aquasec/trivy:latest
```

#### Disaster Recovery Testing
```bash
#!/bin/bash
# Quarterly DR test

# Simulate database failure
kubectl scale deployment postgres --replicas=0

# Test backup restoration
./scripts/restore_from_backup.sh /backup/pqc-audit-$(date +%Y%m%d).tar.gz

# Verify service recovery
sleep 60
curl -f http://pqc-audit:8080/health

# Test cross-region failover (if applicable)
kubectl config use-context dr-cluster
kubectl apply -f k8s/
kubectl rollout status deployment/pqc-audit

# Document recovery time
echo "DR test completed at $(date), RTO: $recovery_time minutes" >> dr_test_log.txt
```

## Emergency Procedures

### Service Outage Response
```bash
#!/bin/bash
# Emergency service restoration

# Quick diagnosis
kubectl get pods -l app=pqc-audit
kubectl describe pod -l app=pqc-audit | grep -A 10 "Events"
kubectl logs -l app=pqc-audit --tail=100

# Emergency restart
kubectl rollout restart deployment/pqc-audit
kubectl rollout status deployment/pqc-audit --timeout=300s

# Scale out for recovery
kubectl scale deployment pqc-audit --replicas=5

# Notification
curl -X POST $SLACK_WEBHOOK -d '{"text": "PQC Audit service emergency restart completed"}'
```

### Data Corruption Recovery
```bash
#!/bin/bash
# Emergency data recovery

# Stop service to prevent further corruption
kubectl scale deployment pqc-audit --replicas=0

# Backup current state
kubectl exec -it postgres-pod -- pg_dump -U postgres pqc_audit > /backup/emergency_backup_$(date +%s).sql

# Restore from last known good backup
LAST_BACKUP=$(ls -t /backup/pqc-audit-*.tar.gz | head -1)
./scripts/restore_from_backup.sh $LAST_BACKUP

# Validate restoration
kubectl scale deployment pqc-audit --replicas=1
sleep 30
curl -f http://pqc-audit:8080/health/detailed

# Resume normal operations
kubectl scale deployment pqc-audit --replicas=3
```

### Security Incident Response
```bash
#!/bin/bash
# Security incident response

# Immediate isolation
kubectl patch deployment pqc-audit -p '{"spec":{"template":{"spec":{"hostNetwork":false,"dnsPolicy":"None"}}}}'

# Collect forensic evidence
kubectl logs -l app=pqc-audit --previous > incident_logs_$(date +%s).txt
kubectl get events --sort-by='.lastTimestamp' > incident_events_$(date +%s).txt

# Rotate all credentials
kubectl delete secret pqc-audit-secrets
kubectl create secret generic pqc-audit-secrets --from-env-file=.env.new

# Force pod recreation with new secrets
kubectl rollout restart deployment/pqc-audit

# Enable enhanced monitoring
kubectl patch deployment pqc-audit -p '{"spec":{"template":{"spec":{"containers":[{"name":"pqc-audit","env":[{"name":"LOG_LEVEL","value":"DEBUG"},{"name":"AUDIT_MODE","value":"enabled"}]}]}}}}'
```

## Automation Scripts

### Health Check Automation
```python
#!/usr/bin/env python3
"""
Automated health check and self-healing script
"""
import requests
import subprocess
import time
import logging

def check_service_health():
    try:
        response = requests.get("http://pqc-audit:8080/health", timeout=10)
        return response.status_code == 200
    except:
        return False

def restart_service():
    subprocess.run(["kubectl", "rollout", "restart", "deployment/pqc-audit"])
    time.sleep(60)  # Wait for restart
    
def check_resource_usage():
    result = subprocess.run(["kubectl", "top", "pods", "-l", "app=pqc-audit"], 
                          capture_output=True, text=True)
    return "80%" not in result.stdout  # Simple threshold check

def main():
    logging.basicConfig(level=logging.INFO)
    
    if not check_service_health():
        logging.warning("Service health check failed, attempting restart")
        restart_service()
        
        if not check_service_health():
            logging.error("Service restart failed, escalating")
            subprocess.run(["curl", "-X", "POST", os.environ["ALERT_WEBHOOK"]])
    
    if not check_resource_usage():
        logging.warning("High resource usage detected")
        # Could implement auto-scaling logic here
        
    logging.info("Health check completed successfully")

if __name__ == "__main__":
    main()
```

### Backup Automation
```bash
#!/bin/bash
# Automated backup script

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backup"
RETENTION_DAYS=30

# Create backup directory
mkdir -p $BACKUP_DIR

# Database backup
kubectl exec -it postgres-pod -- pg_dump -U postgres pqc_audit > $BACKUP_DIR/database_$DATE.sql

# Configuration backup
kubectl get configmaps,secrets -o yaml > $BACKUP_DIR/config_$DATE.yaml

# Application data backup
kubectl exec -it $(kubectl get pods -l app=pqc-audit -o name | head -1) -- tar -czf - /data > $BACKUP_DIR/appdata_$DATE.tar.gz

# Create comprehensive backup archive
tar -czf $BACKUP_DIR/pqc-audit-backup_$DATE.tar.gz $BACKUP_DIR/*_$DATE.*

# Clean up individual files
rm $BACKUP_DIR/database_$DATE.sql $BACKUP_DIR/config_$DATE.yaml $BACKUP_DIR/appdata_$DATE.tar.gz

# Remove old backups
find $BACKUP_DIR -name "pqc-audit-backup_*.tar.gz" -mtime +$RETENTION_DAYS -delete

# Verify backup
tar -tzf $BACKUP_DIR/pqc-audit-backup_$DATE.tar.gz > /dev/null && echo "Backup verification successful"

# Upload to remote storage (optional)
# aws s3 cp $BACKUP_DIR/pqc-audit-backup_$DATE.tar.gz s3://backup-bucket/
```

## Monitoring and Alerting

### Maintenance Dashboards
```json
{
  "dashboard": {
    "title": "PQC Audit Maintenance Dashboard",
    "panels": [
      {
        "title": "System Health Score",
        "type": "stat",
        "targets": [
          {
            "expr": "(pqc:service_availability_5m + (1 - pqc:error_rate_5m) + (1 - pqc:memory_utilization_percentage/100)) / 3",
            "legendFormat": "Health Score"
          }
        ]
      },
      {
        "title": "Maintenance Activities",
        "type": "table",
        "targets": [
          {
            "expr": "pqc_maintenance_tasks_total",
            "legendFormat": "{{task_type}}"
          }
        ]
      }
    ]
  }
}
```

### Maintenance Alerts
```yaml
groups:
- name: maintenance-alerts
  rules:
  - alert: MaintenanceRequired
    expr: time() - pqc_last_maintenance_timestamp > 86400 * 7
    labels:
      severity: warning
    annotations:
      summary: "Weekly maintenance overdue"
      description: "System maintenance has not been performed in over 7 days"
      
  - alert: BackupFailure
    expr: pqc_backup_success == 0
    for: 1h
    labels:
      severity: critical
    annotations:
      summary: "Backup failure detected"
      description: "Automated backup has failed"
```

## Documentation and Change Management

### Maintenance Logs
```bash
# Maintenance log template
cat > maintenance_log_template.md << 'EOF'
# Maintenance Log - $(date +%Y-%m-%d)

## Pre-maintenance Status
- Service Health: [ ]
- Resource Usage: [ ]
- Active Alerts: [ ]

## Maintenance Activities
- [ ] Security updates
- [ ] Performance optimization
- [ ] Backup verification
- [ ] Certificate rotation

## Post-maintenance Validation
- [ ] Service health check
- [ ] Performance verification
- [ ] Alert validation
- [ ] User acceptance test

## Issues Encountered
- None / [Description of any issues]

## Next Maintenance Items
- [Items for next maintenance window]

Performed by: [Name]
Duration: [Start] - [End]
EOF
```

### Change Control Process
1. **Pre-approval**: All maintenance changes require approval
2. **Documentation**: Changes must be documented in advance
3. **Testing**: Changes tested in staging environment first
4. **Rollback Plan**: Documented rollback procedure required
5. **Post-verification**: Mandatory post-change validation
6. **Lessons Learned**: Document improvements for future maintenance