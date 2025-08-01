# Deployment Guide

This guide covers deploying the PQC Migration Audit tool in various environments.

## Container Deployment

### Quick Start with Docker

```bash
# Pull and run the latest image
docker run --rm -it -v $(pwd):/workspace terragonlabs/pqc-migration-audit:latest scan /workspace

# Run with custom configuration
docker run --rm -it \
  -v $(pwd):/workspace \
  -v $(pwd)/config:/config \
  -e PQC_AUDIT_CONFIG_FILE=/config/pqc-audit.yml \
  terragonlabs/pqc-migration-audit:latest scan /workspace
```

### Docker Compose Development

```bash
# Start development environment
docker-compose up -d

# Run a scan
docker-compose exec pqc-audit pqc-audit scan /workspace

# View logs
docker-compose logs -f pqc-audit

# Stop services
docker-compose down
```

### Docker Compose Production

```bash
# Set environment variables
export POSTGRES_PASSWORD=secure_password
export REDIS_PASSWORD=secure_redis_password
export SENTRY_DSN=your_sentry_dsn

# Deploy production stack
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Scale services
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d --scale pqc-audit=3

# Health check
docker-compose -f docker-compose.yml -f docker-compose.prod.yml ps
```

## Build Configuration

### Building Docker Images

```bash
# Build development image
make docker-build

# Build multi-platform production image
make docker-build-multi

# Test the built image
make docker-test

# Scan for vulnerabilities
make docker-scan
```

### Custom Build Parameters

```bash
# Custom image name and version
make docker-build IMAGE_NAME=my-pqc-audit VERSION=1.2.3

# Custom registry
make docker-build-multi REGISTRY=my-registry.com/security

# Multi-platform build
make docker-build-multi PLATFORM=linux/amd64,linux/arm64,linux/arm/v7
```

## Environment Configuration

### Required Environment Variables

```bash
# Core configuration
PQC_AUDIT_LOG_LEVEL=INFO
PQC_AUDIT_OUTPUT_DIR=/reports
PQC_AUDIT_CACHE_DIR=/cache

# Database (optional)
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=pqc_audit
POSTGRES_USER=pqc_user
POSTGRES_PASSWORD=secure_password

# Redis (optional)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=secure_redis_password

# Monitoring
SENTRY_DSN=https://your-sentry-dsn@sentry.io/project
PROMETHEUS_ENABLED=true
PROMETHEUS_PORT=9090
```

### Security Configuration

```bash
# API Security
API_KEY=your_secure_api_key
JWT_SECRET=your_jwt_secret

# Encryption
ENCRYPTION_KEY=32_byte_encryption_key_here
SIGNING_KEY=your_signing_key

# SSL/TLS
SSL_CERT_PATH=/etc/ssl/certs/server.crt
SSL_KEY_PATH=/etc/ssl/private/server.key
```

## Cloud Deployments

### AWS ECS

```yaml
# ecs-task-definition.json
{
  "family": "pqc-migration-audit",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "executionRoleArn": "arn:aws:iam::account:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::account:role/pqc-audit-task-role",
  "containerDefinitions": [
    {
      "name": "pqc-audit",
      "image": "terragonlabs/pqc-migration-audit:latest",
      "essential": true,
      "environment": [
        {"name": "PQC_AUDIT_LOG_LEVEL", "value": "INFO"},
        {"name": "AWS_REGION", "value": "us-east-1"}
      ],
      "secrets": [
        {
          "name": "POSTGRES_PASSWORD",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:pqc-audit/postgres:password::"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/pqc-migration-audit",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "pqc-audit --version || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      }
    }
  ]
}
```

### Kubernetes

```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pqc-migration-audit
  labels:
    app: pqc-migration-audit
spec:
  replicas: 3
  selector:
    matchLabels:
      app: pqc-migration-audit
  template:
    metadata:
      labels:
        app: pqc-migration-audit
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: pqc-audit
        image: terragonlabs/pqc-migration-audit:latest
        ports:
        - containerPort: 8000
        env:
        - name: PQC_AUDIT_LOG_LEVEL
          value: "INFO"
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: pqc-audit-secrets
              key: postgres-password
        resources:
          requests:
            cpu: 200m
            memory: 512Mi
          limits:
            cpu: 1000m
            memory: 2Gi
        livenessProbe:
          exec:
            command:
            - pqc-audit
            - --version
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          exec:
            command:
            - pqc-audit
            - --version
          initialDelaySeconds: 5
          periodSeconds: 10
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: reports
          mountPath: /reports
      volumes:
      - name: tmp
        emptyDir: {}
      - name: reports
        persistentVolumeClaim:
          claimName: pqc-audit-reports

---
apiVersion: v1
kind: Service
metadata:
  name: pqc-migration-audit-service
spec:
  selector:
    app: pqc-migration-audit
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8000
  type: ClusterIP

---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: pqc-audit-reports
spec:
  accessModes:
  - ReadWriteMany
  resources:
    requests:
      storage: 10Gi
```

### Azure Container Instances

```yaml
# azure-container-instance.yaml
apiVersion: 2021-03-01
location: eastus
name: pqc-migration-audit
properties:
  containers:
  - name: pqc-audit
    properties:
      image: terragonlabs/pqc-migration-audit:latest
      resources:
        requests:
          cpu: 1.0
          memoryInGb: 2.0
      environmentVariables:
      - name: PQC_AUDIT_LOG_LEVEL
        value: INFO
      - name: POSTGRES_PASSWORD
        secureValue: secure_password
      ports:
      - port: 8000
        protocol: TCP
      volumeMounts:
      - name: reports
        mountPath: /reports
  osType: Linux
  restartPolicy: Always
  ipAddress:
    type: Public
    ports:
    - protocol: TCP
      port: 8000
  volumes:
  - name: reports
    azureFile:
      shareName: pqc-audit-reports
      storageAccountName: pqcauditstorage
      storageAccountKey: storage_account_key
tags:
  environment: production
  project: pqc-migration-audit
```

## Security Hardening

### Container Security

```bash
# Run security scan
make security-container

# Use distroless base image (custom Dockerfile)
FROM gcr.io/distroless/python3-debian11
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/pqc-audit /usr/local/bin/
USER nonroot:nonroot
ENTRYPOINT ["pqc-audit"]
```

### Network Security

```yaml
# docker-compose.yml security additions
services:
  pqc-audit:
    security_opt:
      - no-new-privileges:true
      - seccomp:unconfined
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - SETGID
      - SETUID
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
```

### Secrets Management

```bash
# Docker Secrets
echo "secure_password" | docker secret create postgres_password -
docker service create \
  --name pqc-audit \
  --secret postgres_password \
  terragonlabs/pqc-migration-audit:latest

# Kubernetes Secrets
kubectl create secret generic pqc-audit-secrets \
  --from-literal=postgres-password=secure_password \
  --from-literal=redis-password=secure_redis_password

# HashiCorp Vault integration
export VAULT_ADDR=https://vault.company.com
vault kv put secret/pqc-audit \
  postgres_password=secure_password \
  redis_password=secure_redis_password
```

## Monitoring and Logging

### Prometheus Metrics

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'pqc-migration-audit'
    static_configs:
      - targets: ['pqc-audit:9090']
    metrics_path: /metrics
    scrape_interval: 30s
```

### Log Aggregation

```yaml
# fluentd/fluent.conf
<source>
  @type forward
  port 24224
  bind 0.0.0.0
</source>

<match pqc.audit.**>
  @type elasticsearch
  host elasticsearch
  port 9200
  index_name pqc-audit-logs
  type_name audit_log
</match>
```

### Health Checks

```bash
# Health check endpoints
curl http://localhost:8000/health
curl http://localhost:8000/metrics
curl http://localhost:8000/ready

# Kubernetes health checks
livenessProbe:
  httpGet:
    path: /health
    port: 8000
  initialDelaySeconds: 30
  periodSeconds: 30

readinessProbe:
  httpGet:
    path: /ready
    port: 8000
  initialDelaySeconds: 5
  periodSeconds: 10
```

## Performance Tuning

### Resource Allocation

```yaml
# Docker Compose resource limits
services:
  pqc-audit:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          cpus: '0.5'
          memory: 1G
```

### Database Optimization

```sql
-- PostgreSQL tuning
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET work_mem = '4MB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
SELECT pg_reload_conf();
```

### Redis Optimization

```bash
# Redis configuration
maxmemory 1gb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000
```

## Backup and Recovery

### Database Backups

```bash
# PostgreSQL backup
docker-compose exec database pg_dump -U pqc_user pqc_audit > backup.sql

# Automated backup script
#!/bin/bash
BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)
docker-compose exec -T database pg_dump -U pqc_user pqc_audit | gzip > "${BACKUP_DIR}/pqc_audit_${DATE}.sql.gz"
```

### Volume Backups

```bash
# Docker volume backup
docker run --rm -v pqc_reports_data:/data -v $(pwd):/backup alpine tar czf /backup/reports_backup.tar.gz -C /data .

# Kubernetes persistent volume backup
kubectl exec -n default pvc/pqc-audit-reports -- tar czf - /reports | gzip > reports_backup.tar.gz
```

## Troubleshooting

### Common Issues

1. **Container fails to start**
   ```bash
   docker logs pqc-audit
   docker-compose logs pqc-audit
   ```

2. **Permission errors**
   ```bash
   # Fix volume permissions
   sudo chown -R 1000:1000 ./reports
   sudo chmod -R 755 ./reports
   ```

3. **Database connection issues**
   ```bash
   # Check database connectivity
   docker-compose exec pqc-audit ping database
   docker-compose exec database pg_isready -U pqc_user
   ```

4. **High memory usage**
   ```bash
   # Monitor resource usage
   docker stats
   kubectl top pods
   ```

### Debug Mode

```bash
# Enable debug logging
docker run -e PQC_AUDIT_LOG_LEVEL=DEBUG terragonlabs/pqc-migration-audit:latest

# Interactive debugging
docker run -it --entrypoint=/bin/bash terragonlabs/pqc-migration-audit:latest
```

### Log Analysis

```bash
# View application logs
docker-compose logs -f pqc-audit

# Filter error logs
docker-compose logs pqc-audit 2>&1 | grep ERROR

# Tail logs in real-time
kubectl logs -f deployment/pqc-migration-audit
```

## Best Practices

1. **Use specific image tags** in production (not `latest`)
2. **Implement health checks** for all services
3. **Use secrets management** for sensitive data
4. **Enable resource limits** to prevent resource exhaustion
5. **Implement backup strategies** for persistent data
6. **Monitor application metrics** and set up alerts
7. **Use security scanning** in CI/CD pipelines
8. **Implement log aggregation** for centralized logging
9. **Use multi-stage builds** to minimize image size
10. **Test deployments** in staging environments first