# Container Security Scanning Setup

## Overview

This document outlines the container security scanning strategy for the PQC Migration Audit tool, including vulnerability scanning, compliance checks, and hardening guidelines.

## Container Security Tools

### 1. Trivy - Comprehensive Vulnerability Scanner

#### Configuration
```yaml
# .trivyignore
# Temporary exclusions with justification
CVE-2023-12345  # False positive in base image, fixed in newer version
```

#### Scanning Commands
```bash
# Vulnerability scanning
trivy image pqc-migration-audit:latest

# Configuration scanning
trivy config Dockerfile

# Filesystem scanning
trivy fs .

# SARIF output for CI/CD
trivy image --format sarif -o trivy-results.sarif pqc-migration-audit:latest
```

### 2. Grype - Alternative Vulnerability Scanner

#### Configuration
```yaml
# .grype.yml
ignore:
  - vulnerability: "GHSA-*"
    package:
      name: "test-package"
      version: "1.0.0"
    
check-for-app-update: false
fail-on-severity: "medium"
output: ["json", "table"]
```

### 3. Docker Scout (Native Docker Security)

#### Setup
```bash
# Enable Docker Scout
docker scout cves pqc-migration-audit:latest

# Policy evaluation
docker scout policy pqc-migration-audit:latest

# Recommendations
docker scout recommendations pqc-migration-audit:latest
```

## Security Scanning Workflow

### CI/CD Integration

#### GitHub Actions Workflow
```yaml
# Container security scanning job
container-security:
  runs-on: ubuntu-latest
  steps:
    - name: Build Docker image
      run: docker build -t pqc-audit:${{ github.sha }} .
    
    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: 'pqc-audit:${{ github.sha }}'
        format: 'sarif'
        output: 'trivy-results.sarif'
        
    - name: Upload Trivy scan results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'
```

### Automated Scanning Script

```bash
#!/bin/bash
# Container security scanning automation

IMAGE_NAME="pqc-migration-audit"
IMAGE_TAG=${1:-"latest"}
REPORTS_DIR="security-reports/container"

mkdir -p "$REPORTS_DIR"

echo "🔍 Starting container security scan for $IMAGE_NAME:$IMAGE_TAG"

# 1. Trivy vulnerability scan
echo "📦 Running Trivy vulnerability scan..."
trivy image \
    --format json \
    --output "$REPORTS_DIR/trivy-vulnerabilities.json" \
    "$IMAGE_NAME:$IMAGE_TAG"

# 2. Trivy configuration scan
echo "⚙️ Running Trivy configuration scan..."
trivy config \
    --format json \
    --output "$REPORTS_DIR/trivy-config.json" \
    Dockerfile

# 3. Grype scan
echo "🔎 Running Grype scan..."
grype "$IMAGE_NAME:$IMAGE_TAG" \
    -o json \
    --file "$REPORTS_DIR/grype-results.json"

# 4. Generate summary report
echo "📊 Generating security summary..."
python3 scripts/generate-container-security-report.py \
    --trivy "$REPORTS_DIR/trivy-vulnerabilities.json" \
    --grype "$REPORTS_DIR/grype-results.json" \
    --output "$REPORTS_DIR/security-summary.html"

echo "✅ Container security scan complete!"
```

## Security Hardening Guidelines

### Base Image Security

#### Approved Base Images
- `python:3.11-slim` (Debian-based, minimal)
- `python:3.11-alpine` (Alpine Linux, ultra-minimal)
- `gcr.io/distroless/python3` (Google Distroless)

#### Base Image Verification
```dockerfile
# Pin base image with cryptographic hash
FROM python:3.11-slim@sha256:specific-digest

# Verify image signature (when available)
# Use Docker Content Trust
ENV DOCKER_CONTENT_TRUST=1
```

### Runtime Security

#### Non-Root User
```dockerfile
# Create non-privileged user
RUN groupadd -r pqcaudit && useradd -r -g pqcaudit pqcaudit

# Switch to non-root user
USER pqcaudit
```

#### Read-Only Root Filesystem
```dockerfile
# Enable read-only root filesystem
FROM python:3.11-slim
# ... build steps ...
# Set read-only root filesystem in docker-compose or k8s
```

#### Capability Dropping
```yaml
# docker-compose.yml
security_opt:
  - no-new-privileges:true
cap_drop:
  - ALL
read_only: true
```

### Network Security

#### Minimal Network Exposure
```yaml
# Expose only necessary ports
EXPOSE 8080

# Use internal networks
networks:
  - internal
```

#### Security Policies
```yaml
# Network policies for Kubernetes
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: pqc-audit-policy
spec:
  podSelector:
    matchLabels:
      app: pqc-audit
  policyTypes:
  - Ingress
  - Egress
  ingress: []  # No ingress by default
  egress:
  - to: []    # Restrict egress as needed
```

## Vulnerability Management

### Severity Classification

#### Critical (CVSS 9.0-10.0)
- **Response Time**: Immediate (< 2 hours)
- **Action**: Stop deployment, patch immediately
- **Escalation**: Security team notification

#### High (CVSS 7.0-8.9)
- **Response Time**: 24 hours
- **Action**: Create patch plan, deploy within SLA
- **Escalation**: Development team notification

#### Medium (CVSS 4.0-6.9)
- **Response Time**: 7 days
- **Action**: Schedule patch in next sprint
- **Escalation**: Standard issue tracking

### Patching Strategy

#### Base Image Updates
```bash
# Weekly base image updates
docker pull python:3.11-slim
docker build --no-cache -t pqc-migration-audit:latest .

# Verify no new vulnerabilities
trivy image pqc-migration-audit:latest
```

#### Dependency Updates
```bash
# Update Python dependencies
pip-audit --fix --dry-run
safety check --continue-on-error
```

## Compliance and Standards

### CIS Docker Benchmark

#### Key Controls
- CIS-Docker-1.1.1: Separate partition for containers
- CIS-Docker-1.2.1: Use trusted base images
- CIS-Docker-4.1: Create user for container
- CIS-Docker-4.6: Add HEALTHCHECK instruction

#### Automated Compliance Check
```bash
# Docker Bench Security
docker run --rm --net host --pid host --userns host --cap-add audit_control \
    -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
    -v /etc:/etc:ro \
    -v /usr/bin/containerd:/usr/bin/containerd:ro \
    -v /usr/bin/runc:/usr/bin/runc:ro \
    -v /usr/lib/systemd:/usr/lib/systemd:ro \
    -v /var/lib:/var/lib:ro \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    --label docker_bench_security \
    docker/docker-bench-security
```

### NIST Container Security Guidelines

#### Implementation Checklist
- [ ] Image vulnerability scanning
- [ ] Runtime security monitoring
- [ ] Network segmentation
- [ ] Secrets management
- [ ] Access controls
- [ ] Logging and monitoring
- [ ] Incident response procedures

## Monitoring and Alerting

### Runtime Security Monitoring

#### Container Behavior Analysis
- Process monitoring
- File system changes
- Network connections
- System calls

#### Security Tools Integration
- **Falco**: Runtime security monitoring
- **Sysdig**: Container visibility
- **Aqua Security**: Comprehensive container security

### Alert Configuration

#### Critical Alerts
- Container escape attempts
- Privilege escalation
- Unexpected network connections
- File system modifications

#### Notification Channels
- Slack: `#security-alerts`
- Email: `security@terragonlabs.com`
- PagerDuty: Critical incidents

## Testing and Validation

### Security Testing Pipeline

#### Automated Tests
```python
# Container security tests
def test_container_runs_as_non_root():
    result = docker_client.containers.run(
        "pqc-migration-audit:latest",
        "whoami",
        remove=True
    )
    assert result.decode().strip() != "root"

def test_no_high_vulnerabilities():
    scan_result = trivy_scan("pqc-migration-audit:latest")
    high_vulns = [v for v in scan_result if v.severity == "HIGH"]
    assert len(high_vulns) == 0
```

#### Manual Security Review
- Dockerfile security review
- Runtime configuration validation
- Secrets management verification
- Network policy testing

## Incident Response

### Container Security Incidents

#### Response Procedures
1. **Immediate**: Stop affected containers
2. **Analysis**: Investigate compromise indicators
3. **Containment**: Isolate affected systems
4. **Recovery**: Rebuild from known-good images
5. **Post-Incident**: Update security controls

### Forensics and Investigation

#### Evidence Collection
- Container logs
- System audit logs
- Network traffic captures
- File system snapshots

#### Analysis Tools
- Container forensics tools
- Log analysis platforms
- Network monitoring systems
- Threat intelligence feeds

## References

- [NIST SP 800-190: Container Security Guide](https://csrc.nist.gov/publications/detail/sp/800-190/final)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [OWASP Container Security Top 10](https://owasp.org/www-project-container-security/)
- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)