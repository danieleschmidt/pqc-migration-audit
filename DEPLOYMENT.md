# PQC Migration Audit - Production Deployment Guide

## Overview

This guide covers production deployment of the PQC Migration Audit tool, including installation, configuration, monitoring, and maintenance procedures.

## Prerequisites

### System Requirements
- Python 3.8 or higher
- Minimum 2GB RAM (4GB recommended for large repositories)
- 1GB disk space for installation and logs
- Network access for dependency installation

### Dependencies
- Core dependencies are listed in `requirements.txt`
- No external services required (self-contained tool)

## Installation

### Production Installation
```bash
# Clone repository
git clone <repository-url>
cd pqc-migration-audit

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install package in production mode
pip install -e .

# Verify installation
pqc-audit --version
```

### Docker Deployment
```bash
# Build Docker image
docker build -t pqc-migration-audit:latest .

# Run container
docker run -v /path/to/scan:/app/scan pqc-migration-audit:latest scan /app/scan
```

## Configuration

### Environment Variables
```bash
# Optional: Configure output directory
export PQC_OUTPUT_DIR=/var/log/pqc-audit

# Optional: Set log level
export PQC_LOG_LEVEL=INFO

# Optional: Configure parallel processing
export PQC_MAX_WORKERS=4

# Optional: Enable performance monitoring
export PQC_ENABLE_METRICS=true
```

### Configuration File
Create `/etc/pqc-audit/config.yaml`:
```yaml
# Global configuration
scan:
  exclude_patterns:
    - "*.pyc"
    - "__pycache__"
    - ".git"
    - "node_modules"
  
  # Performance settings
  parallel_processing: true
  max_workers: 4
  cache_enabled: true
  
# Output configuration
output:
  format: "json"
  include_patches: true
  include_dashboard: true
  
# Security settings
security:
  max_file_size_mb: 10
  scan_timeout_seconds: 300
```

## Quality Gates

### Security Scanning
```bash
# Run security quality gate
python3 security_scan.py

# Required: Score ≥ 85/100
# Monitors: hardcoded secrets, weak crypto, injection vulnerabilities
```

### Performance Benchmarking
```bash
# Run performance quality gate
python3 performance_benchmark.py

# Required: Score ≥ 75/100
# Benchmarks: scan speed, memory usage, parallel processing
```

### Test Coverage
```bash
# Run all tests with coverage
python3 -m pytest --cov=src/pqc_migration_audit --cov-report=html

# Required: Coverage ≥ 85%
```

## Monitoring

### Health Checks
```bash
# Basic health check
pqc-audit --health-check

# Detailed system check
python3 -c "from src.pqc_migration_audit.core import CryptoAuditor; print('✅ System healthy')"
```

### Logging
- Application logs: `/var/log/pqc-audit/app.log`
- Security logs: `/var/log/pqc-audit/security.log`
- Performance logs: `/var/log/pqc-audit/performance.log`

### Metrics Collection
```bash
# Generate performance report
python3 performance_benchmark.py

# Generate security report
python3 security_scan.py

# View reports
cat performance_report.json
cat security_report.json
```

## Maintenance

### Regular Tasks
1. **Weekly**: Run quality gates to ensure continued compliance
2. **Monthly**: Review and update crypto pattern definitions
3. **Quarterly**: Update dependencies and security definitions

### Updates
```bash
# Update dependencies
pip install -U -r requirements.txt

# Run quality gates after updates
python3 security_scan.py
python3 performance_benchmark.py
```

### Backup and Recovery
```bash
# Backup configuration
cp -r /etc/pqc-audit /backup/pqc-audit-$(date +%Y%m%d)

# Backup scan results
cp -r /var/log/pqc-audit /backup/pqc-logs-$(date +%Y%m%d)
```

## Troubleshooting

### Common Issues

#### High Memory Usage
- Reduce `max_workers` in configuration
- Enable streaming processing for large files
- Increase system memory or use smaller batches

#### Slow Performance
- Enable parallel processing
- Check disk I/O for bottlenecks
- Optimize exclude patterns to skip unnecessary files

#### False Positives
- Review and update pattern definitions in `core.py`
- Configure exclude patterns for test/documentation files
- Validate results with security team

### Debug Mode
```bash
# Enable debug logging
export PQC_LOG_LEVEL=DEBUG
pqc-audit scan /path/to/code --debug
```

### Support
- Check logs in `/var/log/pqc-audit/`
- Run health checks and quality gates
- Review configuration files
- Contact development team with error reports

## Security Considerations

### Access Control
- Restrict access to configuration files
- Secure log files with appropriate permissions
- Use service accounts for automated scanning

### Data Handling
- Scan results may contain sensitive code patterns
- Ensure secure storage and transmission of reports
- Follow data retention policies for scan results

### Network Security
- Tool operates offline by default
- No external network calls required
- Secure any CI/CD integrations appropriately

## Performance Optimization

### Large Repositories
- Use exclude patterns to skip unnecessary files
- Enable parallel processing with appropriate worker count
- Consider scanning in smaller batches for massive codebases

### CI/CD Integration
- Cache scan results between builds when possible
- Use incremental scanning for changed files only
- Set appropriate timeouts for CI/CD pipelines

### Resource Limits
```bash
# Set memory limits
ulimit -m 2097152  # 2GB memory limit

# Set CPU limits
taskset -c 0-3 pqc-audit scan /path/to/code  # Use specific CPU cores
```

## Production Checklist

### Pre-deployment
- [ ] All tests pass with ≥85% coverage
- [ ] Security scan passes with score ≥85/100
- [ ] Performance benchmark passes with score ≥75/100
- [ ] Configuration files reviewed and secured
- [ ] Monitoring and logging configured

### Post-deployment
- [ ] Health checks passing
- [ ] Performance within acceptable ranges
- [ ] Security monitoring active
- [ ] Backup procedures verified
- [ ] Documentation updated

### Ongoing Operations
- [ ] Regular quality gate execution
- [ ] Dependency updates scheduled
- [ ] Security pattern updates scheduled
- [ ] Performance monitoring active
- [ ] Incident response procedures documented