# Observability Best Practices

## Overview

This document outlines observability best practices for the PQC Migration Audit system, covering metrics, logging, tracing, and alerting strategies.

## Metrics Strategy

### The Four Golden Signals
1. **Latency**: How long it takes to service a request
2. **Traffic**: How much demand is being placed on your system
3. **Errors**: The rate of requests that fail
4. **Saturation**: How "full" your service is

### PQC-Specific Metrics

#### Scanning Performance
```
# Scan execution metrics
pqc_scan_duration_histogram{scan_type, repository_size}
pqc_scan_throughput_files_per_second
pqc_scan_error_rate{error_type}
pqc_scan_queue_length

# Vulnerability detection metrics
pqc_vulnerabilities_detected_total{algorithm, severity, language}
pqc_false_positive_rate{algorithm, detection_method}
pqc_coverage_percentage{language, framework}
```

#### Migration Progress
```
# Migration tracking
pqc_migration_completion_percentage{component, target_algorithm}
pqc_compatibility_test_success_rate{migration_type}
pqc_rollback_incidents_total{reason}
pqc_hybrid_mode_usage{classical_algorithm, pqc_algorithm}
```

#### Security Posture
```
# Security metrics
pqc_security_score{repository, assessment_type}
pqc_quantum_readiness_percentage
pqc_compliance_violations{standard, severity}
pqc_risk_assessment_score{category}
```

## Logging Strategy

### Structured Logging Standards

#### Log Levels and Usage
- **DEBUG**: Detailed internal state, algorithm parameters
- **INFO**: Successful operations, scan completions
- **WARN**: Deprecated algorithms, compatibility issues
- **ERROR**: Scan failures, parsing errors
- **CRITICAL**: Security violations, system compromises

#### Required Fields
```json
{
  "timestamp": "RFC3339 format",
  "level": "DEBUG|INFO|WARN|ERROR|CRITICAL",
  "service": "pqc-audit",
  "component": "scanner|analyzer|reporter|api",
  "message": "Human readable message",
  "context": {
    "scan_id": "unique identifier",
    "file_path": "relative path",
    "algorithm": "detected algorithm",
    "severity": "vulnerability severity"
  },
  "trace_id": "distributed tracing ID",
  "span_id": "span identifier"
}
```

#### Security-Sensitive Logging Rules
✅ **LOG**:
- Algorithm types and parameters
- Key sizes and strengths
- File paths and line numbers
- Vulnerability classifications
- Performance metrics
- Error conditions

❌ **NEVER LOG**:
- Private keys or key material
- User credentials
- Authentication tokens
- Personal data
- Production secrets

### Log Aggregation

#### ELK Stack Configuration
```yaml
# logstash pipeline
input {
  beats {
    port => 5044
  }
}

filter {
  if [service] == "pqc-audit" {
    grok {
      match => { "message" => "%{GREEDYDATA:log_message}" }
    }
    
    # Parse JSON logs
    json {
      source => "message"
    }
    
    # Add security context
    if [component] == "scanner" and [context][severity] == "critical" {
      mutate {
        add_tag => [ "security_critical" ]
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "pqc-audit-%{+YYYY.MM.dd}"
  }
}
```

## Distributed Tracing

### OpenTelemetry Configuration

#### Trace Context
```python
from opentelemetry import trace
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

# Configure tracer
trace.set_tracer_provider(TracerProvider())
tracer = trace.get_tracer(__name__)

jaeger_exporter = JaegerExporter(
    agent_host_name="jaeger",
    agent_port=6831,
)

span_processor = BatchSpanProcessor(jaeger_exporter)
trace.get_tracer_provider().add_span_processor(span_processor)

# Instrumentation example
@tracer.start_as_current_span("crypto_scan")
def scan_file(file_path):
    span = trace.get_current_span()
    span.set_attribute("file.path", file_path)
    span.set_attribute("scan.type", "crypto_detection")
    
    try:
        result = perform_scan(file_path)
        span.set_attribute("vulnerabilities.found", len(result.vulnerabilities))
        span.set_status(trace.Status(trace.StatusCode.OK))
        return result
    except Exception as e:
        span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
        span.record_exception(e)
        raise
```

#### Key Spans to Trace
- File scanning operations
- Vulnerability analysis
- Report generation
- API requests
- Database operations
- External service calls

## Alerting Strategy

### Alert Hierarchy

#### P0 - Critical (Immediate Response)
- Service completely down
- Critical security vulnerabilities in production
- Data corruption or loss
- Security breach indicators

#### P1 - High (Response within 30 minutes)
- High error rates (>5%)
- Performance degradation (>5s response time)
- High memory/CPU usage (>90%)
- Failed security scans

#### P2 - Medium (Response within 4 hours)
- Moderate error rates (1-5%)
- Performance issues (2-5s response time)
- Medium memory/CPU usage (70-90%)
- Deprecated algorithm usage

#### P3 - Low (Response within 24 hours)
- Low error rates (<1%)
- Minor performance degradation
- Information gathering alerts
- Compliance notifications

### Alert Configuration

#### Prometheus Alerting Rules
```yaml
groups:
- name: pqc-audit-alerts
  rules:
  # Critical alerts
  - alert: PQCServiceDown
    expr: up{job="pqc-audit-app"} == 0
    for: 5m
    labels:
      severity: critical
      priority: P0
    annotations:
      summary: "PQC Audit service is down"
      description: "PQC Audit service has been down for more than 5 minutes"
      
  - alert: CriticalVulnerabilityFound
    expr: increase(pqc_vulnerabilities_found{severity="critical"}[5m]) > 0
    labels:
      severity: critical
      priority: P0
    annotations:
      summary: "Critical cryptographic vulnerability detected"
      description: "A critical vulnerability has been found: {{ $labels.algorithm }}"

  # High priority alerts  
  - alert: HighErrorRate
    expr: rate(pqc_scan_errors_total[5m]) > 0.05
    for: 10m
    labels:
      severity: warning
      priority: P1
    annotations:
      summary: "High error rate in PQC scans"
      description: "Error rate is {{ $value | humanizePercentage }}"
      
  - alert: HighMemoryUsage
    expr: process_resident_memory_bytes{job="pqc-audit-app"} / 1024 / 1024 / 1024 > 2
    for: 15m
    labels:
      severity: warning
      priority: P1
    annotations:
      summary: "High memory usage"
      description: "Memory usage is {{ $value }}GB"
```

#### Alertmanager Configuration
```yaml
global:
  smtp_smarthost: 'localhost:587'
  smtp_from: 'alerts@company.com'

route:
  group_by: ['alertname', 'severity']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'default'
  routes:
  - match:
      priority: P0
    receiver: 'critical-alerts'
    group_wait: 0s
    repeat_interval: 15m
  - match:
      priority: P1
    receiver: 'high-priority-alerts'
    repeat_interval: 30m

receivers:
- name: 'default'
  email_configs:
  - to: 'team@company.com'
    subject: 'PQC Audit Alert: {{ .GroupLabels.alertname }}'
    
- name: 'critical-alerts'
  email_configs:
  - to: 'oncall@company.com'
    subject: '[CRITICAL] PQC Audit: {{ .GroupLabels.alertname }}'
  pagerduty_configs:
  - routing_key: 'YOUR_PAGERDUTY_KEY'
    description: '{{ .GroupLabels.alertname }}: {{ .CommonAnnotations.summary }}'
    
- name: 'high-priority-alerts'
  slack_configs:
  - api_url: 'YOUR_SLACK_WEBHOOK'
    channel: '#security-alerts'
    title: 'PQC Audit Alert'
    text: '{{ .CommonAnnotations.summary }}'
```

## Dashboard Strategy

### Key Dashboards

#### Executive Dashboard
- Overall security posture score
- Migration progress percentage
- Risk trend analysis
- Compliance status

#### Operations Dashboard  
- Service health and uptime
- Scan performance metrics
- Error rates and trends
- Resource utilization

#### Security Dashboard
- Vulnerability detection trends
- Algorithm usage breakdown
- Compliance violations
- Risk assessment results

#### Development Dashboard
- Build and deployment metrics
- Test coverage and quality
- Performance benchmarks
- Technical debt metrics

### Grafana Dashboard Examples

#### Service Overview
```json
{
  "dashboard": {
    "title": "PQC Audit Service Overview",
    "panels": [
      {
        "title": "Service Status",
        "type": "stat",
        "targets": [
          {
            "expr": "up{job=\"pqc-audit-app\"}",
            "legendFormat": "Service Up"
          }
        ]
      },
      {
        "title": "Scan Performance",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(pqc_scans_total[5m])",
            "legendFormat": "Scans per second"
          }
        ]
      }
    ]
  }
}
```

## Performance Monitoring

### SLI/SLO Framework

#### Service Level Indicators (SLIs)
- **Availability**: Percentage of successful health checks
- **Latency**: P99 response time for scan operations
- **Throughput**: Files scanned per minute
- **Quality**: Percentage of scans without false positives

#### Service Level Objectives (SLOs)
- **Availability**: 99.9% uptime
- **Latency**: P99 < 30 seconds for file scans
- **Throughput**: Process 1000+ files per minute
- **Quality**: <1% false positive rate

#### Error Budget
- Monthly error budget: 0.1% (43.8 minutes downtime)
- Burn rate alerting at 2x, 6x, and 14x rates
- Automatic deployment freezes when budget depleted

## Compliance and Audit

### Audit Trail Requirements
- All security-relevant events logged
- Immutable log storage for compliance
- Log retention for regulatory periods
- Access controls on monitoring data

### Privacy Considerations
- GDPR compliance for EU users
- Data minimization in logs
- Right to deletion procedures
- Consent management for telemetry

### Regulatory Compliance
- SOC 2 Type II controls
- ISO 27001 monitoring requirements
- NIST Cybersecurity Framework alignment
- Industry-specific compliance (HIPAA, PCI DSS)