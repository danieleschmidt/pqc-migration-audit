# Alerting Guide for PQC Migration Audit

## Overview

This guide describes the alerting strategy, escalation procedures, and response protocols for the PQC Migration Audit tool monitoring system.

## Alert Categories and Severity Levels

### Severity Levels

#### Critical (P1)
- **Response Time**: Immediate (< 15 minutes)
- **Escalation**: Automatic PagerDuty, Slack, Email
- **Examples**: Service down, critical vulnerabilities, security breaches
- **SLA Impact**: Customer-facing service disruption

#### High (P2)  
- **Response Time**: 1 hour
- **Escalation**: Slack, Email to team
- **Examples**: High error rates, performance degradation
- **SLA Impact**: Potential customer impact

#### Warning (P3)
- **Response Time**: 4 hours during business hours
- **Escalation**: Email notification
- **Examples**: Resource usage warnings, minor performance issues
- **SLA Impact**: No immediate customer impact

#### Info (P4)
- **Response Time**: Next business day
- **Escalation**: Dashboard notification only
- **Examples**: Deployment notifications, maintenance windows
- **SLA Impact**: No customer impact

### Alert Categories

#### Security Alerts
- **Critical Vulnerabilities**: CVE score >= 9.0
- **Unauthorized Access**: Failed authentication attempts
- **Suspicious Activity**: Anomalous usage patterns
- **Data Breach**: Potential data exposure incidents

#### Application Alerts
- **Service Health**: Application availability and responsiveness
- **Error Rates**: Application error thresholds
- **Performance**: Response time and throughput metrics
- **Dependencies**: External service failures

#### Infrastructure Alerts
- **System Resources**: CPU, memory, disk usage
- **Network**: Connectivity and bandwidth issues
- **Container Health**: Docker container status
- **Database**: Database connectivity and performance

#### Business Metrics
- **Scan Completion**: Success rate monitoring
- **User Experience**: Performance and reliability metrics
- **False Positives**: Detection accuracy monitoring
- **Usage Patterns**: Anomalous usage detection

## Alert Routing and Escalation

### Primary On-Call Rotation

#### Security Team
- **Scope**: All security-related alerts
- **Members**: security@terragonlabs.com
- **Escalation**: CISO after 30 minutes

#### Development Team
- **Scope**: Application and service alerts
- **Members**: dev-team@terragonlabs.com
- **Escalation**: Team lead after 1 hour

#### Infrastructure Team
- **Scope**: System and infrastructure alerts
- **Members**: infra@terragonlabs.com
- **Escalation**: Infrastructure manager after 2 hours

### Escalation Matrix

| Time | P1 (Critical) | P2 (High) | P3 (Warning) | P4 (Info) |
|------|---------------|-----------|--------------|-----------|
| 0 min | Primary on-call | Primary on-call | Email notification | Dashboard only |
| 15 min | Secondary on-call + Manager | Email to team | - | - |
| 30 min | Director + PagerDuty | Secondary on-call | - | - |
| 1 hour | VP Engineering | Team lead | Primary on-call | - |
| 2 hours | CTO/CEO (P1 only) | Manager | - | - |

## Notification Channels

### Slack Integration

#### Security Alerts Channel: `#security-alerts`
```yaml
# High-priority security notifications
webhook_url: "${SLACK_SECURITY_WEBHOOK}"
channel: "#security-alerts"
username: "Security Monitor"
templates:
  critical: |
    🚨 *CRITICAL SECURITY ALERT*
    {{ .CommonAnnotations.summary }}
    Severity: {{ .CommonLabels.severity }}
    Time: {{ .Alerts.0.StartsAt.Format "15:04:05 UTC" }}
```

#### Development Team Channel: `#pqc-audit-alerts`
```yaml
# Application and development alerts
webhook_url: "${SLACK_DEV_WEBHOOK}"
channel: "#pqc-audit-alerts"
username: "PQC Audit Monitor"
```

#### Infrastructure Channel: `#infrastructure-alerts`
```yaml
# System and infrastructure alerts
webhook_url: "${SLACK_INFRA_WEBHOOK}"
channel: "#infrastructure-alerts"
username: "Infrastructure Monitor"
```

### Email Notifications

#### Distribution Lists
- **Critical Security**: security@terragonlabs.com
- **Development Team**: dev-team@terragonlabs.com
- **Infrastructure Team**: infra@terragonlabs.com
- **Management**: leadership@terragonlabs.com

#### Email Templates
```html
<!-- Critical Alert Template -->
Subject: 🚨 CRITICAL: {{ .GroupLabels.alertname }}

CRITICAL ALERT NOTIFICATION

Service: {{ .CommonLabels.service }}
Alert: {{ .CommonAnnotations.summary }}
Description: {{ .CommonAnnotations.description }}
Started: {{ .Alerts.0.StartsAt.Format "2006-01-02 15:04:05 UTC" }}

IMMEDIATE ACTION REQUIRED

Dashboard: https://grafana.terragonlabs.com
Runbook: https://docs.terragonlabs.com/runbooks/{{ .GroupLabels.alertname }}
```

### PagerDuty Integration

#### Service Configuration
```yaml
# PagerDuty routing keys
services:
  security_critical: "${PAGERDUTY_SECURITY_KEY}"
  application_high: "${PAGERDUTY_APP_KEY}"
  infrastructure: "${PAGERDUTY_INFRA_KEY}"

# Escalation policies
escalation_policies:
  security:
    - level: 1
      targets: ["security-oncall"]
      timeout: 15m
    - level: 2  
      targets: ["security-manager", "ciso"]
      timeout: 30m
```

## Alert Response Procedures

### Critical Security Alert Response

#### Immediate Actions (0-15 minutes)
1. **Acknowledge** the alert in PagerDuty/Slack
2. **Assess** the scope and impact
3. **Isolate** affected systems if necessary
4. **Notify** stakeholders via established channels
5. **Begin** incident response procedures

#### Investigation Phase (15-60 minutes)
1. **Gather** logs and forensic evidence
2. **Analyze** attack vectors and compromise indicators
3. **Document** findings in incident tracker
4. **Coordinate** with relevant teams
5. **Implement** containment measures

#### Resolution Phase (1+ hours)
1. **Remediate** identified vulnerabilities
2. **Verify** system integrity
3. **Monitor** for continued threats
4. **Communicate** status updates
5. **Conduct** post-incident review

### Application Alert Response

#### Standard Response Process
1. **Check** application health dashboard
2. **Review** recent deployments and changes
3. **Examine** error logs and metrics
4. **Test** critical functionality
5. **Escalate** if unable to resolve within SLA

#### Common Troubleshooting Steps
```bash
# Check service health
curl -f https://api.pqc-audit.com/health

# Review application logs
docker logs pqc-audit-app --tail=100

# Check resource usage
docker stats pqc-audit-app

# Verify database connectivity
docker exec pqc-audit-app python -c "from core import db; db.test_connection()"
```

### Infrastructure Alert Response

#### System Resource Alerts
1. **Identify** resource bottlenecks
2. **Scale** resources if possible
3. **Investigate** root cause
4. **Implement** short-term fixes
5. **Plan** long-term solutions

#### Container Health Issues
```bash
# Check container status
docker ps -a

# Restart unhealthy containers
docker restart pqc-audit-app

# Check container logs
docker logs pqc-audit-app --since=1h

# Verify resource limits
docker inspect pqc-audit-app | grep -A 5 "Resources"
```

## Alert Tuning and Optimization

### Reducing Alert Fatigue

#### Alert Correlation
- Group related alerts to reduce noise
- Implement dependency-based alert suppression
- Use intelligent alert routing based on business hours

#### Threshold Optimization
```yaml
# Example threshold tuning
alerts:
  high_cpu_usage:
    threshold: 80%  # Reduced from 70% to reduce false positives
    duration: 10m   # Increased from 5m to confirm persistence
    
  memory_usage:
    threshold: 85%  # Adjusted based on historical data
    evaluation_interval: 5m
```

#### Dynamic Thresholds
- Implement time-based thresholds for business hours
- Use seasonal adjustments for expected load patterns
- Configure maintenance window suppressions

### Alert Quality Metrics

#### Measurement Criteria
- **Precision**: True positives / (True positives + False positives)
- **Recall**: True positives / (True positives + False negatives)
- **Mean Time to Acknowledge (MTTA)**: Average alert acknowledgment time
- **Mean Time to Resolution (MTTR)**: Average resolution time

#### Target SLAs
- Alert precision: > 85%
- Alert recall: > 95%
- MTTA (Critical): < 5 minutes
- MTTR (Critical): < 2 hours

## Runbook Integration

### Alert-Specific Runbooks

#### Format Template
```markdown
# Alert: [AlertName]

## Description
Brief description of what this alert indicates.

## Impact
Potential impact on users and business operations.

## Investigation Steps
1. Step-by-step troubleshooting guide
2. Commands to run and logs to check
3. Common causes and solutions

## Resolution Steps
1. Immediate actions to take
2. Long-term fixes to implement
3. Prevention measures

## Escalation
When and how to escalate this alert.
```

#### Runbook Examples
- **PQCAuditServiceDown**: Service restart procedures
- **CriticalVulnerabilityDetected**: Security response protocol
- **HighMemoryUsage**: Resource scaling procedures
- **SlowScanPerformance**: Performance optimization steps

## Testing and Validation

### Alert Testing Schedule

#### Monthly Tests
- Test all critical alert paths
- Verify notification delivery
- Validate escalation procedures
- Review alert thresholds

#### Quarterly Reviews
- Analyze alert quality metrics
- Review and update runbooks
- Conduct post-incident reviews
- Update escalation contacts

### Synthetic Alert Testing
```bash
# Generate test alerts for validation
curl -X POST http://alertmanager:9093/api/v1/alerts \
  -H "Content-Type: application/json" \
  -d '[{
    "labels": {
      "alertname": "TestAlert",
      "severity": "warning",
      "service": "pqc-audit"
    },
    "annotations": {
      "summary": "Test alert for validation"
    }
  }]'
```

## Continuous Improvement

### Alert Review Process
1. **Weekly**: Review alert frequency and false positive rates
2. **Monthly**: Analyze response times and resolution effectiveness
3. **Quarterly**: Comprehensive alert tuning and optimization
4. **Annually**: Full alerting strategy review and updates

### Feedback Mechanisms
- Post-incident reviews for alert effectiveness
- Regular team feedback on alert quality
- Stakeholder input on notification preferences
- Automated alert quality scoring

## Contact Information

### Emergency Contacts
- **Security Incidents**: security@terragonlabs.com, +1-555-SECURITY
- **Technical Issues**: dev-team@terragonlabs.com, +1-555-DEV-TEAM
- **Business Critical**: leadership@terragonlabs.com, +1-555-CRITICAL

### Escalation Contacts
- **CISO**: ciso@terragonlabs.com
- **VP Engineering**: vp-eng@terragonlabs.com
- **CTO**: cto@terragonlabs.com

## References

- [Prometheus Alerting Rules](https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/)
- [Alertmanager Configuration](https://prometheus.io/docs/alerting/latest/configuration/)
- [PagerDuty Integration Guide](https://www.pagerduty.com/docs/guides/prometheus-integration-guide/)
- [Slack Webhook Documentation](https://api.slack.com/messaging/webhooks)