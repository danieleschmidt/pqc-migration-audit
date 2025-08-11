# PQC Migration Audit - Production Deployment Guide

## 🚀 Quick Start Production Deployment

### Prerequisites
- Python 3.8+ 
- 4GB+ RAM recommended
- Network access for threat intelligence (optional)
- SIEM/SOAR endpoints configured (optional)

### Installation

```bash
# Clone repository
git clone https://github.com/terragonlabs/pqc-migration-audit.git
cd pqc-migration-audit

# Install core dependencies
pip install -r requirements-production.txt

# Install package
pip install -e .

# Verify installation
pqc-audit --version
```

### Basic Usage

```bash
# Scan current directory
pqc-audit scan .

# Comprehensive analysis with compliance
pqc-audit analyze . --include-patches --include-dashboard

# Generate executive report
pqc-audit scan . --format html --output pqc-report.html
```

## 🏗️ Enterprise Deployment

### Architecture Components

1. **Core Scanning Engine** - Multi-language crypto vulnerability detection
2. **Research Module** - Algorithm benchmarking and comparative analysis
3. **Threat Intelligence** - OSINT collection and quantum threat monitoring
4. **Enterprise Integration** - SIEM/SOAR connectivity with CEF/LEEF/JSON formats
5. **Compliance Engine** - Multi-framework assessment (NIST CSF, ISO 27001, PCI DSS)
6. **Autonomous Orchestrator** - Self-managing operations with ML optimization

### Configuration

#### SIEM Integration

```python
from pqc_migration_audit.enterprise_integration import IntegrationConfig, IntegrationType

siem_config = IntegrationConfig(
    integration_type=IntegrationType.SIEM,
    endpoint_url="https://your-siem.company.com/api",
    authentication={
        "type": "bearer",
        "token": "your-api-token"
    },
    custom_fields={
        "event_format": "CEF",  # or LEEF, JSON
        "events_endpoint": "/api/events"
    }
)
```

#### Compliance Frameworks

```python
from pqc_migration_audit.compliance_engine import ComplianceEngine, ComplianceFramework

compliance = ComplianceEngine()
report = compliance.assess_compliance(
    scan_results,
    frameworks=[
        ComplianceFramework.NIST_CSF,
        ComplianceFramework.ISO_27001,
        ComplianceFramework.PCI_DSS
    ],
    organization_context={
        "handles_payment_cards": True,
        "industry": "financial_services"
    }
)
```

### Autonomous Operations

```python
from pqc_migration_audit.autonomous_orchestrator import AutonomousOrchestrator, OperationMode

# Initialize autonomous system
autonomous = AutonomousOrchestrator([
    OperationMode.CONTINUOUS_MONITORING,
    OperationMode.THREAT_RESPONSIVE,
    OperationMode.COMPLIANCE_FOCUSED
])

# Set autonomy level
autonomous.set_autonomous_level('semi_autonomous')

# Start autonomous operations
await autonomous.start_autonomous_operations()
```

## 📊 Monitoring and Metrics

### Health Monitoring

```python
# Check system health
health = await resource_manager.monitor_and_optimize()
print(f"CPU: {health.cpu_utilization}%, Memory: {health.memory_utilization}%")
print(f"Scan throughput: {health.scan_throughput} files/sec")

# Integration health
integration_health = await enterprise.health_check()
print(f"Overall status: {integration_health['overall_status']}")
```

### Performance Metrics

- **Scanning Performance**: Files per second, vulnerability detection rate
- **Resource Utilization**: CPU, memory, network usage
- **Integration Health**: SIEM/SOAR connectivity status
- **Compliance Posture**: Framework-specific compliance scores
- **Threat Intelligence**: OSINT collection rates, threat level assessment

## 🔧 Advanced Configuration

### Research Engine

```python
from pqc_migration_audit.research_engine import ResearchOrchestrator, ResearchMode

# Comparative algorithm analysis
research = ResearchOrchestrator(ResearchMode.COMPARATIVE_ANALYSIS)
result = research.conduct_comparative_study({
    "lattice_based": ["kyber_512", "kyber_768", "kyber_1024"],
    "hash_based": ["sphincs_128f", "sphincs_192f"],
    "code_based": ["classic_mceliece_348864"]
})

# Generate research publication
publication = research.generate_research_publication([result.experiment_id])
```

### Threat Intelligence

```python
from pqc_migration_audit.quantum_threat_intelligence import ThreatIntelligenceEngine

ti_engine = ThreatIntelligenceEngine()
analysis = ti_engine.perform_comprehensive_analysis()

print(f"Threat level: {analysis['threat_landscape']['overall_threat_level']}")
print(f"Strategic recommendations: {len(analysis['strategic_recommendations'])}")
```

## 🔒 Security Configuration

### Authentication

- **API Keys**: Secure storage for SIEM/SOAR authentication
- **TLS/SSL**: All external communications encrypted
- **Certificate Management**: Automated cert rotation support
- **Access Control**: Role-based access to sensitive functions

### Data Protection

- **Scan Data**: Local processing, no external data transmission by default
- **Threat Intelligence**: Configurable OSINT sources
- **Logging**: Structured logging with configurable retention
- **Compliance Data**: Encrypted storage for sensitive compliance information

## 📈 Scaling Guidelines

### Horizontal Scaling

- **Worker Processes**: Auto-scaling based on workload
- **Resource Pools**: Dynamic memory and CPU allocation
- **Load Balancing**: Intelligent work distribution
- **Caching**: Predictive caching for improved performance

### Vertical Scaling

| System Size | CPU Cores | RAM | Storage | Concurrent Scans |
|-------------|-----------|-----|---------|------------------|
| Small       | 2-4       | 4GB | 50GB    | 5-10            |
| Medium      | 4-8       | 8GB | 100GB   | 10-25           |
| Large       | 8-16      | 16GB| 200GB   | 25-50           |
| Enterprise  | 16+       | 32GB| 500GB+  | 50+             |

## 🚨 Alerting and Notifications

### SIEM Integration Alerts

- **Critical Vulnerabilities**: Immediate SIEM alerts for quantum-vulnerable crypto
- **Compliance Violations**: Real-time compliance posture changes
- **Threat Intelligence**: High-confidence quantum threat indicators
- **System Health**: Resource constraints and performance degradation

### SOAR Playbook Triggers

- **Emergency Response**: Automated incident creation for critical findings
- **Compliance Remediation**: Workflow initiation for compliance gaps
- **Threat Response**: Adaptive response based on threat intelligence
- **Performance Optimization**: Automated tuning triggers

## 🔄 Maintenance and Updates

### Regular Operations

- **Daily**: Threat intelligence updates, compliance monitoring
- **Weekly**: Performance optimization, health checks
- **Monthly**: Research evaluation, model retraining
- **Quarterly**: Comprehensive compliance assessment

### Update Procedures

```bash
# Update threat intelligence models
pqc-audit update-intelligence --source all

# Refresh compliance frameworks
pqc-audit update-compliance --frameworks nist_csf,iso_27001

# Optimize performance models
pqc-audit optimize --auto-tune
```

## 📋 Troubleshooting

### Common Issues

1. **Import Errors**: Install missing dependencies with `pip install -r requirements-production.txt`
2. **SIEM Connection**: Verify endpoint URL, authentication, and network connectivity
3. **Performance Issues**: Check resource allocation and enable autonomous optimization
4. **Compliance Errors**: Validate organization context and framework configuration

### Debug Mode

```bash
# Enable debug logging
pqc-audit --debug scan /path/to/code

# Verbose output with performance metrics
pqc-audit --verbose analyze /path/to/code

# Health check
pqc-audit health-check --comprehensive
```

### Log Analysis

```bash
# View recent logs
tail -f /var/log/pqc-audit.log

# Filter for errors
grep "ERROR" /var/log/pqc-audit.log | tail -20

# Performance metrics
grep "PERFORMANCE" /var/log/pqc-audit.log
```

## 📞 Support

- **Documentation**: [https://docs.terragonlabs.com/pqc-migration-audit](https://docs.terragonlabs.com)
- **Issues**: [GitHub Issues](https://github.com/terragonlabs/pqc-migration-audit/issues)
- **Enterprise Support**: enterprise@terragonlabs.com
- **Security Issues**: security@terragonlabs.com

---

**⚠️ Security Notice**: This tool identifies cryptographic vulnerabilities. Always review generated recommendations and test thoroughly before applying changes to production systems.

**📜 License**: MIT License - See [LICENSE](LICENSE) for details.

🔐 **Post-Quantum Ready** | 🏢 **Enterprise Grade** | 🤖 **AI-Powered** | 🛡️ **Security Focused**
