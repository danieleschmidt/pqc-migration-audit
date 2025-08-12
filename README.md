# pqc-migration-audit

> CLI + GitHub Action that scans repos for RSA/ECC usages and suggests post-quantum-secure Kyber/Dilithium patches

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![NIST PQC](https://img.shields.io/badge/NIST-PQC-blue.svg)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-Ready-green.svg)](https://github.com/features/actions)
[![SDLC](https://img.shields.io/badge/SDLC-Enterprise%20Ready-green.svg)](#-enterprise-sdlc)
[![Security](https://img.shields.io/badge/Security-Audited-green.svg)](#-security)
[![Documentation](https://img.shields.io/badge/Docs-Complete-green.svg)](docs/)
[![Terragon](https://img.shields.io/badge/Powered%20by-Terragon%20Labs-blue.svg)](https://terragonlabs.com)

## 🔐 Overview

**pqc-migration-audit** helps organizations prepare for the quantum computing era by automatically identifying and migrating classical cryptographic implementations to post-quantum secure alternatives. With enterprises facing a 2027 deadline for crypto-agility and Capgemini's July 2025 report flagging massive readiness gaps, this tool provides automated scanning, risk assessment, and migration assistance.

## ⚡ Key Features

- **Comprehensive Scanning**: Detects RSA, ECC, and other quantum-vulnerable cryptography
- **Automated Patches**: Generates Kyber/Dilithium migration code
- **Risk Heat Maps**: Visual representation of cryptographic vulnerabilities
- **SBOM Integration**: Tracks crypto dependencies in Software Bill of Materials
- **Kubernetes Ready**: Terraform modules for TLS cert rotation

### 🔬 Research-Grade Capabilities (Generation 3)
- **Statistical Validation**: Comprehensive algorithm benchmarking with significance testing
- **Auto-Scaling Research**: Intelligent workload prediction and resource management  
- **Error Recovery**: Advanced resilience with circuit breakers and adaptive strategies
- **Data Integrity**: Multi-level validation framework with confidence scoring
- **Performance Optimization**: Concurrent processing, memory management, and caching

## 🎯 Threat Timeline

| Year | Quantum Threat Level | Action Required |
|------|---------------------|-----------------|
| 2025 | Low | Inventory classical crypto |
| 2027 | Medium | Begin migration |
| 2030 | High | Complete critical systems |
| 2035 | Critical | Full PQC deployment |

## 🚀 Quick Start

### Installation

```bash
# Install CLI tool
pip install pqc-migration-audit

# Or install from source
git clone https://github.com/yourusername/pqc-migration-audit.git
cd pqc-migration-audit
pip install -e .

# Verify installation
pqc-audit --version
```

### Basic Repository Scan

```bash
# Scan current directory
pqc-audit scan .

# Scan with detailed report
pqc-audit scan . --output report.html --format html

# Scan specific languages
pqc-audit scan . --languages python,java,go

# Generate patches
pqc-audit scan . --generate-patches --output patches/
```

### Python API Usage

```python
from pqc_migration_audit.research_engine import AlgorithmBenchmark, ResearchOrchestrator
from pqc_migration_audit.auto_scaling import global_auto_scaler
from pqc_migration_audit.validation_framework import validated_operation

# Initialize research-grade benchmarking
benchmarker = AlgorithmBenchmark()
orchestrator = ResearchOrchestrator()

# Start auto-scaling for optimal performance
global_auto_scaler.start_monitoring()

# Run validated algorithm benchmark
@validated_operation("benchmark", ValidationLevel.RESEARCH_GRADE)
def run_benchmark():
    return benchmarker.benchmark_algorithm(
        algorithm_name="kyber_768",
        test_data_size=10000,
        runs=5
    )

# Execute with error recovery and validation
result = run_benchmark()

print(f"Algorithm: {result['algorithm']}")
print(f"Performance: {result['mean_ops_per_sec']:.0f} ops/sec")
print(f"Statistical significance: {result['statistical_significance']['significant']}")
print(f"Validation score: {result['_validation_report']['data_integrity_score']:.3f}")

# Generate comparative analysis
comparison = orchestrator.conduct_comparative_study(
    algorithms=['kyber_512', 'kyber_768', 'dilithium2'],
    test_scenarios=['performance', 'security', 'compatibility']
)

print(f"Best algorithm: {comparison['rankings'][0]['algorithm']}")
```

## 🔍 Detection Examples

### RSA Detection

```python
# Before (Vulnerable)
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# After (PQC-Secure)
from pqc_migration.crypto import ML_KEM_768  # Kyber

private_key, public_key = ML_KEM_768.generate_keypair()
```

### ECC Detection

```python
# Before (Vulnerable)
from cryptography.hazmat.primitives.asymmetric import ec

private_key = ec.generate_private_key(ec.SECP256R1())

# After (PQC-Secure)
from pqc_migration.crypto import ML_DSA_65  # Dilithium

signing_key, verification_key = ML_DSA_65.generate_keypair()
```

## 🛠️ GitHub Actions Integration

### Automated Scanning

```yaml
# .github/workflows/pqc-audit.yml
name: Post-Quantum Cryptography Audit

on:
  push:
    branches: [main, develop]
  pull_request:
  schedule:
    - cron: '0 0 * * 0'  # Weekly scan

jobs:
  pqc-audit:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: PQC Migration Audit
      uses: pqc-migration/audit-action@v1
      with:
        scan-path: .
        severity-threshold: medium
        
    - name: Upload Risk Report
      uses: actions/upload-artifact@v3
      with:
        name: pqc-risk-report
        path: pqc-audit-report.html
    
    - name: Comment PR
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v6
      with:
        script: |
          const fs = require('fs');
          const report = JSON.parse(fs.readFileSync('pqc-summary.json'));
          
          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: `## 🔐 PQC Audit Results
            
            **Quantum-Vulnerable Crypto Found**: ${report.total_vulnerabilities}
            - 🔴 Critical: ${report.critical}
            - 🟡 High: ${report.high}
            - 🟢 Medium: ${report.medium}
            
            **Migration Effort**: ${report.estimated_hours} hours
            
            [View Full Report](${report.artifact_url})`
          });
```

### Migration Tracking

```yaml
# .github/workflows/pqc-migration-progress.yml
name: Track PQC Migration Progress

on:
  schedule:
    - cron: '0 0 1 * *'  # Monthly

jobs:
  track-progress:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Calculate Migration Progress
      run: |
        pqc-audit progress \
          --baseline .pqc-baseline.json \
          --output progress-report.json
    
    - name: Update Dashboard
      run: |
        pqc-audit dashboard \
          --data progress-report.json \
          --output public/pqc-dashboard.html
    
    - name: Deploy Dashboard
      uses: peaceiris/actions-gh-pages@v3
      with:
        github_token: ${{ secrets.GITHUB_TOKEN }}
        publish_dir: ./public
```

## 📊 Risk Assessment

### Heat Map Generation

```python
from pqc_migration.visualization import RiskHeatMap

# Create risk heat map
heatmap = RiskHeatMap()

# Add vulnerability data
for vuln in results.vulnerabilities:
    heatmap.add_vulnerability(
        file=vuln.file_path,
        line=vuln.line_number,
        severity=vuln.severity,
        algorithm=vuln.algorithm,
        key_size=vuln.key_size
    )

# Generate interactive visualization
heatmap.save_interactive("risk_heatmap.html")

# Generate static image
heatmap.save_static("risk_heatmap.png", width=1200, height=800)
```

### SBOM Integration

```python
from pqc_migration.sbom import CryptoSBOM

# Generate crypto-focused SBOM
sbom = CryptoSBOM()

# Scan dependencies
sbom.scan_dependencies("requirements.txt", "package.json", "go.mod")

# Add manual entries
sbom.add_crypto_component({
    "name": "internal-auth-service",
    "version": "2.1.0",
    "algorithms": ["RSA-2048", "ECDSA-P256"],
    "pqc_ready": False,
    "migration_priority": "high"
})

# Export SBOM with crypto details
sbom.export("crypto-sbom.json", format="cyclonedx")

# Generate diff from previous scan
diff = sbom.compare_with("crypto-sbom-previous.json")
print(f"New vulnerable components: {len(diff.new_vulnerabilities)}")
```

## 🏗️ Migration Strategies

### Hybrid Approach

```python
from pqc_migration.strategies import HybridMigration

# Implement hybrid classical + PQC
hybrid = HybridMigration()

# Configure hybrid mode
config = {
    "classical": "RSA-2048",
    "pqc": "ML-KEM-768",
    "combiner": "concatenate",  # or "xor", "nested"
    "transition_period": "2025-2027"
}

# Generate hybrid implementation
hybrid_code = hybrid.generate_implementation(
    language="python",
    framework="cryptography",
    config=config
)

# Test hybrid compatibility
test_results = hybrid.test_compatibility(
    clients=["legacy_client_v1", "modern_client_v2"],
    servers=["server_2024", "server_2025"]
)
```

### Crypto Agility Framework

```python
from pqc_migration.agility import CryptoAgilityFramework

# Build crypto-agile system
framework = CryptoAgilityFramework()

# Define algorithm registry
framework.register_algorithm("classical", "RSA", implementation="openssl")
framework.register_algorithm("pqc", "ML-KEM", implementation="liboqs")
framework.register_algorithm("pqc", "ML-DSA", implementation="liboqs")

# Generate abstraction layer
abstraction = framework.generate_abstraction_layer(
    languages=["python", "java", "go"],
    features=["key_exchange", "signatures", "encryption"]
)

# Create migration middleware
middleware = framework.create_migration_middleware(
    negotiate_algorithms=True,
    fallback_chain=["ML-KEM-768", "RSA-2048"],
    log_negotiations=True
)
```

## 🔧 Kubernetes Integration

### Terraform Modules

```hcl
# terraform/modules/pqc-cert-manager/main.tf
module "pqc_cert_rotation" {
  source = "pqc-migration/cert-manager/kubernetes"
  
  namespaces = ["production", "staging"]
  
  certificate_config = {
    algorithm = "ML-DSA-65"
    key_size  = 3296
    validity  = "90d"
  }
  
  rotation_policy = {
    automatic = true
    grace_period = "7d"
    notify_webhook = "https://alerts.company.com/pqc-rotation"
  }
  
  compatibility_mode = {
    enabled = true
    fallback_algorithm = "RSA-2048"
    sunset_date = "2027-01-01"
  }
}
```

### Service Mesh Configuration

```yaml
# istio-pqc-config.yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: pqc-mtls
  namespace: production
spec:
  mtls:
    mode: STRICT
    cipherSuites:
      - TLS_ML_KEM_768_WITH_AES_256_GCM_SHA384
      - TLS_ML_DSA_65_WITH_AES_256_GCM_SHA384
    minProtocolVersion: TLSV1_3
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: pqc-migration-config
data:
  migration_phase: "hybrid"
  classical_algorithms: "RSA-2048,ECDSA-P256"
  pqc_algorithms: "ML-KEM-768,ML-DSA-65"
  transition_deadline: "2027-01-01"
```

## 📈 Migration Dashboard

```python
from pqc_migration.dashboard import MigrationDashboard
import streamlit as st

# Initialize dashboard
dashboard = MigrationDashboard()

# Streamlit UI
st.title("🔐 Post-Quantum Migration Status")

# Overall progress
progress = dashboard.calculate_progress()
st.progress(progress.percentage)
st.metric("Migration Progress", f"{progress.percentage:.1%}", 
          f"+{progress.weekly_change:.1%}")

# Risk metrics
col1, col2, col3 = st.columns(3)
with col1:
    st.metric("Quantum-Vulnerable", progress.vulnerable_count, -progress.fixed_this_week)
with col2:
    st.metric("Harvest Risk", progress.harvest_risk, -progress.risk_reduction)
with col3:
    st.metric("Days to Deadline", progress.days_remaining)

# Department breakdown
st.subheader("Migration by Department")
fig = dashboard.plot_department_progress()
st.plotly_chart(fig)

# Timeline
st.subheader("Migration Timeline")
timeline = dashboard.generate_timeline()
st.plotly_chart(timeline)
```

## 📚 Algorithm Support

### Supported PQC Algorithms

| Type | Algorithm | NIST Level | Status |
|------|-----------|------------|---------|
| KEM | ML-KEM (Kyber) | 1, 3, 5 | Standardized |
| Signature | ML-DSA (Dilithium) | 2, 3, 5 | Standardized |
| Signature | SLH-DSA (SPHINCS+) | 1, 3, 5 | Standardized |
| KEM | Classic McEliece | 1, 3, 5 | Round 4 |
| Signature | Falcon | 1, 5 | Round 4 |

## 🏗️ Enterprise SDLC

This project implements a comprehensive enterprise-grade Software Development Life Cycle (SDLC) with:

### 📋 Project Foundation
- ✅ **Architecture Documentation**: Comprehensive system design and ADRs
- ✅ **Project Charter**: Clear scope and success criteria
- ✅ **Community Files**: Code of conduct, contributing guidelines, security policy
- ✅ **Roadmap**: Versioned milestones and feature planning

### 🔧 Development Environment
- ✅ **DevContainer**: Consistent development environments
- ✅ **Code Quality**: Linting, formatting, and type checking
- ✅ **Pre-commit Hooks**: Automated quality validation
- ✅ **IDE Configuration**: VSCode settings and extensions

### 🧪 Testing Infrastructure
- ✅ **Comprehensive Testing**: Unit, integration, and performance tests
- ✅ **Coverage Reporting**: 80%+ test coverage requirement
- ✅ **Test Automation**: Continuous testing in CI/CD
- ✅ **Quality Gates**: Automated quality thresholds

### 🏗️ Build & Containerization
- ✅ **Docker**: Multi-stage builds with security best practices
- ✅ **Docker Compose**: Local development stack
- ✅ **Semantic Versioning**: Automated release management
- ✅ **Security Scanning**: Container and dependency vulnerabilities

### 📊 Monitoring & Observability
- ✅ **Prometheus**: Metrics collection and alerting
- ✅ **Grafana**: Performance dashboards
- ✅ **Health Checks**: Service monitoring
- ✅ **Structured Logging**: Comprehensive log management

### 🤖 Automation & Metrics
- ✅ **Metrics Tracking**: Comprehensive project metrics
- ✅ **Quality Monitoring**: Automated code quality reports
- ✅ **Dependency Management**: Automated security updates
- ✅ **Repository Maintenance**: Automated cleanup and optimization

### 🔄 CI/CD Workflows
- ✅ **GitHub Actions**: Comprehensive CI/CD pipelines
- ✅ **Security Scanning**: CodeQL, Dependabot, and secret scanning
- ✅ **Automated Testing**: Multi-platform test execution
- ✅ **Deployment**: Automated release and deployment

### 📈 Repository Health
- ✅ **Branch Protection**: Enforced code review and status checks
- ✅ **Issue Templates**: Structured bug reports and feature requests
- ✅ **CODEOWNERS**: Automated review assignments
- ✅ **Security Advisories**: Vulnerability disclosure process

## 🤝 Contributing

We welcome contributions! Priority areas:
- Additional language support
- Cloud provider integrations
- Performance optimizations
- Migration automation tools

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 Citation

```bibtex
@software{pqc_migration_audit,
  title={PQC Migration Audit: Automated Post-Quantum Cryptography Transition},
  author={Daniel Schmidt},
  year={2025},
  url={https://github.com/danieleschmidt/pqc-migration-audit}
}
```

## 🏆 Acknowledgments

- NIST Post-Quantum Cryptography team
- Open Quantum Safe project
- Cryptographic library maintainers

## 📜 License

MIT License - see [LICENSE](LICENSE) for details.

## ⚠️ Security Notice

This tool identifies cryptographic vulnerabilities. Always review generated patches and test thoroughly before deploying to production.
