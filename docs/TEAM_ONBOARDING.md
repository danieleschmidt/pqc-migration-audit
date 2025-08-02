# Team Onboarding Guide

## Welcome to the PQC Migration Audit Project! 🎉

This guide will help new team members get up to speed with our development practices, tools, and processes. The PQC Migration Audit project uses a comprehensive SDLC implemented through the Terragon checkpointed strategy.

## 📚 Project Overview

### Mission Statement
Help organizations prepare for the quantum computing era by automatically identifying and migrating classical cryptographic implementations to post-quantum secure alternatives.

### Key Objectives
- Detect RSA, ECC, and other quantum-vulnerable cryptography
- Generate automated Kyber/Dilithium migration patches
- Provide risk assessment and compliance monitoring
- Enable seamless transition to post-quantum cryptography

### Technology Stack
- **Language**: Python 3.8+
- **Framework**: CLI + GitHub Action
- **Testing**: pytest, coverage, security testing
- **Quality**: Black, isort, flake8, mypy, bandit
- **Containers**: Docker, Kubernetes
- **Monitoring**: Prometheus, Grafana
- **CI/CD**: GitHub Actions

## 🏗️ Repository Structure

```
pqc-migration-audit/
├── src/pqc_migration_audit/        # Core application code
│   ├── __init__.py
│   ├── cli.py                      # Command-line interface
│   ├── core.py                     # Core scanning logic
│   └── metrics.py                  # Metrics collection
├── tests/                          # Comprehensive test suite
│   ├── unit/                       # Unit tests
│   ├── integration/                # Integration tests
│   ├── performance/                # Performance tests
│   ├── security/                   # Security tests
│   └── fixtures/                   # Test data
├── docs/                           # Documentation
│   ├── adr/                        # Architecture Decision Records
│   ├── compliance/                 # Compliance documentation
│   ├── monitoring/                 # Monitoring guides
│   ├── operations/                 # Operational procedures
│   ├── security/                   # Security documentation
│   └── workflows/                  # CI/CD workflow docs
├── scripts/                        # Automation scripts
│   ├── automation/                 # Repository automation
│   ├── setup/                      # Setup and configuration
│   └── metrics-collector.py       # Metrics collection
├── monitoring/                     # Monitoring configuration
│   ├── prometheus-config.yml      # Prometheus setup
│   ├── alert-rules.yml            # Alerting rules
│   └── recording-rules.yml        # Recording rules
├── .github/                        # GitHub configuration
│   ├── workflows/                  # CI/CD workflows (manual setup)
│   ├── ISSUE_TEMPLATE/            # Issue templates
│   ├── PULL_REQUEST_TEMPLATE.md   # PR template
│   ├── CODEOWNERS                 # Code ownership
│   └── project-metrics.json       # Metrics configuration
└── config files                   # Various configuration files
```

## 🚀 Quick Start (30 Minutes)

### 1. Environment Setup

#### Prerequisites
- Python 3.8 or higher
- Git
- Docker (optional, for container development)
- VS Code (recommended)

#### Clone and Setup
```bash
# Clone the repository
git clone https://github.com/danieleschmidt/pqc-migration-audit.git
cd pqc-migration-audit

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e .[dev,test]

# Install pre-commit hooks
pre-commit install

# Verify setup
python -m pytest tests/ -v
pqc-audit --version
```

#### VS Code Setup
```bash
# Install recommended extensions
code --install-extension ms-python.python
code --install-extension ms-python.black-formatter
code --install-extension ms-python.isort
code --install-extension ms-python.flake8

# Open project
code .
```

### 2. Run Your First Scan
```bash
# Scan the project itself
pqc-audit scan . --output report.html --format html

# View the report
open report.html  # or start report.html on Windows
```

### 3. Run Tests
```bash
# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=src --cov-report=html

# Run specific test categories
python -m pytest tests/unit/          # Unit tests only
python -m pytest tests/integration/   # Integration tests only
python -m pytest tests/security/      # Security tests only
```

## 🔧 Development Workflow

### Git Workflow
We use a modified GitFlow with the following branches:

- **`main`**: Production-ready code
- **`develop`**: Integration branch for features
- **`feature/*`**: Feature development branches
- **`hotfix/*`**: Emergency fixes
- **`release/*`**: Release preparation

#### Creating a Feature Branch
```bash
# Start from develop
git checkout develop
git pull origin develop

# Create feature branch
git checkout -b feature/your-feature-name

# Make changes, commit regularly
git add .
git commit -m "feat: add new scanning capability"

# Push and create PR
git push origin feature/your-feature-name
gh pr create --title "Add new scanning capability" --body "Description of changes"
```

### Code Standards

#### Python Code Style
```python
# Use Black formatter (automatic)
black src/ tests/

# Use isort for imports (automatic)
isort src/ tests/

# Follow type hints
def scan_file(file_path: Path) -> ScanResult:
    """Scan a file for cryptographic vulnerabilities."""
    pass

# Use descriptive docstrings
def calculate_risk_score(vulnerabilities: List[Vulnerability]) -> float:
    """
    Calculate risk score based on found vulnerabilities.
    
    Args:
        vulnerabilities: List of found vulnerabilities
        
    Returns:
        Risk score between 0.0 and 100.0
        
    Raises:
        ValueError: If vulnerabilities list is invalid
    """
    pass
```

#### Commit Message Format
We follow Conventional Commits:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (no logic change)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(scanner): add support for Go language detection
fix(cli): resolve output formatting issue with large files
docs(api): update API documentation with new endpoints
test(security): add tests for vulnerability detection
```

### Pull Request Process

#### Before Creating a PR
```bash
# Ensure code quality
black src/ tests/
isort src/ tests/
flake8 src/ tests/
mypy src/

# Run tests
python -m pytest

# Run security checks
bandit -r src/
safety check

# Update documentation if needed
```

#### PR Requirements
- [ ] **Description**: Clear description of changes
- [ ] **Tests**: New tests for new functionality
- [ ] **Documentation**: Updated if needed
- [ ] **Security Review**: For cryptographic changes
- [ ] **Performance**: No performance regression
- [ ] **Breaking Changes**: Documented and justified

#### Review Process
1. **Automated Checks**: All CI checks must pass
2. **Code Review**: At least 1 approval required (2 for main branch)
3. **Security Review**: Required for cryptographic code changes
4. **Final Approval**: Team lead approval for significant changes

## 🧪 Testing Strategy

### Test Categories

#### Unit Tests (`tests/unit/`)
- Test individual functions and classes
- Mock external dependencies
- Fast execution (<1 second per test)
- High coverage (>90% for new code)

```python
def test_vulnerability_detection():
    scanner = CryptoScanner()
    result = scanner.scan_code("rsa.generate_private_key(2048)")
    assert len(result.vulnerabilities) == 1
    assert result.vulnerabilities[0].algorithm == "RSA"
```

#### Integration Tests (`tests/integration/`)
- Test component interactions
- Use real dependencies where appropriate
- Test end-to-end workflows

```python
def test_full_scan_workflow():
    with temp_project() as project_path:
        result = run_scan(project_path)
        assert result.exit_code == 0
        assert "vulnerabilities found" in result.output
```

#### Security Tests (`tests/security/`)
- Test security-specific functionality
- Validate vulnerability detection accuracy
- Test edge cases and attack scenarios

#### Performance Tests (`tests/performance/`)
- Benchmark scan performance
- Memory usage validation
- Scalability testing

### Test Data Management
```python
# Use fixtures for reusable test data
@pytest.fixture
def sample_vulnerable_code():
    return """
    from cryptography.hazmat.primitives.asymmetric import rsa
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    """

# Use temporary directories for file tests
def test_file_scanning(tmp_path):
    test_file = tmp_path / "test.py"
    test_file.write_text("import rsa")
    result = scan_file(test_file)
    assert len(result.vulnerabilities) > 0
```

## 🔐 Security Practices

### Code Security
- **No Hardcoded Secrets**: Use environment variables
- **Input Validation**: Validate all user inputs
- **Error Handling**: Don't expose internal details
- **Dependency Management**: Regular security updates

### Cryptographic Code Guidelines
- **Security Review Required**: All crypto code needs security team review
- **Use Standard Libraries**: Prefer well-established crypto libraries
- **Key Management**: Proper key generation and storage
- **Algorithm Selection**: Follow NIST recommendations

### Security Testing
```python
# Test for common vulnerabilities
def test_no_sql_injection():
    malicious_input = "'; DROP TABLE users; --"
    result = process_input(malicious_input)
    assert "error" not in result.lower()

# Test crypto implementation
def test_secure_random_generation():
    values = [generate_secure_random() for _ in range(1000)]
    assert len(set(values)) == 1000  # No duplicates
```

## 📊 Monitoring and Observability

### Metrics Collection
Our application exposes metrics in Prometheus format:

```python
from prometheus_client import Counter, Histogram, Gauge

# Define metrics
scan_counter = Counter('pqc_scans_total', 'Total scans performed', ['status'])
scan_duration = Histogram('pqc_scan_duration_seconds', 'Scan duration')
vulnerability_gauge = Gauge('pqc_vulnerabilities_found', 'Vulnerabilities found')

# Use in code
with scan_duration.time():
    result = perform_scan(file_path)
    scan_counter.labels(status='success').inc()
    vulnerability_gauge.set(len(result.vulnerabilities))
```

### Logging Standards
```python
import logging
import structlog

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

# Use structured logging
logger.info("Vulnerability detected", 
           file_path=file_path,
           algorithm="RSA",
           severity="critical",
           line_number=42)
```

### Health Checks
```python
# Implement health check endpoints
@app.route('/health')
def health_check():
    return {
        'status': 'healthy',
        'version': __version__,
        'timestamp': datetime.utcnow().isoformat(),
        'checks': {
            'crypto_library': check_crypto_library(),
            'memory_usage': check_memory_usage(),
            'disk_space': check_disk_space()
        }
    }
```

## 🛠️ Tools and Scripts

### Automation Scripts
```bash
# Repository maintenance
./scripts/automation/repository-maintenance.sh

# Dependency scanning
python scripts/automation/dependency-scanner.py

# Metrics collection
python scripts/metrics-collector.py

# Repository configuration
python scripts/setup/repository-configurator.py
```

### Development Tools
```bash
# Code formatting
make format

# Code linting
make lint

# Run tests
make test

# Security scan
make security-scan

# Build container
make build

# Full CI pipeline locally
make ci
```

### VS Code Tasks
Configure in `.vscode/tasks.json`:
```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "Run Tests",
            "type": "shell",
            "command": "python -m pytest",
            "group": "test"
        },
        {
            "label": "Format Code",
            "type": "shell",
            "command": "black src/ tests/ && isort src/ tests/",
            "group": "build"
        }
    ]
}
```

## 📚 Learning Resources

### Internal Documentation
- [Architecture Documentation](docs/ARCHITECTURE.md)
- [API Documentation](docs/api/)
- [Security Guidelines](docs/security/)
- [Deployment Guide](docs/DEPLOYMENT.md)

### External Resources
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Python Cryptography Library](https://cryptography.io/)
- [Testing Best Practices](https://docs.pytest.org/en/stable/)
- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)

### Recommended Reading
- "Cryptography Engineering" by Ferguson, Schneier, and Kohno
- "Post-Quantum Cryptography" by Bernstein, Buchmann, and Dahmen
- "Clean Code" by Robert C. Martin
- "The DevOps Handbook" by Kim, Humble, Debois, and Willis

## 🤝 Team Communication

### Communication Channels
- **Slack Channels**:
  - `#pqc-development`: Development discussions
  - `#pqc-security`: Security-related topics
  - `#pqc-alerts`: Automated alerts and notifications
  - `#pqc-general`: General project discussions

- **Email Lists**:
  - `dev-team@terragonlabs.com`: Development team
  - `security-team@terragonlabs.com`: Security team
  - `all-hands@terragonlabs.com`: All team members

### Meeting Schedule
- **Daily Standups**: 9:00 AM EST (optional for distributed team)
- **Sprint Planning**: Every 2 weeks, Monday 10:00 AM EST
- **Security Review**: Weekly, Wednesday 2:00 PM EST
- **Retrospectives**: End of each sprint, Friday 3:00 PM EST

### Code Review Guidelines
- **Response Time**: Respond to review requests within 24 hours
- **Review Depth**: Review both functionality and security implications
- **Constructive Feedback**: Focus on code improvement, not personal criticism
- **Knowledge Sharing**: Use reviews as learning opportunities

## 🎯 Your First Tasks

### Week 1: Environment and Understanding
- [ ] Complete environment setup
- [ ] Read architecture documentation
- [ ] Run the application locally
- [ ] Complete security training
- [ ] Join team communication channels

### Week 2: First Contribution
- [ ] Pick a "good first issue" from GitHub
- [ ] Create feature branch
- [ ] Implement solution with tests
- [ ] Submit pull request
- [ ] Address review feedback

### Week 3: Integration
- [ ] Participate in team meetings
- [ ] Review other team members' PRs
- [ ] Contribute to documentation
- [ ] Help with testing or automation

### Month 1 Goals
- [ ] Complete first feature implementation
- [ ] Understand the full development workflow
- [ ] Become familiar with security practices
- [ ] Contribute to team knowledge base

## 🆘 Getting Help

### Who to Contact
- **Technical Questions**: Development team lead or senior developers
- **Security Questions**: Security team lead
- **Process Questions**: Project manager or team lead
- **Tool Issues**: DevOps team or infrastructure team

### How to Ask for Help
1. **Search First**: Check documentation and existing issues
2. **Be Specific**: Provide error messages, steps to reproduce
3. **Share Context**: What are you trying to accomplish?
4. **Show Your Work**: What have you already tried?

### Emergency Contacts
- **Security Incidents**: security-emergency@terragonlabs.com
- **System Outages**: devops-oncall@terragonlabs.com
- **General Escalation**: team-lead@terragonlabs.com

## 🏆 Success Metrics

### Individual Success Metrics
- **Code Quality**: Clean, well-tested, and secure code
- **Collaboration**: Effective code reviews and knowledge sharing
- **Learning**: Continuous improvement and skill development
- **Delivery**: Consistent delivery of valuable features

### Team Success Metrics
- **Velocity**: Sustainable development pace
- **Quality**: Low defect rate and high user satisfaction
- **Security**: Zero critical security vulnerabilities
- **Knowledge**: Well-documented and maintainable codebase

Welcome to the team! We're excited to have you contribute to this important project. Remember, everyone is here to help you succeed. Don't hesitate to ask questions and share your ideas.

---

**Document Version**: 1.0  
**Last Updated**: 2025-01-15  
**Next Review**: 2025-04-15  
**Maintained By**: Terragon Labs Development Team