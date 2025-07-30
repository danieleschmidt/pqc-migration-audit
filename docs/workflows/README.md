# GitHub Actions Workflow Documentation

This directory contains documentation for GitHub Actions workflows required for the PQC Migration Audit project.

## Required Workflows

### 1. Continuous Integration (`ci.yml`)

**Purpose**: Run tests, linting, and security checks on every push and PR.

**Triggers**:
- Push to `main` and `develop` branches
- Pull requests to `main`
- Manual workflow dispatch

**Jobs**:
- **Test Matrix**: Python 3.8, 3.9, 3.10, 3.11, 3.12 on Ubuntu, macOS, Windows
- **Code Quality**: Black formatting, isort imports, flake8 linting, mypy type checking
- **Security**: Bandit security scanning, safety dependency checking
- **Coverage**: pytest with coverage reporting to Codecov

### 2. Security Scanning (`security.yml`)

**Purpose**: Advanced security scanning for cryptographic code.

**Triggers**:
- Weekly schedule (Sundays at midnight UTC)
- Push to `main` branch
- Manual workflow dispatch

**Jobs**:
- **SAST**: CodeQL analysis for security vulnerabilities
- **Dependency Scanning**: Dependabot and safety checks
- **Secret Scanning**: GitLeaks for accidentally committed secrets
- **Container Scanning**: If Docker images are used

### 3. Documentation (`docs.yml`)

**Purpose**: Build and deploy documentation.

**Triggers**:
- Push to `main` branch (docs/ directory changes)
- Manual workflow dispatch

**Jobs**:
- **Build Docs**: Sphinx documentation generation
- **Deploy**: GitHub Pages deployment
- **Link Checking**: Verify all documentation links work

### 4. Release (`release.yml`)

**Purpose**: Automated releases and PyPI publishing.

**Triggers**:
- Tag creation matching `v*.*.*` pattern
- Manual workflow dispatch with version input

**Jobs**:
- **Build**: Create wheel and source distributions
- **Test**: Verify packages install correctly
- **Publish**: Upload to PyPI (production) and TestPyPI (staging)
- **Release**: Create GitHub release with changelog

### 5. PQC Self-Audit (`pqc-audit.yml`)

**Purpose**: Use the tool to audit itself for quantum-vulnerable cryptography.

**Triggers**:
- Weekly schedule (Wednesdays at 2 AM UTC)
- Push to `main` branch
- Manual workflow dispatch

**Jobs**:
- **Self-Scan**: Run PQC audit on repository itself
- **Report**: Generate and upload audit reports
- **Alert**: Notify maintainers of new vulnerabilities

## Workflow Files Structure

```
.github/
└── workflows/
    ├── ci.yml                 # Main CI/CD pipeline
    ├── security.yml          # Security scanning
    ├── docs.yml              # Documentation building
    ├── release.yml           # Release automation
    └── pqc-audit.yml         # Self-auditing
```

## Environment Variables and Secrets

### Required Secrets
- `PYPI_API_TOKEN`: PyPI publishing token
- `CODECOV_TOKEN`: Codecov integration token
- `SLACK_WEBHOOK`: Team notifications (optional)

### Environment Variables
- `PYTHON_VERSION`: Default Python version (3.11)
- `NODE_VERSION`: Node.js version for docs (18)

## Branch Protection Rules

### `main` Branch
- Require pull request reviews (2 reviewers)
- Require status checks to pass:
  - `test (ubuntu-latest, 3.11)`
  - `security-scan`
  - `lint`
- Require branches to be up to date
- Restrict pushes to administrators

### `develop` Branch  
- Require pull request reviews (1 reviewer)
- Require status checks to pass:
  - `test (ubuntu-latest, 3.11)`
  - `lint`

## Badge Configuration

Add these badges to README.md:

```markdown
[![CI](https://github.com/terragonlabs/pqc-migration-audit/workflows/CI/badge.svg)](https://github.com/terragonlabs/pqc-migration-audit/actions)
[![Security](https://github.com/terragonlabs/pqc-migration-audit/workflows/Security/badge.svg)](https://github.com/terragonlabs/pqc-migration-audit/actions)
[![codecov](https://codecov.io/gh/terragonlabs/pqc-migration-audit/branch/main/graph/badge.svg)](https://codecov.io/gh/terragonlabs/pqc-migration-audit)
[![PyPI version](https://badge.fury.io/py/pqc-migration-audit.svg)](https://badge.fury.io/py/pqc-migration-audit)
```

## Monitoring and Notifications

### Success Metrics
- Build success rate > 95%
- Test coverage > 80%  
- Security scan results: No high/critical findings
- Release deployment time < 5 minutes

### Failure Notifications
- Slack integration for build failures
- Email notifications for security findings
- GitHub issue creation for recurring failures

## Manual Setup Required

⚠️ **Note**: Due to GitHub Actions security restrictions, these workflow files must be created manually by repository administrators:

1. Create `.github/workflows/` directory
2. Copy workflow templates from `docs/workflows/templates/`
3. Configure required secrets in repository settings
4. Set up branch protection rules
5. Enable GitHub Pages for documentation

## Troubleshooting

### Common Issues
- **Permission denied**: Check GITHUB_TOKEN permissions
- **Test failures**: Verify Python version compatibility  
- **Security scan false positives**: Update allowlist in workflow
- **Documentation build fails**: Check Sphinx configuration

### Support
For workflow setup assistance, contact: devops@terragonlabs.com