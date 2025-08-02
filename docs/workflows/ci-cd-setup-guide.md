# CI/CD Setup Guide

## Overview

This guide provides step-by-step instructions for setting up comprehensive CI/CD pipelines for the PQC Migration Audit project.

## Prerequisites

### Repository Configuration
- Repository administrator access
- GitHub Actions enabled
- Required secrets configured
- Branch protection rules applied

### Required Secrets
Configure these secrets in repository settings (`Settings > Secrets and variables > Actions`):

```bash
# PyPI Publishing
PYPI_API_TOKEN="pypi-..."           # Production PyPI token
TEST_PYPI_API_TOKEN="pypi-..."      # Test PyPI token

# Code Coverage
CODECOV_TOKEN="..."                 # Codecov integration token

# Notifications
SLACK_WEBHOOK_URL="https://hooks.slack.com/..."  # Team notifications
DISCORD_WEBHOOK_URL="https://discord.com/..."   # Alternative notifications

# Security Scanning
SNYK_TOKEN="..."                    # Snyk security scanning
SONAR_TOKEN="..."                   # SonarCloud integration

# Docker Registry (if using containers)
DOCKER_USERNAME="..."               # Docker Hub username
DOCKER_PASSWORD="..."               # Docker Hub password or token
GHCR_TOKEN="${{ secrets.GITHUB_TOKEN }}"  # GitHub Container Registry

# Cloud Deployments (if applicable)
AWS_ACCESS_KEY_ID="..."             # AWS deployments
AWS_SECRET_ACCESS_KEY="..."         # AWS deployments
GOOGLE_CREDENTIALS="..."            # GCP deployments
```

### Repository Variables
Configure these variables in repository settings (`Settings > Secrets and variables > Actions`):

```bash
# Build Configuration
PYTHON_VERSION="3.11"              # Default Python version
NODE_VERSION="18"                   # Node.js for documentation
DOCKER_REGISTRY="ghcr.io"          # Container registry

# Testing Configuration
TEST_TIMEOUT="300"                  # Test timeout in seconds
COVERAGE_THRESHOLD="80"             # Minimum code coverage
PARALLEL_JOBS="4"                   # Parallel test execution

# Security Configuration
SECURITY_SCAN_SEVERITY="high"       # Minimum severity to fail builds
DEPENDENCY_SCAN_ENABLED="true"     # Enable dependency scanning
SECRET_SCAN_ENABLED="true"         # Enable secret scanning
```

## Workflow Implementation

### Step 1: Create Workflow Directory
```bash
# Create workflows directory structure
mkdir -p .github/workflows
mkdir -p .github/ISSUE_TEMPLATE
mkdir -p .github/PULL_REQUEST_TEMPLATE
```

### Step 2: Copy Workflow Templates
```bash
# Copy all workflow templates
cp docs/workflows/templates/*.yml .github/workflows/

# Verify workflow files
ls -la .github/workflows/
```

### Step 3: Configure Branch Protection

#### Main Branch Protection
```bash
# Use GitHub CLI to configure branch protection
gh api repos/:owner/:repo/branches/main/protection \
  --method PUT \
  --field required_status_checks='{"strict":true,"contexts":["test (ubuntu-latest, 3.11)","lint","security-scan"]}' \
  --field enforce_admins=true \
  --field required_pull_request_reviews='{"required_approving_review_count":2,"dismiss_stale_reviews":true}' \
  --field restrictions=null
```

#### Develop Branch Protection
```bash
gh api repos/:owner/:repo/branches/develop/protection \
  --method PUT \
  --field required_status_checks='{"strict":true,"contexts":["test (ubuntu-latest, 3.11)","lint"]}' \
  --field enforce_admins=false \
  --field required_pull_request_reviews='{"required_approving_review_count":1}' \
  --field restrictions=null
```

## Workflow Details

### 1. Continuous Integration (`ci.yml`)

#### Features
- **Multi-OS Testing**: Ubuntu, macOS, Windows
- **Python Matrix**: 3.8, 3.9, 3.10, 3.11, 3.12
- **Code Quality**: Black, isort, flake8, mypy
- **Security**: Bandit, safety
- **Coverage**: pytest with codecov reporting

#### Configuration
```yaml
name: CI
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  workflow_dispatch:

env:
  PYTHON_VERSION: ${{ vars.PYTHON_VERSION || '3.11' }}
  COVERAGE_THRESHOLD: ${{ vars.COVERAGE_THRESHOLD || '80' }}

jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        python-version: ["3.8", "3.9", "3.10", "3.11", "3.12"]
        exclude:
          - os: macos-latest
            python-version: "3.8"
          - os: windows-latest
            python-version: "3.8"
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      with:
        fetch-depth: 0
    
    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}
        cache: 'pip'
    
    - name: Install system dependencies (Ubuntu)
      if: matrix.os == 'ubuntu-latest'
      run: |
        sudo apt-get update
        sudo apt-get install -y libssl-dev libffi-dev
    
    - name: Install Python dependencies
      run: |
        python -m pip install --upgrade pip setuptools wheel
        pip install -e .[test,dev]
    
    - name: Run pre-commit hooks
      if: matrix.python-version == env.PYTHON_VERSION && matrix.os == 'ubuntu-latest'
      run: |
        pre-commit run --all-files
    
    - name: Run tests with coverage
      run: |
        pytest \
          --cov=src/pqc_migration_audit \
          --cov-report=xml \
          --cov-report=html \
          --cov-fail-under=${{ env.COVERAGE_THRESHOLD }} \
          --junitxml=pytest.xml \
          --timeout=${{ vars.TEST_TIMEOUT || '300' }} \
          -v
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      if: matrix.python-version == env.PYTHON_VERSION && matrix.os == 'ubuntu-latest'
      with:
        token: ${{ secrets.CODECOV_TOKEN }}
        file: ./coverage.xml
        flags: unittests
        name: codecov-umbrella
        fail_ci_if_error: true
    
    - name: Upload test results
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: test-results-${{ matrix.os }}-${{ matrix.python-version }}
        path: |
          pytest.xml
          htmlcov/
          coverage.xml
```

### 2. Security Scanning (`security.yml`)

#### Features
- **SAST**: CodeQL analysis
- **Dependency Scanning**: Dependabot, safety
- **Secret Scanning**: GitLeaks
- **Container Scanning**: Trivy (if using Docker)

#### Configuration
```yaml
name: Security
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday
  workflow_dispatch:

jobs:
  codeql:
    name: CodeQL Analysis
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write
    
    steps:
    - name: Checkout repository
      uses: actions/checkout@v4
    
    - name: Initialize CodeQL
      uses: github/codeql-action/init@v2
      with:
        languages: python
        queries: security-and-quality
    
    - name: Autobuild
      uses: github/codeql-action/autobuild@v2
    
    - name: Perform CodeQL Analysis
      uses: github/codeql-action/analyze@v2

  dependency-scan:
    name: Dependency Security Scan
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        pip install safety bandit semgrep
        pip install -e .
    
    - name: Run safety check
      run: |
        safety check --json --output safety-report.json || true
        safety check --short-report
    
    - name: Run bandit security linter
      run: |
        bandit -r src/ -f json -o bandit-report.json || true
        bandit -r src/ -ll
    
    - name: Run semgrep
      run: |
        semgrep --config=auto src/ --json --output=semgrep-report.json || true
        semgrep --config=auto src/
    
    - name: Upload security reports
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: security-reports
        path: |
          safety-report.json
          bandit-report.json
          semgrep-report.json

  secret-scan:
    name: Secret Detection
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
      with:
        fetch-depth: 0
    
    - name: Run GitLeaks
      uses: gitleaks/gitleaks-action@v2
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}
```

### 3. Release Automation (`release.yml`)

#### Features
- **Semantic Versioning**: Automated version bumping
- **PyPI Publishing**: Both test and production
- **GitHub Releases**: Automated release notes
- **Changelog**: Generated from commit messages

#### Configuration
```yaml
name: Release
on:
  push:
    tags:
      - 'v*.*.*'
  workflow_dispatch:
    inputs:
      version:
        description: 'Version to release (e.g., 1.0.0)'
        required: true
        type: string

jobs:
  build:
    name: Build Distribution
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
      with:
        fetch-depth: 0
    
    - uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install build dependencies
      run: |
        pip install build twine wheel setuptools_scm[toml]
    
    - name: Build package
      run: |
        python -m build
    
    - name: Verify build
      run: |
        python -m twine check dist/*
    
    - name: Upload artifacts
      uses: actions/upload-artifact@v3
      with:
        name: dist
        path: dist/

  test-install:
    name: Test Installation
    needs: build
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        python-version: ["3.8", "3.11", "3.12"]
    
    steps:
    - uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Download artifacts
      uses: actions/download-artifact@v3
      with:
        name: dist
        path: dist/
    
    - name: Test wheel installation
      run: |
        pip install dist/*.whl
        python -c "import pqc_migration_audit; print(pqc_migration_audit.__version__)"
        pqc-audit --version

  publish-test:
    name: Publish to TestPyPI
    needs: [build, test-install]
    runs-on: ubuntu-latest
    if: github.event_name == 'workflow_dispatch'
    environment:
      name: testpypi
      url: https://test.pypi.org/p/pqc-migration-audit
    
    steps:
    - name: Download artifacts
      uses: actions/download-artifact@v3
      with:
        name: dist
        path: dist/
    
    - name: Publish to TestPyPI
      uses: pypa/gh-action-pypi-publish@release/v1
      with:
        password: ${{ secrets.TEST_PYPI_API_TOKEN }}
        repository-url: https://test.pypi.org/legacy/

  publish-prod:
    name: Publish to PyPI
    needs: [build, test-install]
    runs-on: ubuntu-latest
    if: startsWith(github.ref, 'refs/tags/')
    environment:
      name: pypi
      url: https://pypi.org/p/pqc-migration-audit
    
    steps:
    - name: Download artifacts
      uses: actions/download-artifact@v3
      with:
        name: dist
        path: dist/
    
    - name: Publish to PyPI
      uses: pypa/gh-action-pypi-publish@release/v1
      with:
        password: ${{ secrets.PYPI_API_TOKEN }}

  github-release:
    name: Create GitHub Release
    needs: [publish-prod]
    runs-on: ubuntu-latest
    if: startsWith(github.ref, 'refs/tags/')
    permissions:
      contents: write
    
    steps:
    - uses: actions/checkout@v4
      with:
        fetch-depth: 0
    
    - name: Generate changelog
      run: |
        # Generate changelog from commits since last tag
        PREVIOUS_TAG=$(git describe --tags --abbrev=0 HEAD~1 2>/dev/null || echo "")
        if [ -n "$PREVIOUS_TAG" ]; then
          git log $PREVIOUS_TAG..HEAD --pretty=format:"- %s (%h)" > CHANGELOG.md
        else
          git log --pretty=format:"- %s (%h)" > CHANGELOG.md
        fi
    
    - name: Create Release
      uses: softprops/action-gh-release@v1
      with:
        body_path: CHANGELOG.md
        draft: false
        prerelease: false
        files: |
          dist/*.whl
          dist/*.tar.gz
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### 4. Documentation (`docs.yml`)

#### Features
- **Sphinx Documentation**: Automated building
- **GitHub Pages**: Deployment
- **Link Checking**: Verify documentation links
- **API Documentation**: Auto-generated from docstrings

### 5. PQC Self-Audit (`pqc-audit.yml`)

#### Features
- **Self-Scanning**: Repository scans itself
- **Vulnerability Reporting**: Alert on new findings
- **Trend Analysis**: Track improvement over time
- **Integration Testing**: Verify tool functionality

## Advanced Configuration

### Dependabot Configuration
```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "09:00"
    reviewers:
      - "security-team"
    assignees:
      - "maintainer"
    commit-message:
      prefix: "deps"
      prefix-development: "deps-dev"
    ignore:
      - dependency-name: "*"
        update-types: ["version-update:semver-major"]

  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    commit-message:
      prefix: "ci"
```

### Issue Templates
```yaml
# .github/ISSUE_TEMPLATE/bug_report.yml
name: Bug Report
description: File a bug report for PQC Migration Audit
title: "[Bug]: "
labels: ["bug", "triage"]
assignees:
  - maintainer-team
body:
  - type: markdown
    attributes:
      value: |
        Thanks for taking the time to fill out this bug report!
  
  - type: input
    id: version
    attributes:
      label: Version
      description: What version of PQC Migration Audit are you running?
      placeholder: ex. 1.0.0
    validations:
      required: true
  
  - type: dropdown
    id: scan-type
    attributes:
      label: Scan Type
      description: What type of scan were you performing?
      options:
        - Repository scan
        - File scan
        - API usage
        - CLI usage
    validations:
      required: true
  
  - type: textarea
    id: bug-description
    attributes:
      label: Bug Description
      description: A clear and concise description of what the bug is.
      placeholder: Tell us what happened!
    validations:
      required: true
  
  - type: textarea
    id: reproduction
    attributes:
      label: Steps to Reproduce
      description: Steps to reproduce the behavior
      placeholder: |
        1. Run command '...'
        2. See error
    validations:
      required: true
  
  - type: textarea
    id: expected
    attributes:
      label: Expected Behavior
      description: A clear and concise description of what you expected to happen.
    validations:
      required: true
  
  - type: textarea
    id: logs
    attributes:
      label: Relevant Logs
      description: Please copy and paste any relevant log output. This will be automatically formatted into code, so no need for backticks.
      render: shell
```

### Pull Request Template
```markdown
# .github/PULL_REQUEST_TEMPLATE.md

## Description
Brief description of changes made in this PR.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Code refactoring

## Testing
- [ ] Tests pass locally
- [ ] New tests added for new functionality
- [ ] Manual testing completed
- [ ] Security testing completed (if applicable)

## Security Considerations
- [ ] No sensitive information exposed
- [ ] Cryptographic changes reviewed by security team
- [ ] Dependency updates checked for vulnerabilities
- [ ] Authentication/authorization impacts assessed

## Documentation
- [ ] Documentation updated (if applicable)
- [ ] Changelog updated
- [ ] API documentation updated (if applicable)

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Code commented where necessary
- [ ] Tests added that prove fix is effective or feature works
- [ ] New and existing unit tests pass locally
- [ ] Any dependent changes have been merged and published

## Screenshots (if applicable)
Include screenshots of UI changes or test results.

## Additional Notes
Any additional information or context about the PR.
```

## Monitoring and Maintenance

### Workflow Health Monitoring
```yaml
# Add to existing workflows for monitoring
- name: Notify on Failure
  if: failure()
  uses: 8398a7/action-slack@v3
  with:
    status: ${{ job.status }}
    channel: '#ci-alerts'
    webhook_url: ${{ secrets.SLACK_WEBHOOK_URL }}
    fields: repo,message,commit,author,action,eventName,ref,workflow

- name: Update Workflow Status
  if: always()
  run: |
    # Update status dashboard or metrics
    curl -X POST "${{ secrets.METRICS_ENDPOINT }}" \
      -H "Content-Type: application/json" \
      -d '{
        "workflow": "${{ github.workflow }}",
        "status": "${{ job.status }}",
        "duration": "${{ steps.timing.outputs.duration }}",
        "commit": "${{ github.sha }}"
      }'
```

### Performance Optimization
```yaml
# Caching strategies
- name: Cache Python packages
  uses: actions/cache@v3
  with:
    path: ~/.cache/pip
    key: ${{ runner.os }}-pip-${{ hashFiles('**/requirements*.txt') }}
    restore-keys: |
      ${{ runner.os }}-pip-

- name: Cache pre-commit
  uses: actions/cache@v3
  with:
    path: ~/.cache/pre-commit
    key: ${{ runner.os }}-pre-commit-${{ hashFiles('.pre-commit-config.yaml') }}

# Parallel execution
strategy:
  matrix:
    include:
      - {os: ubuntu-latest, python: "3.11", toxenv: "py311"}
      - {os: ubuntu-latest, python: "3.10", toxenv: "py310"}
      - {os: macos-latest, python: "3.11", toxenv: "py311"}
  max-parallel: 4
```

## Troubleshooting Guide

### Common Issues

#### 1. Test Failures
```bash
# Debug test failures locally
python -m pytest -xvs tests/failing_test.py::test_name

# Run with debugging
python -m pytest --pdb tests/failing_test.py

# Check for environment issues
python -c "import sys; print(sys.path)"
pip list
```

#### 2. Security Scan False Positives
```yaml
# Add to security workflow
- name: Filter False Positives
  run: |
    # Create allowlist for known false positives
    cat > .bandit_allowlist << 'EOF'
    {
      "skips": [
        "tests/test_crypto.py:B101",  # assert_used - OK in tests
        "src/crypto/legacy.py:B303"   # MD5 - used for demo purposes
      ]
    }
    EOF
    bandit -r src/ -ll -x .bandit_allowlist
```

#### 3. Build Performance Issues
```yaml
# Optimize build performance
- name: Setup Build Cache
  uses: actions/cache@v3
  with:
    path: |
      ~/.cache/pip
      ~/.cache/pre-commit
      ${{ github.workspace }}/.pytest_cache
    key: build-cache-${{ runner.os }}-${{ hashFiles('**/*.py', '**/*.txt', '**/*.yml') }}

- name: Parallel Testing
  run: |
    pytest -n auto --dist worksteal
```

### Support and Escalation

#### Internal Support
- **Primary**: DevOps Team (devops@terragonlabs.com)
- **Secondary**: Security Team (security@terragonlabs.com)
- **Escalation**: Engineering Manager (eng-manager@terragonlabs.com)

#### External Resources
- **GitHub Actions Documentation**: https://docs.github.com/en/actions
- **Python CI/CD Best Practices**: https://realpython.com/python-continuous-integration/
- **Security Scanning Tools**: https://github.com/marketplace/actions/

This comprehensive setup ensures robust, secure, and maintainable CI/CD pipelines for the PQC Migration Audit project.