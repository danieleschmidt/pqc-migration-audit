# Manual Setup Requirements

This document outlines the manual setup tasks that need to be completed by repository administrators due to GitHub App permission limitations.

## 🔧 Required Manual Actions

### 1. GitHub Actions Workflows

**Status:** ⚠️ Manual setup required  
**Location:** `.github/workflows/`

The following workflow files need to be created manually from the templates in `docs/workflows/templates/`:

1. **ci.yml** - Main CI/CD pipeline
   - Copy from `docs/workflows/templates/ci.yml`
   - Configure secrets: `CODECOV_TOKEN`

2. **security.yml** - Security scanning
   - Copy from `docs/workflows/templates/security.yml`
   - Configure CodeQL analysis

3. **pqc-audit.yml** - Self-auditing workflow
   - Copy from `docs/workflows/templates/pqc-audit.yml`
   - Schedule weekly scans

**Instructions:**
```bash
# Create workflows directory
mkdir -p .github/workflows

# Copy template files
cp docs/workflows/templates/*.yml .github/workflows/

# Commit and push
git add .github/workflows/
git commit -m "feat: add GitHub Actions workflows"
git push
```

### 2. Repository Settings

**Status:** ⚠️ Manual configuration required

#### Branch Protection Rules

Configure branch protection for `main` branch:
- ✅ Require pull request reviews (2 reviewers)
- ✅ Require status checks to pass:
  - `test (ubuntu-latest, 3.11)`
  - `security-scan`
  - `lint`
- ✅ Require branches to be up to date
- ✅ Restrict pushes to administrators

#### Repository Topics

Add the following topics to improve discoverability:
```
post-quantum-cryptography, security-audit, python, cryptography, 
migration-tool, quantum-safe, security-scanner, vulnerability-assessment
```

#### Repository Settings
- ✅ Description: "Advanced tool for auditing and migrating to post-quantum cryptography"
- ✅ Homepage: "https://terragonlabs.com/pqc-audit"
- ✅ Enable Issues
- ✅ Enable Wiki
- ✅ Enable Projects
- ✅ Enable Security advisories
- ✅ Enable Vulnerability alerts

### 3. GitHub Secrets Configuration

**Status:** ⚠️ Manual setup required  
**Location:** Repository Settings > Secrets and variables > Actions

Required secrets:
```bash
# Code coverage
CODECOV_TOKEN=your_codecov_token_here

# Optional: Slack notifications
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...

# Optional: PyPI publishing
PYPI_API_TOKEN=pypi-token-here
```

### 4. GitHub Pages Setup

**Status:** ⚠️ Manual configuration required

1. Go to Repository Settings > Pages
2. Set source to "GitHub Actions"
3. Configure custom domain (optional): `pqc-audit.terragonlabs.com`

### 5. Security Features

**Status:** ⚠️ Manual enablement required

Enable these security features in Settings > Security:
- ✅ Dependency graph
- ✅ Dependabot alerts
- ✅ Dependabot security updates
- ✅ Secret scanning
- ✅ Code scanning (CodeQL)

### 6. Integrations Setup

**Status:** ⚠️ Environment variables required

Configure integration environment variables:
```bash
# GitHub integration
export GITHUB_TOKEN="your_github_token"

# Monitoring stack
export PROMETHEUS_URL="http://localhost:9090"
export GRAFANA_URL="http://localhost:3000"

# Notifications
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."

# Coverage reporting
export CODECOV_TOKEN="your_codecov_token"
```

Run integration setup:
```bash
python scripts/automation/integration-setup.py
```

## 📋 Setup Verification Checklist

Use this checklist to verify all manual setup is complete:

### GitHub Actions
- [ ] CI workflow is running successfully
- [ ] Security scanning workflow is configured
- [ ] PQC self-audit workflow is scheduled
- [ ] All required secrets are configured

### Repository Configuration
- [ ] Branch protection rules are enabled
- [ ] Repository topics are set
- [ ] Description and homepage are configured
- [ ] Security features are enabled

### Integrations
- [ ] Codecov integration is working
- [ ] Slack notifications are configured (optional)
- [ ] Monitoring stack is connected (optional)

### Documentation
- [ ] GitHub Pages is configured
- [ ] README badges are displaying correctly
- [ ] API documentation is generated

## 🚨 Security Considerations

### Critical Security Setup

1. **Secret Scanning**: Ensure GitHub's secret scanning is enabled
2. **Dependency Scanning**: Configure Dependabot alerts
3. **Code Scanning**: Set up CodeQL for vulnerability detection
4. **Branch Protection**: Enforce required reviews and status checks

### Access Control

1. **Team Permissions**: Configure team access levels
2. **CODEOWNERS**: Review and update the CODEOWNERS file
3. **Admin Access**: Limit admin access to essential personnel

## 📞 Support

If you need assistance with any of these setup tasks:

- **Technical Issues**: Create an issue in this repository
- **Security Concerns**: Email security@terragonlabs.com
- **General Questions**: Contact devops@terragonlabs.com

## 🔄 Automated Verification

After completing manual setup, run this verification script:

```bash
# Verify setup completeness
python scripts/automation/integration-health-check.py

# Run full quality check
python scripts/automation/quality-monitor.py

# Generate setup report
python scripts/automation/collect-metrics.py
```

---

**Last Updated:** 2025-01-01  
**Next Review:** 2025-02-01  
**Responsible Team:** DevOps & Security Teams