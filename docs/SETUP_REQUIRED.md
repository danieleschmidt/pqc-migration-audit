# Manual Setup Required

## Overview

Due to GitHub security restrictions, certain workflow files and configurations must be manually created by repository administrators. This document provides comprehensive instructions for completing the CI/CD setup.

## ⚠️ Important Notice

**GitHub Actions Limitations**: Automated creation of workflow files in `.github/workflows/` is restricted for security reasons. Repository maintainers must manually implement these configurations.

## Required Manual Actions

### 1. Create GitHub Workflows

#### Copy Workflow Templates
```bash
# Create workflows directory
mkdir -p .github/workflows

# Copy all workflow templates from documentation
cp docs/workflows/templates/ci.yml .github/workflows/
cp docs/workflows/templates/security.yml .github/workflows/
cp docs/workflows/templates/cd.yml .github/workflows/
cp docs/workflows/templates/pqc-audit.yml .github/workflows/
cp docs/workflows/templates/dependency-update.yml .github/workflows/

# Verify workflows are in place
ls -la .github/workflows/
```

#### Additional Required Workflows
Create these additional workflow files in `.github/workflows/`:

**`docs.yml`** - Documentation Building
```yaml
name: Documentation
on:
  push:
    branches: [main]
    paths: ['docs/**', 'README.md', 'src/**/*.py']
  pull_request:
    paths: ['docs/**', 'README.md']

jobs:
  build-docs:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    - name: Install dependencies
      run: |
        pip install -e .[docs]
        pip install sphinx sphinx-rtd-theme
    - name: Build documentation
      run: |
        cd docs && make html
    - name: Deploy to GitHub Pages
      if: github.ref == 'refs/heads/main'
      uses: peaceiris/actions-gh-pages@v3
      with:
        github_token: ${{ secrets.GITHUB_TOKEN }}
        publish_dir: ./docs/_build/html
```

**`release.yml`** - Automated Releases
```yaml
name: Release
on:
  push:
    tags: ['v*.*.*']
  workflow_dispatch:
    inputs:
      version:
        description: 'Version to release'
        required: true

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    - name: Build package
      run: |
        pip install build
        python -m build
    - name: Publish to PyPI
      uses: pypa/gh-action-pypi-publish@release/v1
      with:
        password: ${{ secrets.PYPI_API_TOKEN }}
    - name: Create GitHub Release
      uses: softprops/action-gh-release@v1
      with:
        files: dist/*
        generate_release_notes: true
```

### 2. Configure Repository Secrets

#### Navigate to Repository Settings
```
Repository → Settings → Secrets and variables → Actions
```

#### Required Secrets
Add these secrets in the repository settings:

**PyPI Publishing**
```
PYPI_API_TOKEN=pypi-...                    # Production PyPI token
TEST_PYPI_API_TOKEN=pypi-...               # Test PyPI token  
```

**Code Coverage**
```
CODECOV_TOKEN=...                          # Codecov integration token
```

**Security Scanning**
```
SNYK_TOKEN=...                             # Snyk security scanning (optional)
SONAR_TOKEN=...                            # SonarCloud integration (optional)
```

**Notifications**
```
SLACK_WEBHOOK_URL=https://hooks.slack.com/... # Team notifications
DISCORD_WEBHOOK_URL=https://discord.com/...   # Alternative notifications
```

**Cloud Deployments** (if applicable)
```
AWS_ACCESS_KEY_ID=...                      # AWS deployments
AWS_SECRET_ACCESS_KEY=...                  # AWS deployments
GOOGLE_CREDENTIALS=...                     # GCP deployments
DOCKER_USERNAME=...                        # Docker Hub username
DOCKER_PASSWORD=...                        # Docker Hub token
```

#### Repository Variables
Configure these variables:
```
PYTHON_VERSION=3.11                       # Default Python version
NODE_VERSION=18                            # Node.js for documentation
COVERAGE_THRESHOLD=80                      # Minimum code coverage
TEST_TIMEOUT=300                          # Test timeout in seconds
```

### 3. Configure Branch Protection Rules

#### Method 1: GitHub CLI (Recommended)
```bash
# Install GitHub CLI if not available
# See: https://cli.github.com/

# Authenticate
gh auth login

# Configure main branch protection
gh api repos/danieleschmidt/pqc-migration-audit/branches/main/protection \
  --method PUT \
  --field required_status_checks='{
    "strict": true,
    "contexts": [
      "test (ubuntu-latest, 3.11)",
      "lint",
      "security-scan",
      "type-check"
    ]
  }' \
  --field enforce_admins=true \
  --field required_pull_request_reviews='{
    "required_approving_review_count": 2,
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true
  }' \
  --field restrictions=null \
  --field required_linear_history=true \
  --field allow_force_pushes=false \
  --field allow_deletions=false \
  --field required_conversation_resolution=true
```

#### Method 2: Web Interface
1. Go to `Settings → Branches → Add rule`
2. **Branch name pattern**: `main`
3. **Configure protection settings**:
   - ✅ Require a pull request before merging
   - ✅ Require approvals (2)
   - ✅ Dismiss stale reviews
   - ✅ Require review from code owners
   - ✅ Require status checks to pass
   - ✅ Require branches to be up to date
   - **Required status checks**:
     - `test (ubuntu-latest, 3.11)`
     - `lint`
     - `security-scan`
     - `type-check`
   - ✅ Require conversation resolution
   - ✅ Require linear history
   - ✅ Include administrators
   - ❌ Allow force pushes
   - ❌ Allow deletions

### 4. Create CODEOWNERS File

Create `.github/CODEOWNERS`:
```bash
# .github/CODEOWNERS
# Global owners - require review for all changes
* @danieleschmidt

# Core source code
/src/ @danieleschmidt @core-maintainers

# Cryptographic components (require security review)
/src/pqc_migration_audit/crypto/ @danieleschmidt @security-team
/src/pqc_migration_audit/algorithms/ @danieleschmidt @security-team
/src/pqc_migration_audit/scanner/ @danieleschmidt @security-team

# Security-sensitive files
/src/pqc_migration_audit/security/ @danieleschmidt @security-team
/tests/security/ @danieleschmidt @security-team
/docs/security/ @danieleschmidt @security-team

# Infrastructure and deployment
/.github/ @danieleschmidt @devops-team
/docker/ @danieleschmidt @devops-team
/k8s/ @danieleschmidt @devops-team
/terraform/ @danieleschmidt @devops-team

# Documentation
/docs/ @danieleschmidt @docs-team
/README.md @danieleschmidt @docs-team
/*.md @danieleschmidt

# Dependencies and configuration
/requirements*.txt @danieleschmidt @security-team
/pyproject.toml @danieleschmidt
/setup.py @danieleschmidt

# Testing infrastructure
/tests/ @danieleschmidt @core-maintainers
/.github/workflows/ @danieleschmidt @devops-team
```

### 5. Configure Dependabot

Create `.github/dependabot.yml`:
```yaml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "09:00"
    reviewers:
      - "danieleschmidt"
    assignees:
      - "danieleschmidt"
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

### 6. Setup Issue and PR Templates

#### Create Issue Templates
```bash
mkdir -p .github/ISSUE_TEMPLATE
```

**Bug Report Template** (`.github/ISSUE_TEMPLATE/bug_report.yml`):
```yaml
name: Bug Report
description: File a bug report for PQC Migration Audit
title: "[Bug]: "
labels: ["bug", "triage"]
body:
  - type: input
    id: version
    attributes:
      label: Version
      description: What version are you running?
      placeholder: ex. 1.0.0
    validations:
      required: true
  
  - type: textarea
    id: bug-description
    attributes:
      label: Bug Description
      description: A clear description of the bug
    validations:
      required: true
  
  - type: textarea
    id: reproduction
    attributes:
      label: Steps to Reproduce
      placeholder: |
        1. Run command '...'
        2. See error
    validations:
      required: true
```

**Feature Request Template** (`.github/ISSUE_TEMPLATE/feature_request.yml`):
```yaml
name: Feature Request
description: Suggest a new feature for PQC Migration Audit
title: "[Feature]: "
labels: ["enhancement", "triage"]
body:
  - type: textarea
    id: feature-description
    attributes:
      label: Feature Description
      description: A clear description of the feature
    validations:
      required: true
  
  - type: textarea
    id: use-case
    attributes:
      label: Use Case
      description: Describe the problem this feature would solve
    validations:
      required: true
```

#### Create PR Template
Create `.github/PULL_REQUEST_TEMPLATE.md`:
```markdown
## Description
Brief description of changes in this PR.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing
- [ ] Tests pass locally
- [ ] New tests added for new functionality
- [ ] Manual testing completed

## Security Considerations
- [ ] No sensitive information exposed
- [ ] Cryptographic changes reviewed by security team (if applicable)
- [ ] Dependencies checked for vulnerabilities

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Tests added that prove fix is effective or feature works
- [ ] Documentation updated (if applicable)
```

### 7. Enable GitHub Pages (for Documentation)

1. Go to `Settings → Pages`
2. **Source**: Deploy from a branch
3. **Branch**: `gh-pages` (will be created by docs workflow)
4. **Folder**: `/ (root)`
5. Click **Save**

### 8. Configure Notifications

#### Slack Integration (Optional)
1. Create Slack webhook in your workspace
2. Add `SLACK_WEBHOOK_URL` to repository secrets
3. Configure notification channels in workflows

#### Email Notifications
1. Go to `Settings → Notifications`
2. Configure email preferences for:
   - Actions workflows
   - Dependabot alerts
   - Security alerts

### 9. Security Configuration

#### Enable Security Features
1. Go to `Settings → Security & analysis`
2. Enable:
   - ✅ Dependency graph
   - ✅ Dependabot alerts
   - ✅ Dependabot security updates
   - ✅ Code scanning alerts
   - ✅ Secret scanning alerts

#### Configure CodeQL Analysis
CodeQL will be automatically configured by the security workflow, but you can customize it:

1. Go to `Security → Code scanning alerts`
2. Click **Set up this workflow** for CodeQL Analysis
3. Customize the generated workflow if needed

### 10. Performance Monitoring Setup

#### Codecov Integration
1. Sign up at [codecov.io](https://codecov.io)
2. Connect your GitHub repository
3. Get integration token
4. Add `CODECOV_TOKEN` to repository secrets

#### SonarCloud Integration (Optional)
1. Sign up at [sonarcloud.io](https://sonarcloud.io)
2. Import your repository
3. Get project token
4. Add `SONAR_TOKEN` to repository secrets

### 11. Verification Steps

#### Test Workflow Execution
```bash
# Trigger CI workflow
git checkout -b test-workflows
echo "# Test" >> README.md
git add README.md
git commit -m "test: trigger CI workflow"
git push origin test-workflows

# Create PR to test all checks
gh pr create --title "Test: Verify CI/CD Setup" --body "Testing workflow configuration"
```

#### Verify Protection Rules
```bash
# Test branch protection
git checkout main
git pull origin main
echo "# Direct push test" >> README.md
git add README.md
git commit -m "test: direct push (should fail)"
git push origin main  # This should fail due to protection rules
```

#### Check Status Checks
1. Go to a pull request
2. Verify required status checks appear
3. Confirm checks must pass before merge

## Troubleshooting

### Common Issues

#### 1. Workflow Permissions
If workflows fail with permission errors:
```bash
# Check workflow permissions
# Go to Settings → Actions → General
# Ensure "Read and write permissions" is selected for GITHUB_TOKEN
```

#### 2. Missing Status Checks
If required status checks don't appear:
```bash
# Verify workflow names match exactly
# Check .github/workflows/ files for correct job names
# Ensure workflows have run at least once
```

#### 3. Branch Protection Conflicts
```bash
# View current protection settings
gh api repos/danieleschmidt/pqc-migration-audit/branches/main/protection

# Update if needed
gh api repos/danieleschmidt/pqc-migration-audit/branches/main/protection \
  --method PUT \
  --field [corrected-settings]
```

### Getting Help

#### Support Contacts
- **Primary**: Repository maintainer (@danieleschmidt)
- **DevOps**: devops@terragonlabs.com
- **Security**: security@terragonlabs.com

#### Useful Resources
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Branch Protection Documentation](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/defining-the-mergeability-of-pull-requests/about-protected-branches)
- [Dependabot Configuration](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file)

## Success Criteria

✅ **Workflow Setup Complete When**:
- [ ] All 5 core workflows are in `.github/workflows/`
- [ ] Repository secrets are configured
- [ ] Branch protection rules are active
- [ ] CODEOWNERS file is in place
- [ ] Issue/PR templates are created
- [ ] First test PR successfully runs all checks
- [ ] Documentation builds and deploys
- [ ] Security scanning is active
- [ ] Dependabot is monitoring dependencies

## Next Steps

After completing manual setup:
1. **Test the complete CI/CD pipeline** with a test PR
2. **Configure team access** and reviewer assignments
3. **Set up monitoring dashboards** for workflow health
4. **Train team members** on the new processes
5. **Document any customizations** made during setup

This manual setup ensures a robust, secure, and maintainable CI/CD pipeline for the PQC Migration Audit project.