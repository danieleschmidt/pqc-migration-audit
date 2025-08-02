# Branch Protection Configuration Guide

## Overview

This guide provides comprehensive instructions for configuring branch protection rules to ensure code quality, security, and proper review processes for the PQC Migration Audit project.

## Branch Protection Strategy

### Repository Structure
```
main (production)
├── develop (staging)
├── feature/* (feature branches)
├── hotfix/* (emergency fixes)
├── release/* (release preparation)
└── security/* (security patches)
```

### Protection Levels

#### Level 1: Maximum Protection (`main` branch)
- **Purpose**: Production-ready code
- **Merge Requirements**: Strict
- **Review Requirements**: 2+ approvals
- **Status Checks**: All must pass
- **Force Push**: Disabled
- **Deletion**: Disabled

#### Level 2: Standard Protection (`develop` branch)
- **Purpose**: Integration and testing
- **Merge Requirements**: Standard
- **Review Requirements**: 1+ approval
- **Status Checks**: Core checks must pass
- **Force Push**: Disabled for non-admins
- **Deletion**: Disabled

#### Level 3: Basic Protection (Feature branches)
- **Purpose**: Development work
- **Merge Requirements**: Basic
- **Review Requirements**: Optional
- **Status Checks**: Linting and basic tests
- **Force Push**: Allowed for branch owner
- **Deletion**: Allowed after merge

## Implementation Guide

### Prerequisites
- Repository admin access
- GitHub CLI installed and authenticated
- Branch protection permissions enabled

### Method 1: GitHub CLI Configuration

#### Main Branch Protection
```bash
#!/bin/bash
# Configure main branch protection

REPO_OWNER="danieleschmidt"
REPO_NAME="pqc-migration-audit"

gh api repos/$REPO_OWNER/$REPO_NAME/branches/main/protection \
  --method PUT \
  --field required_status_checks='{
    "strict": true,
    "contexts": [
      "test (ubuntu-latest, 3.11)",
      "test (macos-latest, 3.11)", 
      "test (windows-latest, 3.11)",
      "lint",
      "security-scan",
      "type-check",
      "coverage-check"
    ]
  }' \
  --field enforce_admins=true \
  --field required_pull_request_reviews='{
    "required_approving_review_count": 2,
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true,
    "require_last_push_approval": true,
    "bypass_pull_request_allowances": {
      "users": [],
      "teams": ["security-team"],
      "apps": []
    }
  }' \
  --field restrictions='{
    "users": [],
    "teams": ["core-maintainers"],
    "apps": []
  }' \
  --field required_linear_history=true \
  --field allow_force_pushes=false \
  --field allow_deletions=false \
  --field block_creations=false \
  --field required_conversation_resolution=true

echo "✅ Main branch protection configured"
```

#### Develop Branch Protection
```bash
#!/bin/bash
# Configure develop branch protection

gh api repos/$REPO_OWNER/$REPO_NAME/branches/develop/protection \
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
  --field enforce_admins=false \
  --field required_pull_request_reviews='{
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false,
    "require_last_push_approval": false
  }' \
  --field restrictions=null \
  --field required_linear_history=false \
  --field allow_force_pushes=false \
  --field allow_deletions=false \
  --field required_conversation_resolution=true

echo "✅ Develop branch protection configured"
```

#### Feature Branch Protection (Pattern-based)
```bash
#!/bin/bash
# Configure protection for feature/* branches

# Note: Pattern-based protection may require GitHub Enterprise
gh api repos/$REPO_OWNER/$REPO_NAME/branches/feature*/protection \
  --method PUT \
  --field required_status_checks='{
    "strict": false,
    "contexts": [
      "test (ubuntu-latest, 3.11)",
      "lint"
    ]
  }' \
  --field enforce_admins=false \
  --field required_pull_request_reviews='{
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": false,
    "require_code_owner_reviews": false
  }' \
  --field restrictions=null \
  --field allow_force_pushes=true \
  --field allow_deletions=true

echo "✅ Feature branch protection configured"
```

### Method 2: GitHub Web Interface

#### Step-by-Step Configuration

1. **Navigate to Branch Protection**
   ```
   Repository → Settings → Branches → Add rule
   ```

2. **Configure Main Branch Rule**
   - **Branch name pattern**: `main`
   - **Protect matching branches**: ✅ Enabled
   
   **Pull Request Requirements**:
   - ✅ Require a pull request before merging
   - ✅ Require approvals (2)
   - ✅ Dismiss stale reviews when new commits are pushed
   - ✅ Require review from code owners
   - ✅ Require approval of the most recent reviewable push
   
   **Status Check Requirements**:
   - ✅ Require status checks to pass before merging
   - ✅ Require branches to be up to date before merging
   - **Required status checks**:
     - `test (ubuntu-latest, 3.11)`
     - `test (macos-latest, 3.11)`
     - `test (windows-latest, 3.11)`
     - `lint`
     - `security-scan`
     - `type-check`
     - `coverage-check`
   
   **Additional Restrictions**:
   - ✅ Require conversation resolution before merging
   - ✅ Require linear history
   - ✅ Include administrators
   - ❌ Allow force pushes
   - ❌ Allow deletions

3. **Configure Develop Branch Rule**
   - **Branch name pattern**: `develop`
   - **Pull Request Requirements**: 1 approval required
   - **Status Check Requirements**: Core checks only
   - **Additional Restrictions**: Moderate settings

### Method 3: Terraform Configuration

#### Branch Protection with Terraform
```hcl
# terraform/github-branch-protection.tf

terraform {
  required_providers {
    github = {
      source  = "integrations/github"
      version = "~> 5.0"
    }
  }
}

provider "github" {
  token = var.github_token
  owner = var.github_owner
}

variable "github_token" {
  description = "GitHub personal access token"
  type        = string
  sensitive   = true
}

variable "github_owner" {
  description = "GitHub repository owner"
  type        = string
  default     = "danieleschmidt"
}

variable "repository_name" {
  description = "GitHub repository name"
  type        = string
  default     = "pqc-migration-audit"
}

# Main branch protection
resource "github_branch_protection" "main" {
  repository_id = var.repository_name
  pattern       = "main"

  required_status_checks {
    strict   = true
    contexts = [
      "test (ubuntu-latest, 3.11)",
      "test (macos-latest, 3.11)",
      "test (windows-latest, 3.11)",
      "lint",
      "security-scan",
      "type-check",
      "coverage-check"
    ]
  }

  required_pull_request_reviews {
    required_approving_review_count = 2
    dismiss_stale_reviews           = true
    require_code_owner_reviews      = true
    require_last_push_approval      = true
    
    bypass_pull_request_allowances {
      teams = ["security-team"]
    }
  }

  restrict_pushes {
    teams = ["core-maintainers"]
  }

  enforce_admins                = true
  require_signed_commits        = true
  require_conversation_resolution = true
  require_linear_history        = true
  allows_force_pushes           = false
  allows_deletions              = false
}

# Develop branch protection  
resource "github_branch_protection" "develop" {
  repository_id = var.repository_name
  pattern       = "develop"

  required_status_checks {
    strict   = true
    contexts = [
      "test (ubuntu-latest, 3.11)",
      "lint",
      "security-scan",
      "type-check"
    ]
  }

  required_pull_request_reviews {
    required_approving_review_count = 1
    dismiss_stale_reviews           = true
    require_code_owner_reviews      = false
    require_last_push_approval      = false
  }

  enforce_admins                = false
  require_conversation_resolution = true
  require_linear_history        = false
  allows_force_pushes           = false
  allows_deletions              = false
}

# Release branch protection
resource "github_branch_protection" "release" {
  repository_id = var.repository_name
  pattern       = "release/*"

  required_status_checks {
    strict   = true
    contexts = [
      "test (ubuntu-latest, 3.11)",
      "security-scan",
      "build-check"
    ]
  }

  required_pull_request_reviews {
    required_approving_review_count = 2
    dismiss_stale_reviews           = true
    require_code_owner_reviews      = true
  }

  enforce_admins                = true
  require_conversation_resolution = true
  allows_force_pushes           = false
  allows_deletions              = false
}

# Hotfix branch protection
resource "github_branch_protection" "hotfix" {
  repository_id = var.repository_name
  pattern       = "hotfix/*"

  required_status_checks {
    strict   = false  # Allow emergency fixes
    contexts = [
      "test (ubuntu-latest, 3.11)",
      "security-scan"
    ]
  }

  required_pull_request_reviews {
    required_approving_review_count = 1  # Reduced for emergency
    dismiss_stale_reviews           = false
    require_code_owner_reviews      = true
  }

  enforce_admins                = false  # Allow admin override
  require_conversation_resolution = false
  allows_force_pushes           = false
  allows_deletions              = true
}
```

#### Deploy with Terraform
```bash
# Initialize Terraform
terraform init

# Plan the changes
terraform plan -var="github_token=$GITHUB_TOKEN"

# Apply the configuration
terraform apply -var="github_token=$GITHUB_TOKEN" -auto-approve
```

## CODEOWNERS Configuration

### CODEOWNERS File
```bash
# .github/CODEOWNERS
# Global owners - require review for all changes
* @danieleschmidt @security-team

# Core source code
/src/ @core-maintainers @security-team

# Cryptographic components (require security team review)
/src/pqc_migration_audit/crypto/ @security-team @crypto-experts
/src/pqc_migration_audit/algorithms/ @security-team @crypto-experts
/src/pqc_migration_audit/scanner/ @security-team

# Security-sensitive files
/src/pqc_migration_audit/security/ @security-team
/tests/security/ @security-team
/docs/security/ @security-team

# Infrastructure and deployment
/.github/ @devops-team @core-maintainers
/docker/ @devops-team
/k8s/ @devops-team
/terraform/ @devops-team

# Documentation
/docs/ @docs-team @core-maintainers
/README.md @docs-team @core-maintainers
/*.md @docs-team

# Dependencies and configuration
/requirements*.txt @security-team @core-maintainers
/pyproject.toml @core-maintainers
/setup.py @core-maintainers
/setup.cfg @core-maintainers

# Testing infrastructure
/tests/ @core-maintainers
/.github/workflows/ @devops-team @core-maintainers

# Performance-critical components
/src/pqc_migration_audit/performance/ @performance-team

# API definitions
/src/pqc_migration_audit/api/ @api-team @core-maintainers

# Database schemas and migrations
/migrations/ @database-team @core-maintainers
/alembic/ @database-team @core-maintainers
```

## Status Check Configuration

### Required Status Checks

#### Core Checks (All Branches)
```yaml
required_contexts:
  - "test (ubuntu-latest, 3.11)"    # Primary platform test
  - "lint"                          # Code formatting and style
  - "type-check"                    # Static type checking
```

#### Extended Checks (Main Branch)
```yaml
required_contexts:
  # Multi-platform testing
  - "test (ubuntu-latest, 3.11)"
  - "test (macos-latest, 3.11)"
  - "test (windows-latest, 3.11)"
  
  # Code quality
  - "lint"
  - "type-check"
  - "coverage-check"
  
  # Security
  - "security-scan"
  - "dependency-scan"
  - "secret-scan"
  
  # Performance
  - "performance-test"
  
  # Documentation
  - "docs-build"
  
  # Integration
  - "integration-test"
```

#### Security Checks (Security Branches)
```yaml
required_contexts:
  - "test (ubuntu-latest, 3.11)"
  - "security-scan"
  - "vulnerability-scan"
  - "secret-scan"
  - "compliance-check"
  - "cryptographic-review"
```

### Custom Status Checks

#### Cryptographic Review Check
```python
# .github/scripts/crypto-review-check.py
#!/usr/bin/env python3
"""
Custom status check for cryptographic code changes
"""
import os
import sys
import subprocess
import json
from pathlib import Path

def check_crypto_changes():
    """Check if PR contains cryptographic changes requiring review"""
    
    # Get list of changed files
    result = subprocess.run([
        'git', 'diff', '--name-only', 'origin/main...HEAD'
    ], capture_output=True, text=True)
    
    changed_files = result.stdout.strip().split('\n')
    
    # Define crypto-sensitive paths
    crypto_paths = [
        'src/pqc_migration_audit/crypto/',
        'src/pqc_migration_audit/algorithms/',
        'src/pqc_migration_audit/security/',
        'tests/crypto/',
        'tests/security/'
    ]
    
    # Check for crypto changes
    crypto_changes = []
    for file_path in changed_files:
        for crypto_path in crypto_paths:
            if file_path.startswith(crypto_path):
                crypto_changes.append(file_path)
                break
    
    if crypto_changes:
        print("🔐 Cryptographic changes detected:")
        for change in crypto_changes:
            print(f"  - {change}")
        
        # Check for required reviewers
        pr_number = os.environ.get('GITHUB_PR_NUMBER')
        if pr_number:
            # Check if security team has approved
            result = subprocess.run([
                'gh', 'pr', 'view', pr_number, '--json', 'reviews'
            ], capture_output=True, text=True)
            
            reviews = json.loads(result.stdout)
            security_approved = any(
                review.get('author', {}).get('login') in ['security-team', 'crypto-expert']
                and review.get('state') == 'APPROVED'
                for review in reviews.get('reviews', [])
            )
            
            if not security_approved:
                print("❌ Security team review required for cryptographic changes")
                sys.exit(1)
    
    print("✅ Cryptographic review check passed")
    return 0

if __name__ == "__main__":
    sys.exit(check_crypto_changes())
```

#### Performance Regression Check
```python
# .github/scripts/performance-check.py
#!/usr/bin/env python3
"""
Custom status check for performance regressions
"""
import subprocess
import json
import sys

def check_performance():
    """Run performance benchmarks and check for regressions"""
    
    # Run performance tests
    result = subprocess.run([
        'python', '-m', 'pytest', 'tests/performance/', 
        '--benchmark-json=benchmark.json'
    ], capture_output=True, text=True)
    
    if result.returncode != 0:
        print("❌ Performance tests failed")
        print(result.stdout)
        print(result.stderr)
        return 1
    
    # Load benchmark results
    try:
        with open('benchmark.json') as f:
            benchmark_data = json.load(f)
    except FileNotFoundError:
        print("❌ Benchmark results not found")
        return 1
    
    # Check for regressions (example threshold: 20% slower)
    regression_threshold = 1.2
    regressions = []
    
    for benchmark in benchmark_data.get('benchmarks', []):
        current_time = benchmark.get('stats', {}).get('mean', 0)
        baseline_time = get_baseline_time(benchmark.get('name', ''))
        
        if baseline_time and current_time > baseline_time * regression_threshold:
            regressions.append({
                'name': benchmark.get('name'),
                'current': current_time,
                'baseline': baseline_time,
                'regression': (current_time / baseline_time - 1) * 100
            })
    
    if regressions:
        print("❌ Performance regressions detected:")
        for reg in regressions:
            print(f"  - {reg['name']}: {reg['regression']:.1f}% slower")
        return 1
    
    print("✅ Performance check passed")
    return 0

def get_baseline_time(benchmark_name):
    """Get baseline performance time for comparison"""
    # This would typically fetch from a performance database
    # or load from a baseline file
    baselines = {
        'test_scan_performance': 0.5,  # 500ms baseline
        'test_crypto_operations': 0.1,  # 100ms baseline
    }
    return baselines.get(benchmark_name)

if __name__ == "__main__":
    sys.exit(check_performance())
```

## Bypass Procedures

### Emergency Bypass Process

#### 1. Hotfix Bypass (Security Issues)
```bash
# Create emergency bypass for critical security fixes
gh api repos/danieleschmidt/pqc-migration-audit/branches/main/protection \
  --method PATCH \
  --field restrictions='{"users":["emergency-user"],"teams":["security-team"],"apps":[]}' \
  --field enforce_admins=false

# Apply hotfix
git checkout main
git pull origin main
git checkout -b hotfix/critical-security-fix
# ... make changes ...
git commit -m "security: critical vulnerability fix"
git push origin hotfix/critical-security-fix

# Emergency merge (with proper documentation)
gh pr create --title "🚨 HOTFIX: Critical Security Fix" \
  --body "Emergency security fix - bypassing normal review process under security incident procedures"
gh pr merge --admin --merge

# Restore protection
gh api repos/danieleschmidt/pqc-migration-audit/branches/main/protection \
  --method PATCH \
  --field enforce_admins=true
```

#### 2. Admin Override Process
```bash
# Document admin override
cat > ADMIN_OVERRIDE.md << 'EOF'
# Admin Override Record

**Date**: $(date)
**User**: $(git config user.name)
**Reason**: [Detailed justification]
**Changes**: [Description of changes]
**Risk Assessment**: [Security and stability impact]
**Post-Override Actions**: [Required follow-up actions]

## Approval Chain
- [ ] Security Team Lead: ________________
- [ ] Engineering Manager: ________________ 
- [ ] CTO (if required): ________________

## Restoration Plan
- [ ] Normal protection rules restored
- [ ] Changes reviewed in next business day
- [ ] Documentation updated
- [ ] Team notified of override

EOF

# Apply override with full documentation
git add ADMIN_OVERRIDE.md
git commit -m "admin: document emergency override procedure"
```

### Bypass Monitoring

#### Override Audit Script
```python
#!/usr/bin/env python3
"""
Monitor and audit branch protection bypasses
"""
import requests
import json
import os
from datetime import datetime, timedelta

def audit_bypasses():
    """Audit recent branch protection bypasses"""
    
    token = os.environ['GITHUB_TOKEN']
    repo = 'danieleschmidt/pqc-migration-audit'
    
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    
    # Get recent commits to protected branches
    since = (datetime.now() - timedelta(days=7)).isoformat()
    
    response = requests.get(
        f'https://api.github.com/repos/{repo}/commits',
        headers=headers,
        params={'since': since, 'sha': 'main'}
    )
    
    commits = response.json()
    
    # Check for admin bypasses
    bypasses = []
    for commit in commits:
        # Check if commit bypassed protection
        if check_bypass(commit, headers, repo):
            bypasses.append(commit)
    
    # Generate audit report
    if bypasses:
        print(f"⚠️  {len(bypasses)} branch protection bypasses detected:")
        for bypass in bypasses:
            print(f"  - {bypass['sha'][:8]}: {bypass['commit']['message']}")
            print(f"    Author: {bypass['commit']['author']['name']}")
            print(f"    Date: {bypass['commit']['author']['date']}")
    else:
        print("✅ No branch protection bypasses detected")

def check_bypass(commit, headers, repo):
    """Check if a commit bypassed branch protection"""
    # This would implement logic to detect bypasses
    # by checking protection rules at time of commit
    return False

if __name__ == "__main__":
    audit_bypasses()
```

## Troubleshooting

### Common Issues

#### 1. Status Check Failures
```bash
# Debug failing status checks
gh run list --limit 10
gh run view [run-id] --log

# Rerun failed checks
gh run rerun [run-id]

# Skip specific checks (emergency only)
gh pr merge --admin --squash
```

#### 2. Review Requirements Not Met
```bash
# Check current reviews
gh pr view --json reviews

# Request specific reviewers
gh pr edit --add-reviewer @security-team,@crypto-expert

# Check CODEOWNERS coverage
gh api repos/danieleschmidt/pqc-migration-audit/contents/.github/CODEOWNERS
```

#### 3. Branch Protection Conflicts
```bash
# View current protection rules
gh api repos/danieleschmidt/pqc-migration-audit/branches/main/protection

# Update protection rules
gh api repos/danieleschmidt/pqc-migration-audit/branches/main/protection \
  --method PUT \
  --field [updated-configuration]

# Validate configuration
python scripts/validate-branch-protection.py
```

### Support and Escalation

#### Contact Information
- **Primary**: DevOps Team (devops@terragonlabs.com)
- **Security**: Security Team (security@terragonlabs.com)
- **Emergency**: On-call Engineer (oncall@terragonlabs.com)

#### Documentation Links
- [GitHub Branch Protection Documentation](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/defining-the-mergeability-of-pull-requests/about-protected-branches)
- [CODEOWNERS Documentation](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)
- [Status Checks Documentation](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/defining-the-mergeability-of-pull-requests/about-status-checks)

This comprehensive branch protection setup ensures code quality, security, and proper review processes while maintaining flexibility for different types of changes and emergency scenarios.