#!/bin/bash
# Container security scanning script for PQC Migration Audit
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
REPORTS_DIR="$PROJECT_ROOT/security-reports/container"
IMAGE_NAME="pqc-migration-audit"
IMAGE_TAG="${1:-latest}"
FULL_IMAGE="$IMAGE_NAME:$IMAGE_TAG"

# Create reports directory
mkdir -p "$REPORTS_DIR"

echo "🔍 Starting container security scan for $FULL_IMAGE"

# Ensure image exists
if ! docker image inspect "$FULL_IMAGE" >/dev/null 2>&1; then
    echo "❌ Image $FULL_IMAGE not found. Building..."
    docker build -t "$FULL_IMAGE" "$PROJECT_ROOT"
fi

# 1. Trivy vulnerability scanning
echo "📦 Running Trivy vulnerability scan..."
if command -v trivy >/dev/null 2>&1; then
    # Vulnerabilities in JSON format
    trivy image \
        --format json \
        --output "$REPORTS_DIR/trivy-vulnerabilities.json" \
        "$FULL_IMAGE" || true
    
    # Human-readable report
    trivy image \
        --format table \
        --output "$REPORTS_DIR/trivy-vulnerabilities.txt" \
        "$FULL_IMAGE" || true
    
    # SARIF format for GitHub integration
    trivy image \
        --format sarif \
        --output "$REPORTS_DIR/trivy-vulnerabilities.sarif" \
        "$FULL_IMAGE" || true
    
    echo "✅ Trivy vulnerability scan complete"
else
    echo "⚠️  Trivy not installed, installing..."
    # Install Trivy (Ubuntu/Debian)
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
    echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
    sudo apt-get update
    sudo apt-get install trivy
fi

# 2. Trivy configuration scanning
echo "⚙️ Running Trivy configuration scan..."
trivy config \
    --format json \
    --output "$REPORTS_DIR/trivy-config.json" \
    "$PROJECT_ROOT/Dockerfile" || true

trivy config \
    --format table \
    --output "$REPORTS_DIR/trivy-config.txt" \
    "$PROJECT_ROOT/Dockerfile" || true

echo "✅ Trivy configuration scan complete"

# 3. Grype vulnerability scanning
echo "🔎 Running Grype scan..."
if command -v grype >/dev/null 2>&1; then
    grype "$FULL_IMAGE" \
        -o json \
        --file "$REPORTS_DIR/grype-results.json" || true
    
    grype "$FULL_IMAGE" \
        -o table \
        --file "$REPORTS_DIR/grype-results.txt" || true
    
    echo "✅ Grype scan complete"
else
    echo "⚠️  Grype not installed, installing..."
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
fi

# 4. Docker Scout scanning (if available)
echo "🐋 Running Docker Scout scan..."
if command -v docker >/dev/null 2>&1 && docker scout version >/dev/null 2>&1; then
    docker scout cves "$FULL_IMAGE" \
        --format json \
        --output "$REPORTS_DIR/docker-scout.json" || true
    
    docker scout recommendations "$FULL_IMAGE" \
        --format json \
        --output "$REPORTS_DIR/docker-scout-recommendations.json" || true
    
    echo "✅ Docker Scout scan complete"
else
    echo "⚠️  Docker Scout not available"
fi

# 5. Container structure analysis
echo "🏗️ Running container structure analysis..."
if command -v container-structure-test >/dev/null 2>&1; then
    # Create basic structure test config
    cat > /tmp/container-test.yaml << EOF
schemaVersion: '2.0.0'
commandTests:
  - name: "Check non-root user"
    command: "whoami"
    expectedOutput: ["pqcaudit"]
  - name: "Check Python version"
    command: "python"
    args: ["--version"]
    expectedOutput: ["Python 3.11.*"]
fileExistenceTests:
  - name: "Check application exists"
    path: "/usr/local/bin/pqc-audit"
    shouldExist: true
    permissions: "-rwxr-xr-x"
metadataTest:
  user: "pqcaudit"
  workdir: "/workspace"
EOF

    container-structure-test test \
        --image "$FULL_IMAGE" \
        --config /tmp/container-test.yaml \
        --output "$REPORTS_DIR/structure-test.json" || true
    
    echo "✅ Container structure test complete"
else
    echo "⚠️  container-structure-test not available"
fi

# 6. Security best practices check
echo "🔒 Running security best practices check..."
python3 << 'EOF'
import docker
import json
import sys
from pathlib import Path

try:
    client = docker.from_env()
    image_name = sys.argv[1] if len(sys.argv) > 1 else "pqc-migration-audit:latest"
    
    # Get image details
    image = client.images.get(image_name)
    config = image.attrs['Config']
    
    security_checks = {
        'timestamp': str(datetime.now() if 'datetime' in globals() else 'unknown'),
        'image': image_name,
        'checks': []
    }
    
    # Check if running as root
    user = config.get('User', 'root')
    security_checks['checks'].append({
        'name': 'Non-root user',
        'status': 'PASS' if user != 'root' else 'FAIL',
        'details': f'Running as user: {user}',
        'severity': 'HIGH' if user == 'root' else 'INFO'
    })
    
    # Check for exposed ports
    exposed_ports = config.get('ExposedPorts', {})
    security_checks['checks'].append({
        'name': 'Minimal port exposure',
        'status': 'PASS' if len(exposed_ports) <= 1 else 'WARN',
        'details': f'Exposed ports: {list(exposed_ports.keys())}',
        'severity': 'MEDIUM' if len(exposed_ports) > 1 else 'LOW'
    })
    
    # Check for secrets in environment variables
    env_vars = config.get('Env', [])
    secret_patterns = ['password', 'secret', 'key', 'token', 'api']
    potential_secrets = []
    
    for env_var in env_vars:
        if '=' in env_var:
            key, value = env_var.split('=', 1)
            if any(pattern.lower() in key.lower() for pattern in secret_patterns):
                potential_secrets.append(key)
    
    security_checks['checks'].append({
        'name': 'Environment variable secrets',
        'status': 'PASS' if not potential_secrets else 'WARN',
        'details': f'Potential secrets in env vars: {potential_secrets}',
        'severity': 'HIGH' if potential_secrets else 'INFO'
    })
    
    # Save results
    reports_dir = Path('security-reports/container')
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    with open(reports_dir / 'security-checks.json', 'w') as f:
        json.dump(security_checks, f, indent=2)
    
    # Print summary
    failed_checks = [c for c in security_checks['checks'] if c['status'] == 'FAIL']
    warned_checks = [c for c in security_checks['checks'] if c['status'] == 'WARN']
    
    print(f"✅ Security best practices check complete")
    print(f"📊 {len(failed_checks)} failures, {len(warned_checks)} warnings")
    
    if failed_checks:
        for check in failed_checks:
            print(f"❌ {check['name']}: {check['details']}")
    
except Exception as e:
    print(f"⚠️  Error during security check: {e}")
EOF "$FULL_IMAGE"

# 7. Generate comprehensive report
echo "📊 Generating comprehensive security report..."
cat > "$REPORTS_DIR/security-summary.md" << EOF
# Container Security Scan Report

**Image**: $FULL_IMAGE  
**Scan Date**: $(date -u +"%Y-%m-%d %H:%M:%S UTC")

## Scan Results Overview

### Vulnerability Scanning
- **Trivy**: [trivy-vulnerabilities.json](./trivy-vulnerabilities.json)
- **Grype**: [grype-results.json](./grype-results.json)
- **Docker Scout**: [docker-scout.json](./docker-scout.json)

### Configuration Analysis
- **Trivy Config**: [trivy-config.json](./trivy-config.json)
- **Structure Test**: [structure-test.json](./structure-test.json)
- **Security Checks**: [security-checks.json](./security-checks.json)

## Quick Analysis

### Critical Issues
$(if [ -f "$REPORTS_DIR/trivy-vulnerabilities.json" ]; then
    python3 -c "
import json
try:
    with open('$REPORTS_DIR/trivy-vulnerabilities.json') as f:
        data = json.load(f)
        if 'Results' in data:
            critical = sum(1 for result in data['Results'] or [] for vuln in result.get('Vulnerabilities', []) if vuln.get('Severity') == 'CRITICAL')
            high = sum(1 for result in data['Results'] or [] for vuln in result.get('Vulnerabilities', []) if vuln.get('Severity') == 'HIGH')
            print(f'- **Critical**: {critical} vulnerabilities')
            print(f'- **High**: {high} vulnerabilities')
        else:
            print('- No vulnerabilities found')
except:
    print('- Unable to parse vulnerability data')
"
else
    echo "- Vulnerability data not available"
fi)

### Recommendations

1. **Update Base Image**: Regularly update to latest security patches
2. **Minimize Attack Surface**: Remove unnecessary packages and files
3. **Security Scanning**: Integrate into CI/CD pipeline
4. **Runtime Security**: Implement runtime monitoring
5. **Network Policies**: Restrict network access

## Next Steps

1. Review all HIGH and CRITICAL vulnerabilities
2. Update vulnerable packages where possible
3. Implement additional security hardening
4. Schedule regular security scans
5. Monitor for new vulnerabilities

## Tools Used

- **Trivy**: Vulnerability and configuration scanning
- **Grype**: Alternative vulnerability scanner
- **Docker Scout**: Native Docker security analysis
- **Container Structure Test**: Configuration validation
- **Custom Security Checks**: Best practices validation

EOF

# 8. Security assessment summary
echo "🎯 Performing final security assessment..."

# Count critical/high vulnerabilities
CRITICAL_COUNT=0
HIGH_COUNT=0

if [ -f "$REPORTS_DIR/trivy-vulnerabilities.json" ]; then
    CRITICAL_COUNT=$(python3 -c "
import json
try:
    with open('$REPORTS_DIR/trivy-vulnerabilities.json') as f:
        data = json.load(f)
        if 'Results' in data:
            print(sum(1 for result in data['Results'] or [] for vuln in result.get('Vulnerabilities', []) if vuln.get('Severity') == 'CRITICAL'))
        else:
            print(0)
except:
    print(0)
" 2>/dev/null || echo "0")

    HIGH_COUNT=$(python3 -c "
import json
try:
    with open('$REPORTS_DIR/trivy-vulnerabilities.json') as f:
        data = json.load(f)
        if 'Results' in data:
            print(sum(1 for result in data['Results'] or [] for vuln in result.get('Vulnerabilities', []) if vuln.get('Severity') == 'HIGH'))
        else:
            print(0)
except:
    print(0)
" 2>/dev/null || echo "0")
fi

echo "✅ Container security scan complete!"
echo "📂 Reports saved to: $REPORTS_DIR"
echo "📄 Summary available: $REPORTS_DIR/security-summary.md"
echo "📊 Found $CRITICAL_COUNT critical and $HIGH_COUNT high severity vulnerabilities"

# Exit with error if critical vulnerabilities found
if [ "$CRITICAL_COUNT" -gt 0 ]; then
    echo "🚨 Critical vulnerabilities found! Please review and remediate immediately."
    exit 1
elif [ "$HIGH_COUNT" -gt 0 ]; then
    echo "⚠️  High severity vulnerabilities found. Please review and plan remediation."
    exit 0
else
    echo "🎉 No critical or high severity vulnerabilities found!"
    exit 0
fi