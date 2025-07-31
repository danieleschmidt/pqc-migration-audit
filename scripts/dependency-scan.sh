#!/bin/bash
# Comprehensive dependency scanning script for PQC Migration Audit
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
REPORTS_DIR="$PROJECT_ROOT/security-reports"

# Create reports directory
mkdir -p "$REPORTS_DIR"

echo "🔍 Starting comprehensive dependency security scan..."

# 1. Safety - Python vulnerability scanning
echo "📦 Running Safety vulnerability scan..."
if command -v safety >/dev/null 2>&1; then
    safety check \
        --json \
        --output "$REPORTS_DIR/safety-report.json" \
        --policy-file "$PROJECT_ROOT/.safety-policy.yml" || true
    
    safety check \
        --output "$REPORTS_DIR/safety-report.txt" || true
    
    echo "✅ Safety scan complete"
else
    echo "⚠️  Safety not installed, skipping Python vulnerability scan"
fi

# 2. Pip-audit - Alternative Python vulnerability scanner
echo "🔍 Running pip-audit scan..."
if command -v pip-audit >/dev/null 2>&1; then
    pip-audit \
        --format=json \
        --output="$REPORTS_DIR/pip-audit-report.json" \
        --requirement="$PROJECT_ROOT/requirements.txt" || true
    
    pip-audit \
        --format=cyclonedx-json \
        --output="$REPORTS_DIR/pip-audit-sbom.json" \
        --requirement="$PROJECT_ROOT/requirements.txt" || true
    
    echo "✅ Pip-audit scan complete"
else
    echo "⚠️  pip-audit not installed, installing..."
    pip install pip-audit
fi

# 3. OSV-Scanner - Multi-ecosystem vulnerability scanning
echo "🌐 Running OSV vulnerability scan..."
if command -v osv-scanner >/dev/null 2>&1; then
    osv-scanner \
        --format json \
        --output "$REPORTS_DIR/osv-report.json" \
        "$PROJECT_ROOT" || true
    
    echo "✅ OSV scan complete"
else
    echo "⚠️  OSV-scanner not found, downloading..."
    # Download latest release for Linux
    curl -L -o /tmp/osv-scanner https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64
    chmod +x /tmp/osv-scanner
    /tmp/osv-scanner \
        --format json \
        --output "$REPORTS_DIR/osv-report.json" \
        "$PROJECT_ROOT" || true
fi

# 4. License compatibility check
echo "📄 Checking license compatibility..."
if command -v pip-licenses >/dev/null 2>&1; then
    pip-licenses \
        --format=json \
        --output-file="$REPORTS_DIR/license-report.json" || true
    
    pip-licenses \
        --format=csv \
        --output-file="$REPORTS_DIR/license-report.csv" || true
    
    echo "✅ License scan complete"
else
    echo "⚠️  pip-licenses not installed"
    pip install pip-licenses
fi

# 5. Dependency tree analysis
echo "🌳 Analyzing dependency tree..."
if command -v pipdeptree >/dev/null 2>&1; then
    pipdeptree --json > "$REPORTS_DIR/dependency-tree.json"
    pipdeptree --graph-output png > "$REPORTS_DIR/dependency-graph.png" || true
    
    echo "✅ Dependency analysis complete"
else
    echo "⚠️  pipdeptree not installed"
    pip install pipdeptree
fi

# 6. Cryptographic library specific checks
echo "🔐 Performing cryptographic library analysis..."
python3 << 'EOF'
import json
import pkg_resources
import sys
from pathlib import Path

# Cryptographic packages to monitor
CRYPTO_PACKAGES = [
    'cryptography', 'pycryptodome', 'pyopenssl', 'paramiko',
    'pycrypto', 'm2crypto', 'pynacl', 'bcrypt', 'cryptg'
]

# Quantum-vulnerable packages (for awareness)
QUANTUM_VULNERABLE = [
    'rsa', 'ecdsa', 'dsa', 'ecc'
]

installed_crypto = []
vulnerable_crypto = []

for pkg_name in CRYPTO_PACKAGES + QUANTUM_VULNERABLE:
    try:
        pkg = pkg_resources.get_distribution(pkg_name)
        package_info = {
            'name': pkg.project_name,
            'version': pkg.version,
            'location': pkg.location,
            'quantum_vulnerable': pkg_name in QUANTUM_VULNERABLE
        }
        
        if pkg_name in QUANTUM_VULNERABLE:
            vulnerable_crypto.append(package_info)
        else:
            installed_crypto.append(package_info)
            
    except pkg_resources.DistributionNotFound:
        continue

# Generate crypto analysis report
report = {
    'timestamp': str(datetime.now() if 'datetime' in globals() else 'unknown'),
    'cryptographic_packages': installed_crypto,
    'quantum_vulnerable_packages': vulnerable_crypto,
    'recommendations': [
        'Review quantum-vulnerable packages for post-quantum alternatives',
        'Ensure cryptographic packages are up-to-date',
        'Consider migration timeline for quantum-resistant algorithms'
    ]
}

reports_dir = Path(sys.argv[0]).parent.parent / 'security-reports'
with open(reports_dir / 'crypto-analysis.json', 'w') as f:
    json.dump(report, f, indent=2)

print(f"📊 Found {len(installed_crypto)} cryptographic packages")
print(f"⚠️  Found {len(vulnerable_crypto)} potentially quantum-vulnerable packages")
EOF

# 7. Generate summary report
echo "📊 Generating summary report..."
cat > "$REPORTS_DIR/scan-summary.md" << EOF
# Dependency Security Scan Summary

**Scan Date**: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
**Project**: PQC Migration Audit Tool

## Scan Results

### Safety (Python Vulnerabilities)
- Report: [safety-report.json](./safety-report.json)
- Text Report: [safety-report.txt](./safety-report.txt)

### Pip-audit (Alternative Python Scanner)  
- Report: [pip-audit-report.json](./pip-audit-report.json)
- SBOM: [pip-audit-sbom.json](./pip-audit-sbom.json)

### OSV Scanner (Multi-ecosystem)
- Report: [osv-report.json](./osv-report.json)

### License Analysis
- JSON Report: [license-report.json](./license-report.json)
- CSV Report: [license-report.csv](./license-report.csv)

### Dependency Analysis
- Tree: [dependency-tree.json](./dependency-tree.json)
- Graph: [dependency-graph.png](./dependency-graph.png)

### Cryptographic Package Analysis
- Report: [crypto-analysis.json](./crypto-analysis.json)

## Next Steps

1. Review all HIGH and CRITICAL vulnerabilities
2. Update affected packages where possible
3. Assess quantum-vulnerable dependencies
4. Plan migration to post-quantum alternatives
5. Schedule regular scans (weekly recommended)

## Tools Used

- Safety: Python vulnerability database
- pip-audit: PyPI vulnerability scanner
- OSV-Scanner: Open Source Vulnerabilities
- pip-licenses: License compatibility
- pipdeptree: Dependency analysis
- Custom crypto analysis

EOF

echo "✅ All dependency scans complete!"
echo "📂 Reports saved to: $REPORTS_DIR"
echo "📄 Summary available: $REPORTS_DIR/scan-summary.md"

# Check for critical issues
if [ -f "$REPORTS_DIR/safety-report.json" ]; then
    CRITICAL_COUNT=$(jq '[.vulnerabilities[] | select(.severity == "critical")] | length' "$REPORTS_DIR/safety-report.json" 2>/dev/null || echo "0")
    HIGH_COUNT=$(jq '[.vulnerabilities[] | select(.severity == "high")] | length' "$REPORTS_DIR/safety-report.json" 2>/dev/null || echo "0")
    
    if [ "$CRITICAL_COUNT" -gt 0 ] || [ "$HIGH_COUNT" -gt 0 ]; then
        echo "🚨 Found $CRITICAL_COUNT critical and $HIGH_COUNT high severity vulnerabilities!"
        echo "Please review the reports and take immediate action."
        exit 1
    fi
fi

echo "🎉 No critical security issues found in dependencies!"