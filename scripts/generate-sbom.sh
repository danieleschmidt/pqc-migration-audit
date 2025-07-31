#!/bin/bash
# SBOM Generation Script for PQC Migration Audit
set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SBOM_DIR="$PROJECT_ROOT/sbom"
VERSION="${VERSION:-$(python -m setuptools_scm)}"

# Create SBOM directory
mkdir -p "$SBOM_DIR"

echo "🔍 Generating SBOM for pqc-migration-audit v$VERSION"

# Generate SBOM using syft (recommended)
if command -v syft >/dev/null 2>&1; then
    echo "📦 Using Syft to generate SBOM..."
    
    # SPDX format
    syft "$PROJECT_ROOT" \
        -o spdx-json="$SBOM_DIR/sbom.spdx.json" \
        --config "$PROJECT_ROOT/sbom-config.yml"
    
    # CycloneDX format  
    syft "$PROJECT_ROOT" \
        -o cyclonedx-json="$SBOM_DIR/sbom.cyclonedx.json" \
        --config "$PROJECT_ROOT/sbom-config.yml"
        
    echo "✅ Syft SBOM generation complete"
fi

# Alternative: Generate using python-sbom
if command -v python-sbom >/dev/null 2>&1; then
    echo "🐍 Using python-sbom as fallback..."
    
    python-sbom \
        --input-dir "$PROJECT_ROOT" \
        --output-file "$SBOM_DIR/sbom-python.spdx.json" \
        --format spdx
        
    echo "✅ Python SBOM generation complete"
fi

# Generate dependency tree for analysis
if [[ -f "$PROJECT_ROOT/pyproject.toml" ]]; then
    echo "🌳 Generating dependency tree..."
    
    pip-tree --json-tree > "$SBOM_DIR/dependency-tree.json"
    pip-tree > "$SBOM_DIR/dependency-tree.txt"
    
    echo "✅ Dependency tree generated"
fi

# Validate SBOM files
echo "🔍 Validating SBOM files..."

for sbom_file in "$SBOM_DIR"/*.json; do
    if [[ -f "$sbom_file" ]]; then
        echo "Validating: $(basename "$sbom_file")"
        
        # Basic JSON validation
        if ! python -m json.tool "$sbom_file" >/dev/null; then
            echo "❌ Invalid JSON: $sbom_file"
            exit 1
        fi
        
        # Check required SPDX fields
        if [[ "$sbom_file" == *"spdx"* ]]; then
            if ! grep -q "spdxVersion" "$sbom_file"; then
                echo "⚠️  Missing spdxVersion in $sbom_file"
            fi
        fi
    fi
done

echo "✅ SBOM validation complete"

# Generate SBOM summary report
echo "📊 Generating SBOM summary..."

cat > "$SBOM_DIR/README.md" << EOF
# Software Bill of Materials (SBOM)

Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Version: $VERSION
Format: SPDX 2.3, CycloneDX

## Files

- \`sbom.spdx.json\`: SPDX format SBOM
- \`sbom.cyclonedx.json\`: CycloneDX format SBOM  
- \`dependency-tree.json\`: Dependency analysis
- \`dependency-tree.txt\`: Human-readable dependency tree

## Usage

### Vulnerability Scanning
\`\`\`bash
grype sbom:sbom.spdx.json
trivy sbom sbom.cyclonedx.json
\`\`\`

### License Analysis
\`\`\`bash
fossa analyze --endpoint-type sbom --endpoint sbom.spdx.json
\`\`\`

### Supply Chain Risk Assessment
\`\`\`bash
osv-scanner --sbom sbom.spdx.json
\`\`\`

## Cryptographic Dependencies

This SBOM includes cryptographic packages that require special attention:
- cryptography
- hashlib (built-in)
- hmac (built-in)

Review these dependencies for post-quantum readiness.
EOF

echo "📄 SBOM summary generated: $SBOM_DIR/README.md"
echo "🎉 SBOM generation complete!"
echo "📂 Output directory: $SBOM_DIR"