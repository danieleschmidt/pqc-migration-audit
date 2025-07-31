# SLSA (Supply-chain Levels for Software Artifacts) Compliance

## Overview

This document outlines our approach to achieving SLSA Level 3 compliance for the PQC Migration Audit tool, focusing on supply chain security and build integrity.

## SLSA Framework Summary

SLSA (Supply-chain Levels for Software Artifacts) is a security framework developed by Google to ensure the integrity of software artifacts throughout the software supply chain.

### SLSA Levels

- **SLSA 1**: Basic provenance documentation
- **SLSA 2**: Hosted build service with signed provenance  
- **SLSA 3**: Hardened build platform and stronger provenance
- **SLSA 4**: Hermetic builds with two-person review

## Current SLSA Level Assessment

### Target: SLSA Level 3

**Achieved Requirements:**
- ✅ Source code version control (Git)
- ✅ Build service (GitHub Actions)
- ✅ Provenance generation
- ✅ Non-falsifiable provenance
- ✅ Dependencies complete

**In Progress:**
- 🔄 Hermetic builds (containerized)
- 🔄 Isolated build environment
- 🔄 Parameterless builds

**Planned:**
- 📋 Build service security review
- 📋 Dependency tracking verification

## Implementation Strategy

### 1. Provenance Generation

#### Build Provenance Format
```json
{
  "buildType": "https://github.com/slsa-framework/slsa-github-generator",
  "builder": {
    "id": "https://github.com/actions/runner"
  },
  "invocation": {
    "configSource": {
      "uri": "git+https://github.com/terragonlabs/pqc-migration-audit",
      "digest": {"sha1": "commit-hash"}
    }
  },
  "metadata": {
    "buildInvocationId": "build-id",
    "buildStartedOn": "2024-01-01T00:00:00Z",
    "buildFinishedOn": "2024-01-01T00:05:00Z"
  }
}
```

#### GitHub Actions Integration
```yaml
# SLSA provenance generation workflow
- name: Generate SLSA Provenance
  uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1.9.0
  with:
    base64-subjects: ${{ needs.build.outputs.hashes }}
    provenance-name: pqc-audit-provenance.intoto.jsonl
```

### 2. Build Environment Hardening

#### Hermetic Build Requirements
- Isolated build environment (containers)
- Reproducible builds
- No network access during build
- Controlled dependency resolution
- Verified base images

#### Container Build Security
```dockerfile
# Multi-stage build for SLSA compliance
FROM python:3.11-slim@sha256:specific-digest as builder
# Pinned base image with cryptographic verification
```

### 3. Dependency Management

#### SLSA-Compliant Dependency Tracking
- Pin all dependencies with cryptographic hashes
- Verify SLSA provenance of dependencies where available
- Use lock files for reproducible builds
- Regular dependency security scanning

#### Requirements Pinning
```
# requirements-lock.txt with hashes
cryptography==41.0.7 \
    --hash=sha256:specific-hash-value
click==8.1.7 \
    --hash=sha256:specific-hash-value
```

### 4. Verification Process

#### Artifact Verification Steps
1. Verify build provenance signature
2. Validate source code integrity
3. Check dependency provenance
4. Confirm build environment isolation
5. Validate artifact checksums

#### Consumer Verification Guide
```bash
# Verify SLSA provenance
slsa-verifier verify-artifact \
  --provenance-path pqc-audit-provenance.intoto.jsonl \
  --source-uri github.com/terragonlabs/pqc-migration-audit \
  pqc-migration-audit.whl
```

## Security Controls

### Build-Time Security

#### Source Code Integrity
- **Control**: Signed commits required
- **Implementation**: GPG signatures on all commits
- **Verification**: Automated signature validation

#### Build Environment
- **Control**: Ephemeral build runners  
- **Implementation**: GitHub Actions hosted runners
- **Verification**: Build logs and provenance

#### Dependency Security
- **Control**: Vulnerability scanning
- **Implementation**: Safety, OSV-Scanner, Dependabot
- **Verification**: Automated security reports

### Runtime Security

#### Artifact Integrity
- **Control**: Cryptographic signatures
- **Implementation**: Package signing with Sigstore
- **Verification**: Consumer signature validation

#### Supply Chain Monitoring
- **Control**: Continuous monitoring
- **Implementation**: Security alerts and notifications
- **Verification**: Regular audit reports

## Compliance Monitoring

### Automated Checks

#### Daily Verification
- Source code integrity check
- Dependency vulnerability scan
- Build environment audit
- Provenance validation

#### Weekly Assessment
- SLSA level compliance review
- Security control effectiveness
- Threat model updates
- Process improvement identification

### Metrics and KPIs

#### Security Metrics
- Time to patch vulnerabilities: < 24 hours (critical)
- Provenance coverage: 100% of releases
- Build reproducibility: > 95%
- Dependency freshness: < 30 days average age

#### Compliance Metrics
- SLSA level achievement: Level 3 target
- Control implementation: > 90%
- Audit findings: < 5 per quarter
- Training completion: 100% of team

## Incident Response

### Supply Chain Compromise

#### Detection
- Automated anomaly detection
- Community vulnerability reports
- Internal security assessments
- Third-party security research

#### Response Process
1. **Immediate**: Disable affected artifacts
2. **Investigation**: Root cause analysis
3. **Containment**: Isolate compromised components
4. **Recovery**: Rebuild and re-release
5. **Communication**: Stakeholder notification

### Recovery Procedures

#### Build System Compromise
- Rotate all signing keys
- Rebuild from known-good source
- Re-verify all dependencies
- Enhanced monitoring implementation

## Tools and Integration

### SLSA Toolchain

#### Primary Tools
- **slsa-github-generator**: Provenance generation
- **slsa-verifier**: Artifact verification
- **Sigstore**: Keyless signing
- **in-toto**: Supply chain metadata

#### Integration Points
- GitHub Actions workflows
- PyPI package publishing
- Container registry publishing
- Documentation generation

### Monitoring Stack

#### Security Monitoring
- **OpenSSF Scorecard**: Security posture assessment
- **Dependabot**: Dependency monitoring
- **CodeQL**: Static analysis
- **Trivy**: Container vulnerability scanning

## Roadmap

### Phase 1: Foundation (Current)
- Basic provenance generation
- Signed releases
- Dependency tracking
- Security scanning

### Phase 2: Enhancement (Q2 2024)
- Hermetic builds
- Enhanced provenance
- Automated verification
- Improved documentation

### Phase 3: Advanced (Q3 2024)  
- SLSA Level 4 preparation
- Supply chain risk assessment
- Advanced threat detection
- Community collaboration

## References

- [SLSA Specification](https://slsa.dev/spec/v1.0/)
- [SLSA GitHub Generator](https://github.com/slsa-framework/slsa-github-generator)
- [in-toto Specification](https://in-toto.io/)
- [Sigstore Documentation](https://docs.sigstore.dev/)
- [NIST SSDF](https://csrc.nist.gov/Projects/ssdf)