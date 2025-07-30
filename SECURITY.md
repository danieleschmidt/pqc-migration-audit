# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**DO NOT** open public GitHub issues for security vulnerabilities.

### For Security Issues

Email: **security@terragonlabs.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Any suggested fixes

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 5 business days
- **Regular Updates**: Every 5 business days until resolved

### Disclosure Policy

- We follow **coordinated disclosure**
- Security advisories published after fixes are available
- Credit given to researchers (unless anonymity requested)

## Security Considerations

### This Tool's Purpose
PQC Migration Audit identifies cryptographic vulnerabilities in codebases. The tool itself:

- **Does NOT** store or transmit sensitive data
- **Does NOT** modify production systems
- **Generates** recommendations only
- **Requires** manual review before implementation

### Best Practices

1. **Review All Suggestions**: Never auto-apply cryptographic changes
2. **Test Thoroughly**: Validate all migrations in staging environments
3. **Backup First**: Ensure recovery options before major changes
4. **Expert Review**: Have cryptographic changes reviewed by security experts

### Known Limitations

- **Static Analysis Only**: Cannot detect runtime crypto decisions
- **False Positives**: May flag legitimate classical crypto usage
- **Dependency Scanning**: Limited to direct imports, not transitive
- **Custom Implementations**: May miss proprietary crypto libraries

## Security Features

- No network communication during scanning
- Local-only analysis and reporting
- Configurable output sanitization
- Optional audit trail logging

For questions about security practices, contact: security@terragonlabs.com