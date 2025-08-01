# Test Fixtures

This directory contains test fixtures and sample data for the PQC Migration Audit test suite.

## Directory Structure

```
fixtures/
├── README.md                    # This file
├── sample_repositories/         # Complete sample repositories for testing
│   ├── vulnerable_python/       # Python code with quantum-vulnerable crypto
│   ├── vulnerable_java/         # Java code with quantum-vulnerable crypto
│   ├── mixed_languages/         # Multi-language repository
│   └── secure_pqc/             # Post-quantum secure implementations
├── code_samples/               # Individual code samples
│   ├── python/                 # Python crypto patterns
│   ├── java/                   # Java crypto patterns
│   ├── go/                     # Go crypto patterns
│   └── javascript/             # JavaScript crypto patterns
├── configuration_files/        # Sample configuration files
│   ├── ssl_configs/           # SSL/TLS configurations
│   ├── certificates/          # Sample certificates and keys
│   └── crypto_configs/        # Cryptographic library configurations
├── expected_results/           # Expected scan results for validation
│   ├── vulnerability_reports/  # Expected vulnerability findings
│   ├── risk_assessments/      # Expected risk assessment outputs
│   └── patch_suggestions/     # Expected patch recommendations
└── test_data/                 # Structured test data
    ├── algorithms.json        # Algorithm test data
    ├── libraries.json         # Library patterns test data
    └── patterns.yaml          # Vulnerability patterns test data
```

## Usage Guidelines

### Sample Repositories
- Complete, realistic codebases for integration testing
- Include common patterns found in real-world applications
- Cover multiple programming languages and frameworks
- Include both vulnerable and secure implementations

### Code Samples
- Focused, minimal examples for unit testing
- Test specific vulnerability patterns
- Include edge cases and false positive scenarios
- Organized by programming language

### Configuration Files
- Real-world configuration examples
- Cover common SSL/TLS misconfigurations
- Include certificate and key management patterns
- Test configuration file parsing logic

### Expected Results
- Ground truth data for test validation
- JSON/YAML format for easy comparison
- Include confidence scores and severity levels
- Cover all supported vulnerability types

### Test Data
- Structured data for parameterized testing
- Algorithm metadata and properties
- Library version mappings
- Pattern matching test cases

## Adding New Fixtures

1. **Sample Code**: Add to appropriate language directory
2. **Expected Results**: Include corresponding expected output
3. **Documentation**: Update this README with new fixture descriptions
4. **Tests**: Create corresponding test cases in the test suite

## Security Considerations

- All fixtures contain only synthetic, non-sensitive data
- No real private keys, certificates, or credentials
- Sample code is for testing purposes only
- Vulnerable examples are clearly marked and documented