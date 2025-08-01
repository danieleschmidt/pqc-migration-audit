# Testing Guide

This document provides comprehensive information about testing the PQC Migration Audit tool.

## Test Suite Overview

The test suite is organized into several categories to ensure comprehensive coverage of functionality, security, and performance:

### Test Categories

- **Unit Tests** (`tests/unit/`): Test individual components in isolation
- **Integration Tests** (`tests/integration/`): Test component interactions and workflows
- **Security Tests** (`tests/security/`): Validate security properties and attack resistance
- **Performance Tests** (`tests/performance/`): Benchmark and validate performance requirements
- **End-to-End Tests** (`tests/e2e/`): Complete user workflow validation

## Running Tests

### Basic Test Execution

```bash
# Run all tests
pytest

# Run specific test category
pytest -m unit
pytest -m integration
pytest -m security
pytest -m performance

# Run tests with coverage
pytest --cov=src/pqc_migration_audit --cov-report=html

# Run specific test file
pytest tests/unit/test_crypto_detection.py

# Run specific test function
pytest tests/unit/test_crypto_detection.py::TestCryptoDetection::test_rsa_key_generation_detection
```

### Advanced Test Options

```bash
# Run tests in parallel (requires pytest-xdist)
pytest -n auto

# Run only fast tests (exclude slow markers)
pytest -m "not slow"

# Run tests with verbose output
pytest -v --tb=short

# Run tests and generate multiple report formats
pytest --cov=src --cov-report=html --cov-report=xml --junit-xml=test-results.xml

# Run performance benchmarks
pytest -m performance --benchmark-only

# Run security tests with detailed output
pytest -m security -v --tb=long
```

## Test Configuration

### pytest.ini Configuration

The project uses a comprehensive pytest configuration in `pytest.ini`:

```ini
[tool:pytest]
testpaths = tests
python_files = test_*.py *_test.py
python_classes = Test*
python_functions = test_*

addopts = 
    --strict-markers
    --strict-config
    --cov=src/pqc_migration_audit
    --cov-report=term-missing:skip-covered
    --cov-report=html:htmlcov
    --cov-report=xml:coverage.xml
    --cov-fail-under=85
    --cov-branch
    -ra
    --tb=short
    --durations=10

markers =
    unit: Unit tests
    integration: Integration tests
    security: Security-focused tests
    performance: Performance benchmarks
    crypto: Cryptographic functionality tests
    slow: Tests that take significant time
    network: Tests requiring network access
```

### Test Markers

Tests are categorized using pytest markers:

- `@pytest.mark.unit`: Fast, isolated unit tests
- `@pytest.mark.integration`: Integration tests with dependencies
- `@pytest.mark.security`: Security validation tests
- `@pytest.mark.performance`: Performance and benchmark tests
- `@pytest.mark.crypto`: Cryptographic functionality tests
- `@pytest.mark.slow`: Tests that take significant time (>5 seconds)
- `@pytest.mark.network`: Tests requiring network access

## Test Fixtures

### Core Fixtures

```python
@pytest.fixture
def temp_repo():
    """Create a temporary repository for testing."""
    # Creates isolated temporary directory for each test

@pytest.fixture
def sample_vulnerable_code():
    """Sample code with quantum-vulnerable cryptography."""
    # Provides realistic vulnerable code samples

@pytest.fixture
def sample_secure_code():
    """Sample code with post-quantum secure cryptography."""
    # Provides PQC-secure code examples

@pytest.fixture
def sample_config_files():
    """Sample configuration files with crypto settings."""
    # SSL configs, crypto policies, etc.

@pytest.fixture
def mock_scan_results():
    """Mock scan results for testing."""
    # Pre-configured mock results for reporter testing
```

### Test Helpers

```python
# Create temporary Python files for testing
with pytest.helpers.temp_python_file(code_content) as temp_file:
    results = scanner.scan_file(temp_file)
    assert len(results) > 0
```

## Writing Tests

### Unit Test Example

```python
import pytest
from pqc_migration_audit.scanners import PythonScanner

class TestPythonScanner:
    @pytest.fixture
    def scanner(self):
        return PythonScanner()
    
    @pytest.mark.unit
    def test_rsa_detection(self, scanner, sample_vulnerable_code):
        """Test RSA vulnerability detection."""
        code = sample_vulnerable_code["rsa_key_gen.py"]
        
        with pytest.helpers.temp_python_file(code) as temp_file:
            findings = scanner.scan_file(temp_file)
            
            rsa_findings = [f for f in findings if 'rsa' in f.pattern.lower()]
            assert len(rsa_findings) > 0
            assert any('2048' in f.context for f in rsa_findings)
```

### Integration Test Example

```python
@pytest.mark.integration
def test_full_scan_workflow(self, sample_repository):
    """Test complete scanning workflow."""
    auditor = CryptoAuditor()
    results = auditor.scan_directory(sample_repository)
    
    assert len(results.vulnerabilities) > 0
    assert results.scan_stats.files_processed > 0
    assert results.risk_assessment.overall_risk_score > 0
```

### Security Test Example

```python
@pytest.mark.security
def test_path_traversal_protection(self):
    """Test protection against path traversal attacks."""
    auditor = CryptoAuditor()
    
    malicious_paths = ["../../../etc/passwd", "C:\\Windows\\System32\\config\\SAM"]
    
    for path in malicious_paths:
        try:
            results = auditor.scan_directory(path)
            assert results.scan_stats.files_processed == 0
        except (ValueError, FileNotFoundError) as e:
            pass  # Expected behavior
```

## Test Data and Fixtures

### Sample Vulnerable Code

The test suite includes realistic examples of quantum-vulnerable code:

- **RSA Key Generation**: Various key sizes and configurations
- **ECDSA Signatures**: Different curves and implementations
- **DSA Legacy**: Deprecated DSA usage patterns
- **Diffie-Hellman**: Key exchange vulnerabilities
- **Weak Cryptography**: MD5, SHA1, DES patterns
- **Configuration Files**: SSL/TLS misconfigurations

### Sample Secure Code

Post-quantum secure implementations for validation:

- **ML-KEM (Kyber)**: Key encapsulation mechanisms
- **ML-DSA (Dilithium)**: Digital signatures
- **SLH-DSA (SPHINCS+)**: Hash-based signatures
- **Secure Configurations**: PQC-ready TLS settings

## Continuous Integration

### GitHub Actions Integration

```yaml
name: Test Suite
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.8, 3.9, "3.10", 3.11, 3.12]
    
    steps:
    - uses: actions/checkout@v3
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install dependencies
      run: |
        pip install -e .[dev,test]
    
    - name: Run tests
      run: |
        pytest --cov --cov-report=xml
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
```

### Pre-commit Integration

The test suite integrates with pre-commit hooks:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: pytest-unit
        name: Run unit tests
        entry: pytest -m unit
        language: python
        pass_filenames: false
        always_run: true
```

## Performance Testing

### Benchmark Tests

```python
@pytest.mark.performance
def test_large_repository_performance(self, temp_repo):
    """Benchmark scanning performance on large repositories."""
    # Create 1000 files with crypto patterns
    for i in range(1000):
        (temp_repo / f"file_{i}.py").write_text(f"# RSA key generation\nrsa.generate_private_key(...)")
    
    import time
    start_time = time.time()
    
    auditor = CryptoAuditor()
    results = auditor.scan_directory(temp_repo)
    
    scan_time = time.time() - start_time
    
    assert scan_time < 60  # Should complete within 1 minute
    assert len(results.vulnerabilities) >= 1000
```

### Memory Usage Testing

```python
@pytest.mark.performance  
def test_memory_usage(self, large_repository):
    """Test memory usage with large codebases."""
    import psutil
    import os
    
    process = psutil.Process(os.getpid())
    memory_before = process.memory_info().rss
    
    auditor = CryptoAuditor()
    results = auditor.scan_directory(large_repository)
    
    memory_after = process.memory_info().rss
    memory_increase = memory_after - memory_before
    
    # Memory increase should be reasonable
    assert memory_increase < 500 * 1024 * 1024  # Less than 500MB
```

## Security Testing

### Input Validation Tests

```python
@pytest.mark.security
def test_malicious_input_handling(self, scanner):
    """Test handling of malicious input files."""
    malicious_inputs = [
        "x" * (10 * 1024 * 1024),  # 10MB file
        "def invalid_syntax(:\n    pass",  # Malformed syntax
        b"\x00\x01\x02\x03",  # Binary data
    ]
    
    for malicious_input in malicious_inputs:
        with pytest.helpers.temp_python_file(malicious_input) as temp_file:
            try:
                findings = scanner.scan_file(temp_file)
                assert isinstance(findings, list)
            except (ValueError, SyntaxError, UnicodeDecodeError):
                pass  # Expected for malformed input
```

### Privilege Escalation Tests

```python
@pytest.mark.security
def test_privilege_escalation_protection(self):
    """Ensure scanner doesn't escalate privileges."""
    import os
    
    if hasattr(os, 'getuid'):
        original_uid = os.getuid()
        
        auditor = CryptoAuditor()
        results = auditor.scan_directory(".")
        
        assert os.getuid() == original_uid
```

## Test Coverage

### Coverage Requirements

- **Minimum Coverage**: 85% overall
- **Critical Components**: 95% coverage required
- **Security Functions**: 100% coverage required
- **Branch Coverage**: Required for all conditional logic

### Coverage Reports

```bash
# Generate HTML coverage report
pytest --cov --cov-report=html
# Open htmlcov/index.html in browser

# Generate XML coverage for CI
pytest --cov --cov-report=xml

# Generate terminal coverage report
pytest --cov --cov-report=term-missing
```

### Coverage Configuration

```toml
# pyproject.toml
[tool.coverage.run]
source = ["src/pqc_migration_audit"]
branch = true
omit = [
    "*/tests/*",
    "*/venv/*",
    "*/__pycache__/*"
]

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "def __repr__",
    "raise AssertionError",
    "raise NotImplementedError",
    "if __name__ == .__main__.:",
]
fail_under = 85
```

## Troubleshooting Tests

### Common Issues

1. **Import Errors**: Ensure package is installed in development mode
   ```bash
   pip install -e .[dev,test]
   ```

2. **Fixture Not Found**: Check fixture is properly imported or defined in conftest.py

3. **Test Timeouts**: Use `@pytest.mark.slow` for long-running tests

4. **Permission Errors**: Ensure test temp directories have proper permissions

5. **Platform-Specific Failures**: Use `pytest.skip()` for platform-specific tests

### Debug Mode

```bash
# Run tests with Python debugger
pytest --pdb

# Run specific test with debugging
pytest --pdb tests/unit/test_crypto_detection.py::test_rsa_detection

# Capture output for debugging
pytest -s --tb=long
```

### Test Isolation

Each test should be independent and not rely on state from other tests:

```python
# Good: Each test creates its own data
def test_scanner_functionality(self, temp_repo):
    test_file = temp_repo / "test.py"
    test_file.write_text("test content")
    # Test logic here

# Bad: Tests share global state
global_test_data = {}  # Don't do this
```

## Best Practices

### Test Organization

1. **One concept per test**: Each test should validate one specific behavior
2. **Descriptive names**: Test names should clearly describe what is being tested
3. **Arrange-Act-Assert**: Structure tests with clear setup, execution, and validation
4. **Independent tests**: Tests should not depend on each other

### Test Data

1. **Use fixtures**: Prefer fixtures over hardcoded test data
2. **Realistic examples**: Use real-world code patterns in test data
3. **Edge cases**: Include boundary conditions and error cases
4. **Clean up**: Ensure temporary files and resources are cleaned up

### Performance

1. **Fast unit tests**: Unit tests should complete in milliseconds
2. **Mark slow tests**: Use `@pytest.mark.slow` for tests taking >5 seconds
3. **Parallel execution**: Design tests to run safely in parallel
4. **Resource management**: Monitor memory and CPU usage in performance tests

### Security

1. **No real secrets**: Never use real API keys, passwords, or certificates
2. **Input validation**: Test with malicious and malformed inputs
3. **Privilege separation**: Verify tests don't require elevated privileges
4. **Attack simulation**: Include tests for common attack vectors