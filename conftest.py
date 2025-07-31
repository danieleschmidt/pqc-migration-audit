# Global pytest configuration for PQC Migration Audit
import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock

# Security test fixtures
@pytest.fixture
def temp_crypto_repo():
    """Create temporary repository with sample crypto code for testing."""
    temp_dir = tempfile.mkdtemp()
    repo_path = Path(temp_dir) / "test_repo"
    repo_path.mkdir()
    
    # Sample vulnerable code files
    (repo_path / "rsa_example.py").write_text("""
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
""")
    
    yield repo_path
    shutil.rmtree(temp_dir)

@pytest.fixture
def mock_audit_config():
    """Mock configuration for audit testing."""
    return {
        'scan_patterns': ['*.py', '*.java', '*.go'],
        'vulnerability_rules': 'config/rules.yaml',
        'output_format': 'json',
        'severity_threshold': 'medium'
    }

# Performance testing fixtures
@pytest.fixture
def benchmark_data():
    """Provide consistent data for performance tests."""
    return {
        'large_codebase_files': 1000,
        'expected_scan_time_ms': 5000,
        'memory_limit_mb': 256
    }

# Mutation testing configuration
def pytest_configure(config):
    """Configure pytest for mutation testing compatibility."""
    config.addinivalue_line(
        "markers", "muttest: mark test for mutation testing"
    )