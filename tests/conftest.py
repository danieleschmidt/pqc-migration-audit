"""Pytest configuration and fixtures."""

import pytest
import tempfile
import shutil
from pathlib import Path
from contextlib import contextmanager
from unittest.mock import Mock

# Test helpers
class TestHelpers:
    """Helper utilities for tests."""
    
    @staticmethod
    @contextmanager
    def temp_python_file(content):
        """Create a temporary Python file with given content."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            if isinstance(content, bytes):
                f.write(content.decode('utf-8', errors='ignore'))
            else:
                f.write(content)
            f.flush()
            temp_path = Path(f.name)
        
        try:
            yield temp_path
        finally:
            if temp_path.exists():
                temp_path.unlink()

# Make helpers available to tests
pytest.helpers = TestHelpers()


@pytest.fixture
def temp_repo():
    """Create a temporary repository for testing."""
    temp_dir = Path(tempfile.mkdtemp())
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def sample_vulnerable_code():
    """Sample code with quantum-vulnerable cryptography."""
    return {
        "rsa_key_gen.py": '''
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key
''',
        "ecdsa_signing.py": '''
from cryptography.hazmat.primitives.asymmetric import ec

def create_signing_key():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key
'''
    }


@pytest.fixture
def sample_secure_code():
    """Sample code with post-quantum secure cryptography."""
    return {
        "kyber_kem.py": '''
from pqc_migration.crypto import ML_KEM_768

def generate_keypair():
    private_key, public_key = ML_KEM_768.generate_keypair()
    return private_key, public_key
''',
        "dilithium_sig.py": '''
from pqc_migration.crypto import ML_DSA_65

def create_signing_keys():
    signing_key, verification_key = ML_DSA_65.generate_keypair()
    return signing_key, verification_key
'''
    }


@pytest.fixture
def sample_config_files():
    """Sample configuration files with crypto settings."""
    return {
        "ssl.conf": '''
SSLEngine on
SSLProtocol TLSv1.2 TLSv1.3
SSLCipherSuite ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256
SSLCertificateFile /etc/ssl/certs/server-rsa-2048.crt
SSLCertificateKeyFile /etc/ssl/private/server-rsa-2048.key
''',
        "crypto_policy.yaml": '''
crypto_policy:
  algorithms:
    asymmetric:
      rsa:
        min_key_size: 2048
      ecc:
        allowed_curves: ["secp256r1", "secp384r1"]
    symmetric:
      aes:
        key_sizes: [256]
'''
    }


@pytest.fixture 
def mock_scan_results():
    """Mock scan results for testing."""
    results = Mock()
    results.vulnerabilities = [
        Mock(
            id="RSA-001",
            severity="HIGH", 
            algorithm="RSA",
            key_size=2048,
            file_path=Path("test.py"),
            line_number=10,
            description="RSA key generation with 2048-bit key"
        )
    ]
    results.risk_assessment = Mock()
    results.risk_assessment.overall_risk_score = 75
    results.scan_stats = Mock()
    results.scan_stats.files_processed = 50
    return results


# Test configuration
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests") 
    config.addinivalue_line("markers", "security: Security-focused tests")
    config.addinivalue_line("markers", "performance: Performance benchmarks")
    config.addinivalue_line("markers", "crypto: Cryptographic functionality tests")
    config.addinivalue_line("markers", "slow: Tests that take significant time")
    config.addinivalue_line("markers", "network: Tests requiring network access")