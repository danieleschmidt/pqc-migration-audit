"""Pytest configuration and fixtures."""

import pytest
import tempfile
import shutil
from pathlib import Path


@pytest.fixture
def temp_repo():
    """Create a temporary repository for testing."""
    temp_dir = Path(tempfile.mkdtemp())
    yield temp_dir
    shutil.rmtree(temp_dir)


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