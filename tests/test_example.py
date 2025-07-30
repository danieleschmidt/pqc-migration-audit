"""Example test to verify testing infrastructure works."""

import pytest


def test_basic_functionality():
    """Test that basic testing works."""
    assert 1 + 1 == 2


def test_temp_repo_fixture(temp_repo):
    """Test that temp_repo fixture works."""
    assert temp_repo.exists()
    assert temp_repo.is_dir()


def test_sample_code_fixtures(sample_vulnerable_code, sample_secure_code):
    """Test that code sample fixtures work."""
    assert "rsa_key_gen.py" in sample_vulnerable_code
    assert "kyber_kem.py" in sample_secure_code
    assert "from cryptography.hazmat.primitives.asymmetric import rsa" in sample_vulnerable_code["rsa_key_gen.py"]