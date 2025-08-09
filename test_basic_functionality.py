#!/usr/bin/env python3
"""Basic functionality test for Generation 1."""

import sys
import os
import tempfile
from pathlib import Path

# Add src to path
sys.path.insert(0, 'src')

from pqc_migration_audit.core import CryptoAuditor
from pqc_migration_audit.scanners import PythonScanner

def test_basic_crypto_detection():
    """Test basic crypto detection functionality."""
    print("🔍 Testing basic crypto detection...")
    
    # Create test file with RSA usage
    test_code = """
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        temp_file = Path(f.name)
    
    try:
        # Test scanner
        scanner = PythonScanner()
        findings = scanner.scan_file(temp_file)
        print(f"✅ Scanner found {len(findings)} findings")
        
        # Test auditor
        auditor = CryptoAuditor()
        results = auditor.scan_directory(temp_file.parent)
        print(f"✅ Auditor found {len(results.vulnerabilities)} vulnerabilities")
        
        if results.vulnerabilities:
            vuln = results.vulnerabilities[0]
            print(f"   - Algorithm: {vuln.algorithm.value}")
            print(f"   - Severity: {vuln.severity.value}")
            print(f"   - Description: {vuln.description}")
        
        return len(results.vulnerabilities) > 0
        
    finally:
        temp_file.unlink()

def test_cli_functionality():
    """Test CLI functionality."""
    print("🎯 Testing CLI functionality...")
    
    # Create temp directory with vulnerable code
    with tempfile.TemporaryDirectory() as temp_dir:
        test_file = Path(temp_dir) / "vulnerable.py"
        test_file.write_text("""
from cryptography.hazmat.primitives.asymmetric import rsa, ec

def rsa_test():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def ecc_test():
    return ec.generate_private_key(ec.SECP256R1())
""")
        
        # Test auditor on directory
        auditor = CryptoAuditor()
        results = auditor.scan_directory(temp_dir)
        
        print(f"✅ CLI scan found {len(results.vulnerabilities)} vulnerabilities")
        print(f"   - Files scanned: {results.scanned_files}")
        print(f"   - Languages: {results.languages_detected}")
        
        return len(results.vulnerabilities) >= 2  # RSA + ECC

if __name__ == "__main__":
    print("🚀 Generation 1: MAKE IT WORK - Basic Functionality Test")
    print("=" * 60)
    
    success = True
    
    try:
        if test_basic_crypto_detection():
            print("✅ Basic crypto detection: PASS")
        else:
            print("❌ Basic crypto detection: FAIL")
            success = False
            
        if test_cli_functionality():
            print("✅ CLI functionality: PASS")
        else:
            print("❌ CLI functionality: FAIL")
            success = False
            
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        success = False
    
    print("=" * 60)
    if success:
        print("🎉 Generation 1: MAKE IT WORK - COMPLETE")
        sys.exit(0)
    else:
        print("💥 Generation 1: FAILED")
        sys.exit(1)