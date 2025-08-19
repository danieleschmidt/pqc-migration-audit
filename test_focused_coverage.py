#!/usr/bin/env python3
"""
Focused tests to achieve 80%+ coverage on core modules.
Targets the most essential functionality for production readiness.
"""

import os
import sys
import tempfile
import json
import pytest
import time
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from pqc_migration_audit.core import CryptoAuditor, RiskAssessment, CryptoPatterns
from pqc_migration_audit.types import (
    ScanResults, ScanStats, Vulnerability, Severity, CryptoAlgorithm,
    ValidationResult
)
from pqc_migration_audit.exceptions import (
    ScanException, ValidationException, SecurityException,
    FileSystemException, ScanTimeoutException, ExceptionHandler
)


class TestCoreModules:
    """Focused tests for core modules to achieve coverage targets."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.auditor = CryptoAuditor()
    
    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_types_module_coverage(self):
        """Test types module for full coverage."""
        # Test Severity enum
        assert Severity.CRITICAL.value == 'critical'
        assert Severity.HIGH.value == 'high'
        assert Severity.MEDIUM.value == 'medium'
        assert Severity.LOW.value == 'low'
        
        # Test CryptoAlgorithm enum
        assert CryptoAlgorithm.RSA.value == 'rsa'
        assert CryptoAlgorithm.ECC.value == 'ecc'
        assert CryptoAlgorithm.DSA.value == 'dsa'
        assert CryptoAlgorithm.DH.value == 'dh'
        assert CryptoAlgorithm.ECDSA.value == 'ecdsa'
        assert CryptoAlgorithm.ECDH.value == 'ecdh'
        
        # Test Vulnerability creation
        vuln = Vulnerability(
            file_path="/test/file.py",
            line_number=10,
            algorithm=CryptoAlgorithm.RSA,
            severity=Severity.HIGH,
            description="Test vulnerability",
            code_snippet="test code",
            recommendation="Test recommendation",
            cwe_id="CWE-327",
            key_size=2048
        )
        
        assert vuln.file_path == "/test/file.py"
        assert vuln.line_number == 10
        assert vuln.algorithm == CryptoAlgorithm.RSA
        assert vuln.severity == Severity.HIGH
        assert vuln.key_size == 2048
        
        # Test ScanStats
        stats = ScanStats(
            scan_start_time=time.time(),
            files_processed=100,
            files_skipped=5,
            errors_encountered=2,
            vulnerabilities_found=50
        )
        
        assert stats.files_processed == 100
        assert stats.files_skipped == 5
        assert stats.errors_encountered == 2
        assert stats.vulnerabilities_found == 50
        
        # Test ScanResults
        results = ScanResults(
            scan_path="/test/path",
            timestamp="2025-01-01 00:00:00",
            vulnerabilities=[vuln],
            scanned_files=1,
            total_lines=100,
            scan_time=1.5,
            languages_detected=['python'],
            scan_stats=stats
        )
        
        assert results.scan_path == "/test/path"
        assert len(results.vulnerabilities) == 1
        assert results.scanned_files == 1
        assert results.total_lines == 100
        assert results.scan_time == 1.5
        assert 'python' in results.languages_detected
        assert results.scan_stats == stats
        
        # Test ValidationResult
        validation = ValidationResult(
            is_valid=True,
            error_message=None,
            warnings=["Warning message"]
        )
        
        assert validation.is_valid is True
        assert validation.error_message is None
        assert "Warning message" in validation.warnings
    
    def test_exceptions_module_coverage(self):
        """Test exceptions module for full coverage."""
        # Test ScanException
        scan_ex = ScanException(
            "Scan failed",
            error_code="SCAN_ERROR",
            details={"file": "test.py"}
        )
        
        assert str(scan_ex) == "Scan failed"
        assert scan_ex.error_code == "SCAN_ERROR"
        assert scan_ex.details["file"] == "test.py"
        
        # Test ValidationException
        val_ex = ValidationException(
            "Validation failed",
            error_code="VALIDATION_ERROR",
            validation_details={"field": "path"}
        )
        
        assert str(val_ex) == "Validation failed"
        assert val_ex.error_code == "VALIDATION_ERROR"
        assert val_ex.validation_details["field"] == "path"
        
        # Test SecurityException
        sec_ex = SecurityException(
            "Security violation",
            error_code="SECURITY_ERROR",
            security_context={"threat": "HIGH"}
        )
        
        assert str(sec_ex) == "Security violation"
        assert sec_ex.error_code == "SECURITY_ERROR"
        assert sec_ex.security_context["threat"] == "HIGH"
        
        # Test FileSystemException
        fs_ex = FileSystemException(
            "File system error",
            error_code="FS_ERROR"
        )
        
        assert str(fs_ex) == "File system error"
        assert fs_ex.error_code == "FS_ERROR"
        
        # Test ScanTimeoutException
        timeout_ex = ScanTimeoutException(300, 150)
        
        assert "300" in str(timeout_ex)
        assert "150" in str(timeout_ex)
        assert timeout_ex.timeout_seconds == 300
        assert timeout_ex.files_processed == 150
    
    def test_crypto_patterns_comprehensive(self):
        """Test CryptoPatterns class comprehensively."""
        patterns = CryptoPatterns()
        
        # Test all pattern categories exist
        for lang_patterns in [patterns.PYTHON_PATTERNS, patterns.JAVA_PATTERNS, 
                             patterns.GO_PATTERNS, patterns.JAVASCRIPT_PATTERNS,
                             patterns.C_CPP_PATTERNS]:
            assert isinstance(lang_patterns, dict)
            assert len(lang_patterns) > 0
            
            # Each pattern category should have lists of regex patterns
            for category, pattern_list in lang_patterns.items():
                assert isinstance(pattern_list, list)
                assert len(pattern_list) > 0
                for pattern in pattern_list:
                    assert isinstance(pattern, str)
                    assert len(pattern) > 0
    
    def test_risk_assessment_comprehensive(self):
        """Test RiskAssessment class comprehensively."""
        # Create diverse vulnerability set
        vulnerabilities = [
            Vulnerability(
                file_path="/test/critical.py",
                line_number=1,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.CRITICAL,
                key_size=1024,
                description="Critical RSA vulnerability",
                code_snippet="rsa.generate_private_key(key_size=1024)",
                recommendation="Upgrade immediately"
            ),
            Vulnerability(
                file_path="/test/high_ecc.py",
                line_number=5,
                algorithm=CryptoAlgorithm.ECC,
                severity=Severity.HIGH,
                description="High ECC vulnerability",
                code_snippet="ec.generate_private_key(ec.SECP256R1())",
                recommendation="Migrate to ML-DSA"
            ),
            Vulnerability(
                file_path="/test/medium_dsa.py",
                line_number=10,
                algorithm=CryptoAlgorithm.DSA,
                severity=Severity.MEDIUM,
                description="Medium DSA vulnerability",
                code_snippet="dsa.generate_private_key(1024)",
                recommendation="Use ML-DSA"
            ),
            Vulnerability(
                file_path="/test/low_dh.py",
                line_number=15,
                algorithm=CryptoAlgorithm.DH,
                severity=Severity.LOW,
                description="Low DH vulnerability",
                code_snippet="dh.generate_private_key()",
                recommendation="Consider upgrading"
            ),
        ]
        
        scan_results = ScanResults(
            scan_path="/test",
            timestamp="2025-01-01 00:00:00",
            vulnerabilities=vulnerabilities,
            scanned_files=4,
            total_lines=400,
            scan_time=2.5,
            languages_detected=['python'],
            scan_stats=ScanStats(
                scan_start_time=0.0,
                files_processed=4,
                files_skipped=0,
                errors_encountered=0,
                vulnerabilities_found=4
            )
        )
        
        risk_assessment = RiskAssessment(scan_results)
        
        # Test HNDL risk calculation
        risk_score = risk_assessment.calculate_harvest_now_decrypt_later_risk()
        assert 0 <= risk_score <= 100
        assert risk_score > 20  # Should have some risk with these vulnerabilities
        
        # Test migration hours estimation
        hours = risk_assessment.migration_hours
        assert hours > 0
        # Critical(16) + High(8) + Medium(4) + Low(2) = 30h + 25% = 37.5h
        expected = int((16 + 8 + 4 + 2) * 1.25)
        assert hours == expected
        
        # Test risk report generation
        report = risk_assessment.generate_risk_report()
        
        # Verify report structure
        assert 'risk_summary' in report
        assert 'vulnerability_breakdown' in report
        assert 'recommendations' in report
        
        # Verify risk summary
        summary = report['risk_summary']
        assert summary['total_vulnerabilities'] == 4
        assert summary['hndl_risk_score'] == risk_score
        assert summary['migration_effort_hours'] == hours
        
        # Verify breakdowns
        breakdown = report['vulnerability_breakdown']
        
        severity_breakdown = breakdown['by_severity']
        assert severity_breakdown['critical'] == 1
        assert severity_breakdown['high'] == 1
        assert severity_breakdown['medium'] == 1
        assert severity_breakdown['low'] == 1
        
        algorithm_breakdown = breakdown['by_algorithm']
        assert algorithm_breakdown['rsa'] == 1
        assert algorithm_breakdown['ecc'] == 1
        assert algorithm_breakdown['dsa'] == 1
        assert algorithm_breakdown['dh'] == 1
        
        file_breakdown = breakdown['by_file']
        assert file_breakdown['/test/critical.py'] == 1
        assert file_breakdown['/test/high_ecc.py'] == 1
        
        # Test risk level classification
        assert risk_assessment._get_risk_level(95) == "CRITICAL"
        assert risk_assessment._get_risk_level(75) == "HIGH"
        assert risk_assessment._get_risk_level(55) == "MEDIUM"
        assert risk_assessment._get_risk_level(35) == "LOW"
        assert risk_assessment._get_risk_level(15) == "MINIMAL"
        
        # Test recommendations
        recommendations = report['recommendations']
        assert isinstance(recommendations, list)
        assert len(recommendations) > 0
        assert any('inventory' in rec.lower() for rec in recommendations)
    
    def test_auditor_file_scanning_comprehensive(self):
        """Test all file scanning methods comprehensively."""
        # Create comprehensive test files
        test_files = {
            'python_comprehensive.py': '''
# Python comprehensive crypto test
import rsa
from cryptography.hazmat.primitives.asymmetric import ec, dsa, rsa as crypto_rsa
from Crypto.PublicKey import RSA
import hashlib
import ssl

# RSA vulnerabilities
private_key_1 = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # Critical
private_key_2 = crypto_rsa.generate_private_key(public_exponent=65537, key_size=2048)  # High
rsa_key = RSA.generate(2048)  # High

# ECC vulnerabilities  
ecc_key_1 = ec.generate_private_key(ec.SECP256R1())
ecc_key_2 = ec.generate_private_key(ec.SECP384R1())

# DSA vulnerabilities
dsa_key = dsa.generate_private_key(key_size=1024)

# Legacy SSL/TLS
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
''',
            'java_comprehensive.java': '''
// Java comprehensive crypto test
import java.security.KeyPairGenerator;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.Cipher;

public class CryptoTest {
    public void generateKeys() throws Exception {
        // RSA vulnerabilities
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(1024);  // Weak key size
        
        RSAKeyGenParameterSpec rsaSpec = new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4);
        
        // ECC vulnerabilities
        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        
        // DSA vulnerabilities
        KeyPairGenerator dsaGen = KeyPairGenerator.getInstance("DSA");
        
        // Cipher usage
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    }
}
''',
            'go_comprehensive.go': '''
// Go comprehensive crypto test
package main

import (
    "crypto/rsa"
    "crypto/ecdsa"
    "crypto/rand"
    "crypto/elliptic"
    "crypto/tls"
)

func main() {
    // RSA vulnerabilities
    rsaKey1, _ := rsa.GenerateKey(rand.Reader, 1024)  // Weak
    rsaKey2, _ := rsa.GenerateKey(rand.Reader, 2048)
    
    // ECDSA vulnerabilities  
    ecdsaKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    ecdsaKey2, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
    
    // Legacy TLS
    config := &tls.Config{
        MinVersion: tls.VersionTLS10,  // Legacy
    }
}
''',
            'javascript_comprehensive.js': '''
// JavaScript comprehensive crypto test
const crypto = require('crypto');

// RSA vulnerabilities
const rsaKeyPair1 = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 }); // Weak
const rsaKeyPair2 = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

// ECC vulnerabilities
const eccKeyPair1 = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256r1' });
const eccKeyPair2 = crypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' });

// Legacy crypto
const md5Hash = crypto.createHash('md5');
const sha1Hash = crypto.createHash('sha1');
''',
            'cpp_comprehensive.cpp': '''
// C++ comprehensive crypto test
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

int main() {
    // RSA vulnerabilities
    RSA* rsa1 = RSA_generate_key(1024, RSA_F4, NULL, NULL);  // Weak
    RSA* rsa2 = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    
    // EVP RSA
    EVP_PKEY* pkey = EVP_PKEY_new();
    RSA* rsa3 = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    
    // ECC vulnerabilities
    EC_KEY* ec_key = EC_KEY_new();
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_KEY_generate_key(ec_key);
    
    // Legacy functions
    MD5_CTX md5_ctx;
    MD5_Init(&md5_ctx);
    
    SHA_CTX sha1_ctx;
    SHA1_Init(&sha1_ctx);
    
    return 0;
}
'''
        }
        
        # Create all test files
        for filename, content in test_files.items():
            file_path = Path(self.temp_dir) / filename
            file_path.write_text(content, encoding='utf-8')
        
        # Test comprehensive scanning
        results = self.auditor.scan_directory(self.temp_dir)
        
        # Verify comprehensive results
        assert len(results.vulnerabilities) >= 15  # Should find many vulnerabilities
        assert results.scanned_files == len(test_files)
        assert len(results.languages_detected) == 5  # All languages
        
        # Verify language-specific vulnerabilities
        python_vulns = [v for v in results.vulnerabilities if v.file_path.endswith('.py')]
        java_vulns = [v for v in results.vulnerabilities if v.file_path.endswith('.java')]
        go_vulns = [v for v in results.vulnerabilities if v.file_path.endswith('.go')]
        js_vulns = [v for v in results.vulnerabilities if v.file_path.endswith('.js')]
        cpp_vulns = [v for v in results.vulnerabilities if v.file_path.endswith('.cpp')]
        
        assert len(python_vulns) >= 3
        assert len(java_vulns) >= 2
        assert len(go_vulns) >= 2
        assert len(js_vulns) >= 2
        assert len(cpp_vulns) >= 2
        
        # Test severity distribution
        critical_vulns = [v for v in results.vulnerabilities if v.severity == Severity.CRITICAL]
        high_vulns = [v for v in results.vulnerabilities if v.severity == Severity.HIGH]
        medium_vulns = [v for v in results.vulnerabilities if v.severity == Severity.MEDIUM]
        
        assert len(high_vulns) > 0  # Should have high severity vulns
        
        # Test algorithm distribution
        rsa_vulns = [v for v in results.vulnerabilities if v.algorithm == CryptoAlgorithm.RSA]
        ecc_vulns = [v for v in results.vulnerabilities if v.algorithm == CryptoAlgorithm.ECC]
        
        assert len(rsa_vulns) >= 5  # Multiple RSA vulns across languages
        assert len(ecc_vulns) >= 3  # Multiple ECC vulns
    
    def test_auditor_error_handling_comprehensive(self):
        """Test comprehensive error handling scenarios."""
        # Test with non-existent path
        with pytest.raises((ValidationException, ScanException, FileSystemException)):
            self.auditor.scan_directory("/completely/nonexistent/path/12345")
        
        # Test with empty directory
        empty_dir = Path(self.temp_dir) / "empty"
        empty_dir.mkdir()
        
        results = self.auditor.scan_directory(str(empty_dir))
        assert isinstance(results, ScanResults)
        assert results.scanned_files == 0
        assert len(results.vulnerabilities) == 0
        
        # Test with mixed file types
        text_file = Path(self.temp_dir) / "readme.txt"
        text_file.write_text("This is not a source file")
        
        python_file = Path(self.temp_dir) / "crypto.py"
        python_file.write_text("import rsa; rsa.generate_private_key()")
        
        results = self.auditor.scan_directory(self.temp_dir)
        assert results.scanned_files == 1  # Only Python file
        assert len(results.vulnerabilities) >= 1
        
        # Test with binary file
        binary_file = Path(self.temp_dir) / "binary.py"
        binary_file.write_bytes(b'\x00\x01\x02\x03\xFF\xFE')
        
        results = self.auditor.scan_directory(self.temp_dir)
        # Should handle binary files gracefully
        assert isinstance(results, ScanResults)
    
    def test_migration_plan_comprehensive(self):
        """Test migration plan creation comprehensively."""
        # Create vulnerabilities with all severity levels
        vulnerabilities = []
        
        # Add multiple vulnerabilities per severity level
        for i in range(3):
            vulnerabilities.extend([
                Vulnerability(
                    file_path=f"/test/critical_{i}.py",
                    line_number=i+1,
                    algorithm=CryptoAlgorithm.RSA,
                    severity=Severity.CRITICAL,
                    key_size=1024,
                    description=f"Critical RSA {i}",
                    code_snippet="critical code",
                    recommendation="Fix immediately"
                ),
                Vulnerability(
                    file_path=f"/test/high_{i}.py", 
                    line_number=i+1,
                    algorithm=CryptoAlgorithm.ECC,
                    severity=Severity.HIGH,
                    description=f"High ECC {i}",
                    code_snippet="high code",
                    recommendation="Fix soon"
                ),
                Vulnerability(
                    file_path=f"/test/medium_{i}.py",
                    line_number=i+1,
                    algorithm=CryptoAlgorithm.DSA,
                    severity=Severity.MEDIUM,
                    description=f"Medium DSA {i}",
                    code_snippet="medium code",
                    recommendation="Plan migration"
                ),
                Vulnerability(
                    file_path=f"/test/low_{i}.py",
                    line_number=i+1,
                    algorithm=CryptoAlgorithm.DH,
                    severity=Severity.LOW,
                    description=f"Low DH {i}",
                    code_snippet="low code",
                    recommendation="Consider future upgrade"
                )
            ])
        
        scan_results = ScanResults(
            scan_path="/test",
            timestamp="2025-01-01 00:00:00",
            vulnerabilities=vulnerabilities,
            scanned_files=12,
            total_lines=1200,
            scan_time=5.0,
            languages_detected=['python']
        )
        
        plan = self.auditor.create_migration_plan(scan_results)
        
        # Verify plan structure
        assert 'summary' in plan
        assert 'migration_phases' in plan
        assert 'recommendations' in plan
        
        # Verify summary counts
        summary = plan['summary']
        assert summary['total_vulnerabilities'] == 12
        assert summary['critical'] == 3
        assert summary['high'] == 3
        assert summary['medium'] == 3
        assert summary['low'] == 3
        
        # Verify migration phases
        phases = plan['migration_phases']
        assert len(phases) == 3
        
        # Phase 1: Critical + High
        assert phases[0]['phase'] == 1
        assert len(phases[0]['vulnerabilities']) == 6  # 3 critical + 3 high
        
        # Phase 2: Medium
        assert phases[1]['phase'] == 2
        assert len(phases[1]['vulnerabilities']) == 3  # 3 medium
        
        # Phase 3: Low
        assert phases[2]['phase'] == 3
        assert len(phases[2]['vulnerabilities']) == 3  # 3 low
        
        # Verify recommendations structure
        recommendations = plan['recommendations']
        assert 'immediate_actions' in recommendations
        assert 'pqc_algorithms' in recommendations
        assert 'migration_strategy' in recommendations
        
        pqc_algorithms = recommendations['pqc_algorithms']
        assert 'key_exchange' in pqc_algorithms
        assert 'digital_signatures' in pqc_algorithms
        assert 'ML-KEM' in pqc_algorithms['key_exchange']
        assert 'ML-DSA' in pqc_algorithms['digital_signatures']


if __name__ == "__main__":
    # Run tests with coverage reporting focused on core modules
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "--cov=src/pqc_migration_audit/core.py",
        "--cov=src/pqc_migration_audit/types.py", 
        "--cov=src/pqc_migration_audit/exceptions.py",
        "--cov-append",
        "--cov-report=term-missing",
        "--cov-report=html:htmlcov_focused",
        "--cov-fail-under=80"
    ])