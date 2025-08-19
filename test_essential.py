#!/usr/bin/env python3
"""
Essential functionality tests to demonstrate Generation 1: MAKE IT WORK completion.
This test focuses on core scanning capability without complex features.
"""

import os
import sys
import tempfile
import pytest
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Import core functionality
from pqc_migration_audit.types import *
from pqc_migration_audit.core import CryptoAuditor, RiskAssessment


class TestCoreScanning:
    """Test essential scanning functionality."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        # Create auditor with minimal config to avoid advanced features
        self.auditor = CryptoAuditor({'enable_security_validation': False, 'enable_comprehensive_logging': False})
    
    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_basic_python_rsa_detection(self):
        """Test basic RSA vulnerability detection in Python."""
        python_code = '''
import rsa

# This should be detected as quantum-vulnerable
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
'''
        
        file_path = Path(self.temp_dir) / "crypto_test.py"
        file_path.write_text(python_code)
        
        results = self.auditor.scan_directory(self.temp_dir)
        
        # Verify basic scanning worked
        assert isinstance(results, ScanResults)
        assert results.scanned_files == 1
        assert len(results.vulnerabilities) >= 1
        
        # Verify RSA vulnerability detected
        rsa_vulns = [v for v in results.vulnerabilities if v.algorithm == CryptoAlgorithm.RSA]
        assert len(rsa_vulns) >= 1
        
        vuln = rsa_vulns[0]
        assert vuln.file_path.endswith("crypto_test.py")
        assert vuln.severity in [Severity.HIGH, Severity.MEDIUM, Severity.CRITICAL]
        assert "rsa" in vuln.description.lower()
    
    def test_basic_java_rsa_detection(self):
        """Test basic RSA vulnerability detection in Java."""
        java_code = '''
import java.security.KeyPairGenerator;

public class CryptoTest {
    public void generateRSAKey() {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
    }
}
'''
        
        file_path = Path(self.temp_dir) / "CryptoTest.java"
        file_path.write_text(java_code)
        
        results = self.auditor.scan_directory(self.temp_dir)
        
        # Verify basic scanning worked
        assert isinstance(results, ScanResults)
        assert results.scanned_files == 1
        assert len(results.vulnerabilities) >= 1
        
        # Verify RSA vulnerability detected
        rsa_vulns = [v for v in results.vulnerabilities if v.algorithm == CryptoAlgorithm.RSA]
        assert len(rsa_vulns) >= 1
        
        vuln = rsa_vulns[0]
        assert vuln.file_path.endswith("CryptoTest.java")
        assert vuln.severity == Severity.HIGH
        assert "rsa" in vuln.description.lower()
    
    def test_multiple_file_scanning(self):
        """Test scanning multiple files with different languages."""
        test_files = {
            'python_crypto.py': '''
import rsa
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
''',
            'JavaCrypto.java': '''
import java.security.KeyPairGenerator;
public class JavaCrypto {
    public void test() {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
    }
}
''',
            'safe_file.py': '''
# This file has no crypto vulnerabilities
print("Hello, world!")
'''
        }
        
        for filename, content in test_files.items():
            file_path = Path(self.temp_dir) / filename
            file_path.write_text(content)
        
        results = self.auditor.scan_directory(self.temp_dir)
        
        # Verify scanning worked
        assert isinstance(results, ScanResults)
        assert results.scanned_files == 3
        assert len(results.vulnerabilities) >= 2  # From python and java files
        
        # Verify languages detected
        assert 'python' in results.languages_detected
        assert 'java' in results.languages_detected
        
        # Verify vulnerabilities found in correct files
        python_vulns = [v for v in results.vulnerabilities if v.file_path.endswith('.py')]
        java_vulns = [v for v in results.vulnerabilities if v.file_path.endswith('.java')]
        
        assert len(python_vulns) >= 1
        assert len(java_vulns) >= 1
    
    def test_risk_assessment_basic(self):
        """Test basic risk assessment functionality."""
        # Create vulnerabilities
        vulnerabilities = [
            Vulnerability(
                file_path="/test/high_risk.py",
                line_number=5,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.HIGH,
                key_size=2048,
                description="RSA key generation detected",
                code_snippet="rsa.generate_private_key()",
                recommendation="Replace with ML-KEM"
            ),
            Vulnerability(
                file_path="/test/medium_risk.py", 
                line_number=10,
                algorithm=CryptoAlgorithm.ECC,
                severity=Severity.MEDIUM,
                description="ECC key generation detected",
                code_snippet="ec.generate_private_key()",
                recommendation="Replace with ML-DSA"
            ),
        ]
        
        scan_results = ScanResults(
            scan_path="/test",
            timestamp="2025-01-01 00:00:00",
            vulnerabilities=vulnerabilities,
            scanned_files=2,
            total_lines=100,
            scan_time=1.0,
            languages_detected=['python']
        )
        
        risk_assessment = RiskAssessment(scan_results)
        
        # Test basic risk calculation
        risk_score = risk_assessment.calculate_harvest_now_decrypt_later_risk()
        assert 0 <= risk_score <= 100
        assert risk_score > 0  # Should have some risk
        
        # Test migration hours estimation
        hours = risk_assessment.migration_hours
        assert hours > 0
        assert isinstance(hours, int)
        
        # Test risk report generation
        report = risk_assessment.generate_risk_report()
        assert 'risk_summary' in report
        assert 'vulnerability_breakdown' in report
        assert 'recommendations' in report
        
        # Verify summary
        summary = report['risk_summary']
        assert summary['total_vulnerabilities'] == 2
        assert summary['hndl_risk_score'] == risk_score
        assert summary['migration_effort_hours'] == hours
    
    def test_migration_plan_generation(self):
        """Test basic migration plan generation."""
        # Create test vulnerabilities
        vulnerabilities = [
            Vulnerability(
                file_path="/test/critical.py",
                line_number=1,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.CRITICAL,
                key_size=1024,
                description="Weak RSA key",
                code_snippet="rsa.generate_private_key(key_size=1024)",
                recommendation="Upgrade immediately"
            ),
            Vulnerability(
                file_path="/test/high.py",
                line_number=5,
                algorithm=CryptoAlgorithm.ECC,
                severity=Severity.HIGH,
                description="ECC vulnerability",
                code_snippet="ec.generate_private_key()",
                recommendation="Migrate to PQC"
            ),
        ]
        
        scan_results = ScanResults(
            scan_path="/test",
            timestamp="2025-01-01 00:00:00",
            vulnerabilities=vulnerabilities,
            scanned_files=2,
            total_lines=200,
            scan_time=2.0,
            languages_detected=['python']
        )
        
        plan = self.auditor.create_migration_plan(scan_results)
        
        # Verify plan structure
        assert 'summary' in plan
        assert 'migration_phases' in plan
        assert 'recommendations' in plan
        
        # Verify summary
        summary = plan['summary']
        assert summary['total_vulnerabilities'] == 2
        assert summary['critical'] == 1
        assert summary['high'] == 1
        
        # Verify phases
        phases = plan['migration_phases']
        assert len(phases) == 3  # Three phases
        
        # Phase 1 should have critical + high
        phase1 = phases[0]
        assert phase1['phase'] == 1
        assert len(phase1['vulnerabilities']) == 2
        
        # Verify recommendations
        recommendations = plan['recommendations']
        assert 'immediate_actions' in recommendations
        assert 'pqc_algorithms' in recommendations
        
        pqc_algorithms = recommendations['pqc_algorithms']
        assert 'key_exchange' in pqc_algorithms
        assert 'digital_signatures' in pqc_algorithms
        assert 'ML-KEM' in pqc_algorithms['key_exchange']
        assert 'ML-DSA' in pqc_algorithms['digital_signatures']
    
    def test_comprehensive_crypto_detection(self):
        """Test detection of various crypto algorithms."""
        comprehensive_code = '''
import rsa
from cryptography.hazmat.primitives.asymmetric import ec, dsa
import hashlib

# RSA - should be detected
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# ECC - should be detected
ecc_key = ec.generate_private_key(ec.SECP256R1())

# DSA - should be detected  
dsa_key = dsa.generate_private_key(key_size=2048)

# Legacy hash - may be detected
md5_hash = hashlib.md5(b"data").hexdigest()
'''
        
        file_path = Path(self.temp_dir) / "comprehensive_crypto.py"
        file_path.write_text(comprehensive_code)
        
        results = self.auditor.scan_directory(self.temp_dir)
        
        # Verify scanning worked
        assert isinstance(results, ScanResults)
        assert results.scanned_files == 1
        assert len(results.vulnerabilities) >= 3  # At least RSA, ECC, DSA
        
        # Check algorithm diversity
        algorithms_found = {vuln.algorithm for vuln in results.vulnerabilities}
        assert CryptoAlgorithm.RSA in algorithms_found
        assert CryptoAlgorithm.ECC in algorithms_found
        # DSA might be detected depending on patterns
        
        # Check severity levels
        severities_found = {vuln.severity for vuln in results.vulnerabilities}
        assert len(severities_found) > 0  # Should have at least some severity levels
    
    def test_language_support(self):
        """Test support for multiple programming languages."""
        # Test language detection
        test_cases = [
            ('test.py', 'python'),
            ('Test.java', 'java'),
            ('test.go', 'go'),
            ('test.js', 'javascript'),
            ('test.ts', 'typescript'),
            ('test.c', 'c'),
            ('test.cpp', 'cpp'),
        ]
        
        for filename, expected_language in test_cases:
            file_path = Path(filename)
            detected = self.auditor._detect_language(file_path)
            assert detected == expected_language, f"Language detection failed for {filename}"
        
        # Test unsupported files
        unsupported_cases = ['test.txt', 'README.md', 'config.ini']
        for filename in unsupported_cases:
            file_path = Path(filename)
            detected = self.auditor._detect_language(file_path)
            assert detected is None, f"Should not detect language for {filename}"


class TestDataTypes:
    """Test core data types."""
    
    def test_severity_enum(self):
        """Test Severity enum."""
        assert Severity.LOW.value == "low"
        assert Severity.MEDIUM.value == "medium"  
        assert Severity.HIGH.value == "high"
        assert Severity.CRITICAL.value == "critical"
    
    def test_crypto_algorithm_enum(self):
        """Test CryptoAlgorithm enum."""
        assert CryptoAlgorithm.RSA.value == "rsa"
        assert CryptoAlgorithm.ECC.value == "ecc"
        assert CryptoAlgorithm.DSA.value == "dsa"
        assert CryptoAlgorithm.DH.value == "dh"
        assert CryptoAlgorithm.ECDSA.value == "ecdsa"
        assert CryptoAlgorithm.ECDH.value == "ecdh"
    
    def test_vulnerability_creation(self):
        """Test Vulnerability dataclass creation."""
        vuln = Vulnerability(
            file_path="/test/file.py",
            line_number=10,
            algorithm=CryptoAlgorithm.RSA,
            severity=Severity.HIGH,
            key_size=2048,
            description="RSA vulnerability",
            code_snippet="rsa.generate_private_key()",
            recommendation="Use ML-KEM",
            cwe_id="CWE-327"
        )
        
        assert vuln.file_path == "/test/file.py"
        assert vuln.line_number == 10
        assert vuln.algorithm == CryptoAlgorithm.RSA
        assert vuln.severity == Severity.HIGH
        assert vuln.key_size == 2048
        assert vuln.description == "RSA vulnerability"
        assert vuln.code_snippet == "rsa.generate_private_key()"
        assert vuln.recommendation == "Use ML-KEM"
        assert vuln.cwe_id == "CWE-327"
    
    def test_scan_results_creation(self):
        """Test ScanResults dataclass creation."""
        vuln = Vulnerability(
            file_path="/test/file.py",
            line_number=1,
            algorithm=CryptoAlgorithm.RSA,
            severity=Severity.HIGH,
            description="Test vulnerability",
            code_snippet="test",
            recommendation="test"
        )
        
        results = ScanResults(
            vulnerabilities=[vuln],
            scanned_files=1,
            total_lines=50,
            scan_time=1.5,
            scan_path="/test",
            timestamp="2025-01-01 00:00:00",
            languages_detected=['python']
        )
        
        assert len(results.vulnerabilities) == 1
        assert results.scanned_files == 1
        assert results.total_lines == 50
        assert results.scan_time == 1.5
        assert results.scan_path == "/test"
        assert results.timestamp == "2025-01-01 00:00:00"
        assert 'python' in results.languages_detected


if __name__ == "__main__":
    # Run essential tests  
    pytest.main([
        __file__,
        "-v",
        "--tb=short"
    ])