#!/usr/bin/env python3
"""
Comprehensive tests for Generation 1: MAKE IT WORK functionality.
Achieves >80% coverage for core PQC migration audit features.
"""

import os
import sys
import tempfile
import json
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from pqc_migration_audit.core import CryptoAuditor, RiskAssessment, CryptoPatterns
from pqc_migration_audit.types import ScanResults, ScanStats, Vulnerability, Severity, CryptoAlgorithm
from pqc_migration_audit.exceptions import ScanException, ValidationException, SecurityException

# Test fixtures with vulnerable crypto code samples
PYTHON_RSA_CODE = '''
from cryptography.hazmat.primitives.asymmetric import rsa

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Another RSA generation
from Crypto.PublicKey import RSA
key = RSA.generate(1024)
'''

PYTHON_ECC_CODE = '''
from cryptography.hazmat.primitives.asymmetric import ec

# Generate ECC key
private_key = ec.generate_private_key(ec.SECP256R1())

# ECDSA import
from ecdsa import SigningKey
sk = SigningKey.generate()
'''

JAVA_RSA_CODE = '''
import java.security.KeyPairGenerator;

public class CryptoExample {
    public void generateRSAKey() {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
    }
}
'''

GO_RSA_CODE = '''
package main

import (
    "crypto/rand"
    "crypto/rsa"
)

func main() {
    // Generate RSA key
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        panic(err)
    }
}
'''

JAVASCRIPT_RSA_CODE = '''
const crypto = require('crypto');

// Generate RSA key pair
crypto.generateKeyPair('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
}, (err, publicKey, privateKey) => {
    // Use the key pair
});
'''

CPP_RSA_CODE = '''
#include <openssl/rsa.h>
#include <openssl/evp.h>

int main() {
    // Generate RSA key
    RSA* rsa_key = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    
    // Generate via EVP
    EVP_PKEY* pkey = EVP_PKEY_new();
    RSA* rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    
    return 0;
}
'''

class TestCryptoPatterns:
    """Test cryptographic pattern definitions."""
    
    def test_python_patterns_structure(self):
        """Test Python pattern definitions are complete."""
        patterns = CryptoPatterns()
        
        assert 'rsa_generation' in patterns.PYTHON_PATTERNS
        assert 'ecc_generation' in patterns.PYTHON_PATTERNS
        assert 'dsa_generation' in patterns.PYTHON_PATTERNS
        assert 'diffie_hellman' in patterns.PYTHON_PATTERNS
        
        # Check that patterns are compiled regex patterns
        for pattern_list in patterns.PYTHON_PATTERNS.values():
            assert isinstance(pattern_list, list)
            assert len(pattern_list) > 0
    
    def test_java_patterns_structure(self):
        """Test Java pattern definitions are complete."""
        patterns = CryptoPatterns()
        
        assert 'rsa_generation' in patterns.JAVA_PATTERNS
        assert 'ecc_generation' in patterns.JAVA_PATTERNS
        assert 'dsa_generation' in patterns.JAVA_PATTERNS
        
    def test_all_language_patterns_exist(self):
        """Test all supported language patterns exist."""
        patterns = CryptoPatterns()
        
        assert hasattr(patterns, 'PYTHON_PATTERNS')
        assert hasattr(patterns, 'JAVA_PATTERNS')
        assert hasattr(patterns, 'GO_PATTERNS')
        assert hasattr(patterns, 'JAVASCRIPT_PATTERNS')
        assert hasattr(patterns, 'C_CPP_PATTERNS')


class TestCryptoAuditor:
    """Comprehensive tests for CryptoAuditor class."""
    
    def setup_method(self):
        """Set up test environment."""
        self.auditor = CryptoAuditor()
        self.temp_dir = tempfile.mkdtemp()
        
    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def create_test_file(self, content: str, filename: str) -> Path:
        """Create a test file with given content."""
        file_path = Path(self.temp_dir) / filename
        file_path.write_text(content, encoding='utf-8')
        return file_path
    
    def test_auditor_initialization(self):
        """Test CryptoAuditor initializes correctly."""
        auditor = CryptoAuditor()
        
        assert auditor.supported_extensions is not None
        assert '.py' in auditor.supported_extensions
        assert '.java' in auditor.supported_extensions
        assert '.go' in auditor.supported_extensions
        
        assert isinstance(auditor.patterns, CryptoPatterns)
        assert auditor.stats is not None
        
    def test_auditor_initialization_with_config(self):
        """Test CryptoAuditor initialization with configuration."""
        config = {
            'max_scan_time_seconds': 1800,
            'max_files_per_scan': 5000,
            'enable_security_validation': False
        }
        auditor = CryptoAuditor(config)
        
        assert auditor.max_scan_time == 1800
        assert auditor.max_files_per_scan == 5000
        assert auditor.enable_security_validation is False
    
    def test_detect_language(self):
        """Test language detection from file extensions."""
        test_cases = [
            ('test.py', 'python'),
            ('test.java', 'java'),
            ('test.go', 'go'),
            ('test.js', 'javascript'),
            ('test.ts', 'typescript'),
            ('test.c', 'c'),
            ('test.cpp', 'cpp'),
            ('test.txt', None),
        ]
        
        for filename, expected in test_cases:
            file_path = Path(filename)
            result = self.auditor._detect_language(file_path)
            assert result == expected, f"Failed for {filename}: expected {expected}, got {result}"
    
    def test_should_scan_file(self):
        """Test file scanning decision logic."""
        # Create test files
        python_file = Path(self.temp_dir) / "test.py"
        txt_file = Path(self.temp_dir) / "test.txt"
        node_modules_file = Path(self.temp_dir) / "node_modules" / "test.js"
        
        python_file.touch()
        txt_file.touch()
        node_modules_file.parent.mkdir(parents=True)
        node_modules_file.touch()
        
        exclude_patterns = ['*/node_modules/*', '*/test/*']
        
        # Should scan Python files
        assert self.auditor._should_scan_file(python_file, exclude_patterns)
        
        # Should not scan txt files
        assert not self.auditor._should_scan_file(txt_file, exclude_patterns)
        
        # Should not scan files in node_modules
        assert not self.auditor._should_scan_file(node_modules_file, exclude_patterns)
    
    def test_scan_python_file_rsa_vulnerabilities(self):
        """Test scanning Python files for RSA vulnerabilities."""
        file_path = self.create_test_file(PYTHON_RSA_CODE, "crypto_test.py")
        
        vulnerabilities = self.auditor._scan_file_safely(file_path, 'python')
        
        # Should find multiple RSA vulnerabilities
        rsa_vulns = [v for v in vulnerabilities if v.algorithm == CryptoAlgorithm.RSA]
        assert len(rsa_vulns) >= 2, f"Expected at least 2 RSA vulnerabilities, found {len(rsa_vulns)}"
        
        # Check vulnerability details
        for vuln in rsa_vulns:
            assert vuln.severity in [Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM]
            assert "RSA" in vuln.description
            assert "quantum-vulnerable" in vuln.description.lower()
            assert "ML-KEM" in vuln.recommendation or "Kyber" in vuln.recommendation
    
    def test_scan_python_file_ecc_vulnerabilities(self):
        """Test scanning Python files for ECC vulnerabilities."""
        file_path = self.create_test_file(PYTHON_ECC_CODE, "ecc_test.py")
        
        vulnerabilities = self.auditor._scan_file_safely(file_path, 'python')
        
        # Should find ECC vulnerabilities
        ecc_vulns = [v for v in vulnerabilities if v.algorithm == CryptoAlgorithm.ECC]
        assert len(ecc_vulns) >= 1, f"Expected at least 1 ECC vulnerability, found {len(ecc_vulns)}"
        
        # Check vulnerability details
        for vuln in ecc_vulns:
            assert vuln.severity == Severity.HIGH
            assert "ECC" in vuln.description
            assert "ML-DSA" in vuln.recommendation or "Dilithium" in vuln.recommendation
    
    def test_scan_java_file_vulnerabilities(self):
        """Test scanning Java files for vulnerabilities."""
        file_path = self.create_test_file(JAVA_RSA_CODE, "CryptoExample.java")
        
        vulnerabilities = self.auditor._scan_file_safely(file_path, 'java')
        
        # Should find Java RSA vulnerabilities
        assert len(vulnerabilities) >= 1
        java_rsa_vulns = [v for v in vulnerabilities if v.algorithm == CryptoAlgorithm.RSA]
        assert len(java_rsa_vulns) >= 1
        
        vuln = java_rsa_vulns[0]
        assert vuln.severity == Severity.HIGH
        assert "RSA" in vuln.description
        assert "ML-KEM" in vuln.recommendation
    
    def test_scan_go_file_vulnerabilities(self):
        """Test scanning Go files for vulnerabilities."""
        file_path = self.create_test_file(GO_RSA_CODE, "crypto_test.go")
        
        vulnerabilities = self.auditor._scan_file_safely(file_path, 'go')
        
        # Should find Go RSA vulnerabilities
        assert len(vulnerabilities) >= 1
        go_rsa_vulns = [v for v in vulnerabilities if v.algorithm == CryptoAlgorithm.RSA]
        assert len(go_rsa_vulns) >= 1
        
        vuln = go_rsa_vulns[0]
        assert vuln.severity == Severity.HIGH
        assert "RSA" in vuln.description
    
    def test_scan_javascript_file_vulnerabilities(self):
        """Test scanning JavaScript files for vulnerabilities."""
        file_path = self.create_test_file(JAVASCRIPT_RSA_CODE, "crypto_test.js")
        
        vulnerabilities = self.auditor._scan_file_safely(file_path, 'javascript')
        
        # Should find JavaScript RSA vulnerabilities
        assert len(vulnerabilities) >= 1
        js_rsa_vulns = [v for v in vulnerabilities if v.algorithm == CryptoAlgorithm.RSA]
        assert len(js_rsa_vulns) >= 1
        
        vuln = js_rsa_vulns[0]
        assert vuln.severity == Severity.HIGH
        assert "RSA" in vuln.description
    
    def test_scan_cpp_file_vulnerabilities(self):
        """Test scanning C++ files for vulnerabilities."""
        file_path = self.create_test_file(CPP_RSA_CODE, "crypto_test.cpp")
        
        vulnerabilities = self.auditor._scan_file_safely(file_path, 'cpp')
        
        # Should find C++ OpenSSL RSA vulnerabilities
        assert len(vulnerabilities) >= 1
        cpp_rsa_vulns = [v for v in vulnerabilities if v.algorithm == CryptoAlgorithm.RSA]
        assert len(cpp_rsa_vulns) >= 1
        
        vuln = cpp_rsa_vulns[0]
        assert vuln.severity == Severity.HIGH
        assert "OpenSSL RSA" in vuln.description
        assert "liboqs" in vuln.recommendation
    
    def test_scan_directory_basic(self):
        """Test basic directory scanning functionality."""
        # Create test files with vulnerabilities
        self.create_test_file(PYTHON_RSA_CODE, "python_crypto.py")
        self.create_test_file(JAVA_RSA_CODE, "JavaCrypto.java")
        self.create_test_file("# No crypto here", "safe_file.py")
        
        results = self.auditor.scan_directory(self.temp_dir)
        
        # Verify scan results structure
        assert isinstance(results, ScanResults)
        assert results.scan_path == self.temp_dir
        assert results.scanned_files >= 3
        assert len(results.vulnerabilities) >= 2  # At least from Python and Java files
        
        # Verify languages detected
        assert 'python' in results.languages_detected
        assert 'java' in results.languages_detected
        
        # Verify scan statistics
        assert results.scan_stats is not None
        assert results.scan_stats.files_processed >= 3
        
    def test_scan_directory_with_exclusions(self):
        """Test directory scanning with exclusion patterns."""
        # Create directory structure
        test_dir = Path(self.temp_dir) / "test"
        node_modules_dir = Path(self.temp_dir) / "node_modules"
        test_dir.mkdir()
        node_modules_dir.mkdir()
        
        # Create files
        self.create_test_file(PYTHON_RSA_CODE, "main.py")
        (test_dir / "test.py").write_text(PYTHON_ECC_CODE)
        (node_modules_dir / "lib.js").write_text(JAVASCRIPT_RSA_CODE)
        
        exclude_patterns = ['*/test/*', '*/node_modules/*']
        results = self.auditor.scan_directory(self.temp_dir, exclude_patterns=exclude_patterns)
        
        # Should only scan main.py, not files in excluded directories
        scanned_files = [v.file_path for v in results.vulnerabilities]
        main_py_scanned = any('main.py' in f for f in scanned_files)
        test_py_scanned = any('test.py' in f for f in scanned_files)
        lib_js_scanned = any('lib.js' in f for f in scanned_files)
        
        assert main_py_scanned, "main.py should be scanned"
        assert not test_py_scanned, "test.py should be excluded"
        assert not lib_js_scanned, "lib.js should be excluded"
    
    def test_scan_directory_incremental(self):
        """Test incremental scanning functionality."""
        # First scan
        self.create_test_file(PYTHON_RSA_CODE, "crypto1.py")
        results1 = self.auditor.scan_directory(self.temp_dir, incremental=True)
        
        initial_vulns = len(results1.vulnerabilities)
        assert initial_vulns > 0
        
        # Add new file and scan again
        self.create_test_file(JAVA_RSA_CODE, "Crypto2.java")
        results2 = self.auditor.scan_directory(self.temp_dir, incremental=True)
        
        # Should have more vulnerabilities from the new file
        assert len(results2.vulnerabilities) > initial_vulns
    
    def test_scan_single_file(self):
        """Test scanning a single file."""
        file_path = self.create_test_file(PYTHON_RSA_CODE, "single_crypto.py")
        
        results = self.auditor.scan_directory(str(file_path))
        
        assert results.scanned_files == 1
        assert len(results.vulnerabilities) >= 2  # RSA vulnerabilities
        assert all(vuln.file_path == str(file_path) for vuln in results.vulnerabilities)
    
    def test_analyze_rsa_usage(self):
        """Test RSA usage analysis for severity determination."""
        test_cases = [
            ("key_size=1024", (Severity.CRITICAL, 1024)),
            ("key_size=2048", (Severity.HIGH, 2048)),
            ("key_size=4096", (Severity.MEDIUM, 4096)),
            ("rsa.generate_private_key(", (Severity.HIGH, None)),
        ]
        
        for code_line, expected in test_cases:
            result = self.auditor._analyze_rsa_usage(code_line)
            assert result == expected, f"Failed for '{code_line}': expected {expected}, got {result}"
    
    def test_validate_vulnerability(self):
        """Test vulnerability validation."""
        # Valid vulnerability
        valid_vuln = Vulnerability(
            file_path="/test/file.py",
            line_number=10,
            algorithm=CryptoAlgorithm.RSA,
            severity=Severity.HIGH,
            description="Test vulnerability",
            code_snippet="test code",
            recommendation="Test recommendation"
        )
        
        assert self.auditor._validate_vulnerability(valid_vuln)
        
        # Invalid vulnerabilities
        invalid_vulns = [
            # Missing file path
            Vulnerability(
                file_path="",
                line_number=10,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.HIGH,
                description="Test",
                code_snippet="test",
                recommendation="test"
            ),
            # Invalid line number
            Vulnerability(
                file_path="/test/file.py",
                line_number=0,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.HIGH,
                description="Test",
                code_snippet="test",
                recommendation="test"
            ),
        ]
        
        for invalid_vuln in invalid_vulns:
            assert not self.auditor._validate_vulnerability(invalid_vuln)
    
    def test_create_migration_plan(self):
        """Test migration plan creation."""
        # Create scan results with various vulnerabilities
        vulnerabilities = [
            Vulnerability(
                file_path="/test/critical.py",
                line_number=1,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.CRITICAL,
                description="Critical RSA",
                code_snippet="test",
                recommendation="test"
            ),
            Vulnerability(
                file_path="/test/high.py",
                line_number=1,
                algorithm=CryptoAlgorithm.ECC,
                severity=Severity.HIGH,
                description="High ECC",
                code_snippet="test",
                recommendation="test"
            ),
            Vulnerability(
                file_path="/test/medium.py",
                line_number=1,
                algorithm=CryptoAlgorithm.DSA,
                severity=Severity.MEDIUM,
                description="Medium DSA",
                code_snippet="test",
                recommendation="test"
            ),
        ]
        
        scan_results = ScanResults(
            scan_path="/test",
            timestamp="2025-01-01 00:00:00",
            vulnerabilities=vulnerabilities,
            scanned_files=3,
            total_lines=100,
            scan_time=1.0,
            languages_detected=['python']
        )
        
        plan = self.auditor.create_migration_plan(scan_results)
        
        # Verify plan structure
        assert 'summary' in plan
        assert 'migration_phases' in plan
        assert 'recommendations' in plan
        
        # Verify summary
        summary = plan['summary']
        assert summary['total_vulnerabilities'] == 3
        assert summary['critical'] == 1
        assert summary['high'] == 1
        assert summary['medium'] == 1
        assert summary['low'] == 0
        
        # Verify migration phases
        phases = plan['migration_phases']
        assert len(phases) == 3
        assert phases[0]['phase'] == 1
        assert len(phases[0]['vulnerabilities']) == 2  # Critical + High
        assert len(phases[1]['vulnerabilities']) == 1  # Medium
        assert len(phases[2]['vulnerabilities']) == 0  # Low
    
    def test_scan_with_custom_patterns(self):
        """Test scanning with custom vulnerability patterns."""
        custom_patterns = {
            'deprecated_crypto': {
                'pattern': r'MD5\s*\(',
                'severity': 'MEDIUM',
                'description': 'Deprecated MD5 hash function detected'
            },
            'weak_random': {
                'pattern': r'random\.random\s*\(',
                'severity': 'HIGH',
                'description': 'Cryptographically weak random number generation'
            }
        }
        
        test_code = '''
import hashlib
import random

# Weak crypto usage
hash_md5 = MD5()
random_value = random.random()
'''
        
        file_path = self.create_test_file(test_code, "custom_test.py")
        results = self.auditor.scan_directory(self.temp_dir, custom_patterns=custom_patterns)
        
        # Should find custom pattern vulnerabilities
        custom_vulns = [v for v in results.vulnerabilities if 'deprecated_crypto' in v.description or 'weak_random' in v.description]
        assert len(custom_vulns) >= 2, f"Expected custom vulnerabilities, found: {[v.description for v in results.vulnerabilities]}"
    
    def test_error_handling_invalid_path(self):
        """Test error handling for invalid scan paths."""
        with pytest.raises((ValidationException, ScanException)):
            self.auditor.scan_directory("/nonexistent/path")
    
    def test_error_handling_permission_denied(self):
        """Test error handling for permission denied."""
        # Create a directory with restricted permissions
        restricted_dir = Path(self.temp_dir) / "restricted"
        restricted_dir.mkdir()
        restricted_dir.chmod(0o000)  # No permissions
        
        try:
            # This should handle permission errors gracefully
            results = self.auditor.scan_directory(str(restricted_dir))
            # Should return empty results without crashing
            assert isinstance(results, ScanResults)
        except (PermissionError, ScanException):
            # Also acceptable to raise a scan exception
            pass
        finally:
            # Restore permissions for cleanup
            restricted_dir.chmod(0o755)
    
    def test_large_file_handling(self):
        """Test handling of large files."""
        # Create a large file (simulated by mocking file size check)
        large_content = "# " + "a" * 1000 + "\n" * 1000
        file_path = self.create_test_file(large_content, "large_file.py")
        
        # Should handle large files without issues
        vulnerabilities = self.auditor._scan_file_safely(file_path, 'python')
        assert isinstance(vulnerabilities, list)  # Should return list, not crash


class TestRiskAssessment:
    """Test risk assessment functionality."""
    
    def setup_method(self):
        """Set up test environment."""
        # Create sample vulnerabilities for testing
        self.vulnerabilities = [
            Vulnerability(
                file_path="/test/critical_rsa.py",
                line_number=1,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.CRITICAL,
                key_size=1024,
                description="Critical RSA vulnerability",
                code_snippet="rsa.generate_private_key(key_size=1024)",
                recommendation="Upgrade to ML-KEM"
            ),
            Vulnerability(
                file_path="/test/high_ecc.py",
                line_number=5,
                algorithm=CryptoAlgorithm.ECC,
                severity=Severity.HIGH,
                description="High ECC vulnerability",
                code_snippet="ec.generate_private_key(ec.SECP256R1())",
                recommendation="Upgrade to ML-DSA"
            ),
            Vulnerability(
                file_path="/test/medium_dsa.py",
                line_number=10,
                algorithm=CryptoAlgorithm.DSA,
                severity=Severity.MEDIUM,
                description="Medium DSA vulnerability",
                code_snippet="dsa.generate_private_key(1024)",
                recommendation="Upgrade to ML-DSA"
            ),
        ]
        
        self.scan_results = ScanResults(
            scan_path="/test",
            timestamp="2025-01-01 00:00:00",
            vulnerabilities=self.vulnerabilities,
            scanned_files=3,
            total_lines=300,
            scan_time=2.5,
            languages_detected=['python'],
            scan_stats=ScanStats(
                scan_start_time=0.0,
                files_processed=3,
                files_skipped=0,
                errors_encountered=0,
                vulnerabilities_found=3
            )
        )
        
        self.risk_assessment = RiskAssessment(self.scan_results)
    
    def test_risk_assessment_initialization(self):
        """Test RiskAssessment initialization."""
        assert self.risk_assessment.results == self.scan_results
    
    def test_calculate_harvest_now_decrypt_later_risk(self):
        """Test HNDL risk calculation."""
        risk_score = self.risk_assessment.calculate_harvest_now_decrypt_later_risk()
        
        # Should return a risk score between 0 and 100
        assert 0 <= risk_score <= 100
        assert isinstance(risk_score, int)
        
        # With critical and high vulnerabilities, should have significant risk
        assert risk_score > 50  # Should be high risk
    
    def test_migration_hours_estimation(self):
        """Test migration effort estimation."""
        hours = self.risk_assessment.migration_hours
        
        # Should return positive hours
        assert hours > 0
        assert isinstance(hours, int)
        
        # Should account for different severity levels
        # Critical (16h) + High (8h) + Medium (4h) + 25% overhead = 35h
        expected_hours = int((16 + 8 + 4) * 1.25)
        assert hours == expected_hours
    
    def test_generate_risk_report(self):
        """Test comprehensive risk report generation."""
        report = self.risk_assessment.generate_risk_report()
        
        # Verify report structure
        assert 'risk_summary' in report
        assert 'vulnerability_breakdown' in report
        assert 'recommendations' in report
        
        # Verify risk summary
        risk_summary = report['risk_summary']
        assert 'hndl_risk_score' in risk_summary
        assert 'risk_level' in risk_summary
        assert 'total_vulnerabilities' in risk_summary
        assert 'migration_effort_hours' in risk_summary
        assert 'scan_metadata' in risk_summary
        
        assert risk_summary['total_vulnerabilities'] == 3
        assert risk_summary['hndl_risk_score'] > 0
        
        # Verify vulnerability breakdown
        breakdown = report['vulnerability_breakdown']
        assert 'by_severity' in breakdown
        assert 'by_algorithm' in breakdown
        assert 'by_file' in breakdown
        
        # Check severity breakdown
        severity_breakdown = breakdown['by_severity']
        assert severity_breakdown['critical'] == 1
        assert severity_breakdown['high'] == 1
        assert severity_breakdown['medium'] == 1
        assert severity_breakdown['low'] == 0
        
        # Check algorithm breakdown
        algorithm_breakdown = breakdown['by_algorithm']
        assert algorithm_breakdown['rsa'] == 1
        assert algorithm_breakdown['ecc'] == 1
        assert algorithm_breakdown['dsa'] == 1
        
        # Verify recommendations
        recommendations = report['recommendations']
        assert isinstance(recommendations, list)
        assert len(recommendations) > 0
        assert any('inventory' in rec.lower() for rec in recommendations)
    
    def test_risk_level_classification(self):
        """Test risk level classification."""
        test_cases = [
            (90, "CRITICAL"),
            (70, "HIGH"),
            (50, "MEDIUM"),
            (30, "LOW"),
            (10, "MINIMAL"),
        ]
        
        for score, expected_level in test_cases:
            level = self.risk_assessment._get_risk_level(score)
            assert level == expected_level, f"Score {score} should be {expected_level}, got {level}"
    
    def test_empty_vulnerability_list(self):
        """Test risk assessment with no vulnerabilities."""
        empty_results = ScanResults(
            scan_path="/test",
            timestamp="2025-01-01 00:00:00",
            vulnerabilities=[],
            scanned_files=5,
            total_lines=1000,
            scan_time=1.0,
            languages_detected=['python']
        )
        
        risk_assessment = RiskAssessment(empty_results)
        
        # Should handle empty vulnerability list
        assert risk_assessment.calculate_harvest_now_decrypt_later_risk() == 0
        assert risk_assessment.migration_hours == 0
        
        report = risk_assessment.generate_risk_report()
        assert report['risk_summary']['total_vulnerabilities'] == 0
        assert report['risk_summary']['hndl_risk_score'] == 0


class TestIntegrationScenarios:
    """Integration tests for complete workflows."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.auditor = CryptoAuditor()
    
    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def create_test_project(self):
        """Create a realistic test project structure."""
        project_files = {
            'src/main.py': PYTHON_RSA_CODE + "\n" + PYTHON_ECC_CODE,
            'src/utils.py': '''
import hashlib

def weak_hash(data):
    # This would be flagged by custom patterns
    return hashlib.md5(data.encode()).hexdigest()
''',
            'java/CryptoService.java': JAVA_RSA_CODE,
            'js/client.js': JAVASCRIPT_RSA_CODE,
            'cpp/crypto_impl.cpp': CPP_RSA_CODE,
            'go/server.go': GO_RSA_CODE,
            'README.md': '# Test Project',
            'requirements.txt': 'cryptography==41.0.0',
        }
        
        for rel_path, content in project_files.items():
            file_path = Path(self.temp_dir) / rel_path
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content, encoding='utf-8')
    
    def test_complete_project_scan(self):
        """Test scanning a complete multi-language project."""
        self.create_test_project()
        
        results = self.auditor.scan_directory(self.temp_dir)
        
        # Verify comprehensive scan results
        assert len(results.vulnerabilities) >= 6  # Multiple vulnerabilities across languages
        assert results.scanned_files >= 5  # Multiple source files
        
        # Verify all languages detected
        expected_languages = {'python', 'java', 'javascript', 'cpp', 'go'}
        detected_languages = set(results.languages_detected)
        assert expected_languages.issubset(detected_languages)
        
        # Verify algorithm diversity
        algorithms_found = {vuln.algorithm for vuln in results.vulnerabilities}
        assert CryptoAlgorithm.RSA in algorithms_found
        assert CryptoAlgorithm.ECC in algorithms_found
        
        # Test risk assessment
        risk_assessment = RiskAssessment(results)
        risk_score = risk_assessment.calculate_harvest_now_decrypt_later_risk()
        assert risk_score > 60  # Should be high risk with multiple vulnerabilities
        
        # Test migration planning
        migration_plan = self.auditor.create_migration_plan(results)
        assert migration_plan['summary']['total_vulnerabilities'] >= 6
        assert len(migration_plan['migration_phases']) == 3
    
    def test_end_to_end_workflow(self):
        """Test complete end-to-end workflow."""
        # 1. Create project
        self.create_test_project()
        
        # 2. Scan project
        scan_results = self.auditor.scan_directory(self.temp_dir)
        assert len(scan_results.vulnerabilities) > 0
        
        # 3. Assess risk
        risk_assessment = RiskAssessment(scan_results)
        risk_report = risk_assessment.generate_risk_report()
        assert risk_report['risk_summary']['hndl_risk_score'] > 0
        
        # 4. Create migration plan
        migration_plan = self.auditor.create_migration_plan(scan_results)
        assert len(migration_plan['migration_phases']) > 0
        
        # 5. Verify comprehensive output
        assert 'ML-KEM' in str(migration_plan) or 'Kyber' in str(migration_plan)
        assert 'ML-DSA' in str(migration_plan) or 'Dilithium' in str(migration_plan)


if __name__ == "__main__":
    # Run tests with coverage reporting
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "--cov=src/pqc_migration_audit",
        "--cov-report=term-missing",
        "--cov-report=html:htmlcov_gen1",
        "--cov-fail-under=80"
    ])