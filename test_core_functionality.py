#!/usr/bin/env python3
"""
Core functionality tests that focus on basic scanning without complex logging.
Designed to achieve good coverage on essential functionality.
"""

import os
import sys
import tempfile
import pytest
from pathlib import Path
from unittest.mock import Mock, patch

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from pqc_migration_audit.types import *
from pqc_migration_audit.exceptions import *


class TestBasicAuditor:
    """Test basic auditor functionality without enhanced features."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        
        # Mock the enhanced features to avoid import issues
        with patch.dict('sys.modules', {
            'pqc_migration_audit.logging_config': Mock(),
            'pqc_migration_audit.security_enhanced': Mock(),
            'pqc_migration_audit.resilience_framework': Mock(),
        }):
            # Import with mocked dependencies
            from pqc_migration_audit.core import CryptoAuditor, RiskAssessment
            self.CryptoAuditor = CryptoAuditor
            self.RiskAssessment = RiskAssessment
        
        # Create basic auditor without enhanced features
        self.auditor = self.CryptoAuditor({})
    
    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_basic_python_scanning(self):
        """Test basic Python file scanning."""
        python_code = '''
import rsa
from cryptography.hazmat.primitives.asymmetric import ec

# RSA vulnerability
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# ECC vulnerability
ecc_key = ec.generate_private_key(ec.SECP256R1())
'''
        
        file_path = Path(self.temp_dir) / "test.py"
        file_path.write_text(python_code)
        
        # Mock logger to avoid AuditLogger issues
        self.auditor.logger = Mock()
        self.auditor.logger.warning = Mock()
        self.auditor.logger.error = Mock()
        self.auditor.logger.info = Mock()
        self.auditor.logger.debug = Mock()
        
        results = self.auditor.scan_directory(self.temp_dir)
        
        assert isinstance(results, ScanResults)
        assert results.scanned_files >= 1
        assert len(results.vulnerabilities) >= 2  # RSA + ECC
        
        # Check RSA vulnerability
        rsa_vulns = [v for v in results.vulnerabilities if v.algorithm == CryptoAlgorithm.RSA]
        assert len(rsa_vulns) >= 1
        
        # Check ECC vulnerability  
        ecc_vulns = [v for v in results.vulnerabilities if v.algorithm == CryptoAlgorithm.ECC]
        assert len(ecc_vulns) >= 1
    
    def test_multiple_languages(self):
        """Test scanning multiple languages."""
        test_files = {
            'crypto.py': '''
import rsa
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
''',
            'Crypto.java': '''
import java.security.KeyPairGenerator;
public class Crypto {
    public void generateKey() {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
    }
}
''',
            'crypto.go': '''
package main
import (
    "crypto/rsa"
    "crypto/rand"
)
func main() {
    rsa.GenerateKey(rand.Reader, 2048)
}
''',
            'crypto.js': '''
const crypto = require('crypto');
crypto.generateKeyPair('rsa', { modulusLength: 2048 }, (err, pub, priv) => {});
''',
            'crypto.cpp': '''
#include <openssl/rsa.h>
int main() {
    RSA* rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    return 0;
}
'''
        }
        
        for filename, content in test_files.items():
            file_path = Path(self.temp_dir) / filename
            file_path.write_text(content)
        
        # Mock logger
        self.auditor.logger = Mock()
        self.auditor.logger.warning = Mock()
        self.auditor.logger.error = Mock()
        self.auditor.logger.info = Mock()
        self.auditor.logger.debug = Mock()
        
        results = self.auditor.scan_directory(self.temp_dir)
        
        assert isinstance(results, ScanResults)
        assert results.scanned_files == 5
        assert len(results.vulnerabilities) >= 5  # At least one per file
        assert len(set(results.languages_detected)) >= 4  # Multiple languages
    
    def test_risk_assessment_basic(self):
        """Test basic risk assessment functionality."""
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
                file_path="/test/high.py",
                line_number=5,
                algorithm=CryptoAlgorithm.ECC,
                severity=Severity.HIGH,
                description="High ECC vulnerability", 
                code_snippet="ec.generate_private_key(ec.SECP256R1())",
                recommendation="Migrate to ML-DSA"
            ),
        ]
        
        scan_results = ScanResults(
            scan_path="/test",
            timestamp="2025-01-01 00:00:00",
            vulnerabilities=vulnerabilities,
            scanned_files=2,
            total_lines=200,
            scan_time=1.5,
            languages_detected=['python']
        )
        
        risk_assessment = self.RiskAssessment(scan_results)
        
        # Test risk calculation
        risk_score = risk_assessment.calculate_harvest_now_decrypt_later_risk()
        assert 0 <= risk_score <= 100
        assert risk_score > 50  # Should be high risk
        
        # Test migration hours
        hours = risk_assessment.migration_hours
        assert hours > 0
        expected = int((16 + 8) * 1.25)  # Critical + High + overhead
        assert hours == expected
        
        # Test risk report
        report = risk_assessment.generate_risk_report()
        assert 'risk_summary' in report
        assert 'vulnerability_breakdown' in report
        assert 'recommendations' in report
        
        summary = report['risk_summary']
        assert summary['total_vulnerabilities'] == 2
        assert summary['hndl_risk_score'] == risk_score
        
        breakdown = report['vulnerability_breakdown']
        assert breakdown['by_severity']['critical'] == 1
        assert breakdown['by_severity']['high'] == 1
        assert breakdown['by_algorithm']['rsa'] == 1
        assert breakdown['by_algorithm']['ecc'] == 1
    
    def test_migration_plan_creation(self):
        """Test migration plan creation."""
        # Create vulnerabilities with different severities
        vulnerabilities = []
        for i in range(2):
            vulnerabilities.extend([
                Vulnerability(
                    file_path=f"/test/critical_{i}.py",
                    line_number=i+1,
                    algorithm=CryptoAlgorithm.RSA,
                    severity=Severity.CRITICAL,
                    description=f"Critical vulnerability {i}",
                    code_snippet="critical code",
                    recommendation="Fix immediately"
                ),
                Vulnerability(
                    file_path=f"/test/high_{i}.py",
                    line_number=i+1,
                    algorithm=CryptoAlgorithm.ECC,
                    severity=Severity.HIGH,
                    description=f"High vulnerability {i}",
                    code_snippet="high code", 
                    recommendation="Fix soon"
                ),
                Vulnerability(
                    file_path=f"/test/medium_{i}.py",
                    line_number=i+1,
                    algorithm=CryptoAlgorithm.DSA,
                    severity=Severity.MEDIUM,
                    description=f"Medium vulnerability {i}",
                    code_snippet="medium code",
                    recommendation="Plan migration"
                ),
            ])
        
        scan_results = ScanResults(
            scan_path="/test",
            timestamp="2025-01-01 00:00:00", 
            vulnerabilities=vulnerabilities,
            scanned_files=6,
            total_lines=600,
            scan_time=3.0,
            languages_detected=['python']
        )
        
        plan = self.auditor.create_migration_plan(scan_results)
        
        # Verify plan structure
        assert 'summary' in plan
        assert 'migration_phases' in plan
        assert 'recommendations' in plan
        
        # Verify summary
        summary = plan['summary']
        assert summary['total_vulnerabilities'] == 6
        assert summary['critical'] == 2
        assert summary['high'] == 2
        assert summary['medium'] == 2
        
        # Verify phases
        phases = plan['migration_phases']
        assert len(phases) == 3
        
        # Phase 1: Critical + High (4 total)
        assert phases[0]['phase'] == 1
        assert len(phases[0]['vulnerabilities']) == 4
        
        # Phase 2: Medium (2 total)
        assert phases[1]['phase'] == 2
        assert len(phases[1]['vulnerabilities']) == 2
        
        # Phase 3: Low (0 total)
        assert phases[2]['phase'] == 3
        assert len(phases[2]['vulnerabilities']) == 0
        
        # Verify recommendations
        recommendations = plan['recommendations']
        assert 'immediate_actions' in recommendations
        assert 'pqc_algorithms' in recommendations
        assert 'migration_strategy' in recommendations
        
        pqc_algorithms = recommendations['pqc_algorithms']
        assert 'key_exchange' in pqc_algorithms
        assert 'digital_signatures' in pqc_algorithms
    
    def test_language_detection(self):
        """Test language detection from file extensions."""
        test_cases = [
            ('test.py', 'python'),
            ('Test.java', 'java'),
            ('test.go', 'go'),
            ('test.js', 'javascript'),
            ('test.ts', 'typescript'),
            ('test.c', 'c'),
            ('test.cpp', 'cpp'),
            ('test.txt', None),
            ('README.md', None),
        ]
        
        for filename, expected_language in test_cases:
            file_path = Path(filename)
            detected = self.auditor._detect_language(file_path)
            assert detected == expected_language, f"Failed for {filename}: expected {expected_language}, got {detected}"
    
    def test_rsa_analysis(self):
        """Test RSA usage analysis for severity determination."""
        test_cases = [
            ("key_size=512", (Severity.CRITICAL, 512)),
            ("key_size=1024", (Severity.CRITICAL, 1024)),
            ("key_size=2048", (Severity.HIGH, 2048)),
            ("key_size=4096", (Severity.MEDIUM, 4096)),
            ("rsa.generate_private_key(", (Severity.HIGH, None)),
        ]
        
        for code_line, expected in test_cases:
            result = self.auditor._analyze_rsa_usage(code_line)
            assert result == expected, f"Failed for '{code_line}': expected {expected}, got {result}"
    
    def test_vulnerability_validation(self):
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
        invalid_cases = [
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
            # Missing description
            Vulnerability(
                file_path="/test/file.py",
                line_number=10,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.HIGH,
                description="",
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
        
        for invalid_vuln in invalid_cases:
            assert not self.auditor._validate_vulnerability(invalid_vuln)


class TestTypesModule:
    """Test types module comprehensively."""
    
    def test_severity_enum(self):
        """Test Severity enum values."""
        assert Severity.LOW.value == "low"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.HIGH.value == "high"
        assert Severity.CRITICAL.value == "critical"
        
        # Test enum iteration
        severities = list(Severity)
        assert len(severities) == 4
    
    def test_crypto_algorithm_enum(self):
        """Test CryptoAlgorithm enum values."""
        assert CryptoAlgorithm.RSA.value == "rsa"
        assert CryptoAlgorithm.ECC.value == "ecc"
        assert CryptoAlgorithm.DSA.value == "dsa"
        assert CryptoAlgorithm.DH.value == "dh"
        assert CryptoAlgorithm.ECDSA.value == "ecdsa"
        assert CryptoAlgorithm.ECDH.value == "ecdh"
        
        # Test enum iteration
        algorithms = list(CryptoAlgorithm)
        assert len(algorithms) == 6
    
    def test_vulnerability_dataclass(self):
        """Test Vulnerability dataclass."""
        vuln = Vulnerability(
            file_path="/test/file.py",
            line_number=15,
            algorithm=CryptoAlgorithm.RSA,
            severity=Severity.HIGH,
            key_size=2048,
            description="RSA vulnerability found",
            code_snippet="rsa.generate_private_key()",
            recommendation="Use ML-KEM instead",
            cwe_id="CWE-327"
        )
        
        assert vuln.file_path == "/test/file.py"
        assert vuln.line_number == 15
        assert vuln.algorithm == CryptoAlgorithm.RSA
        assert vuln.severity == Severity.HIGH
        assert vuln.key_size == 2048
        assert vuln.description == "RSA vulnerability found"
        assert vuln.code_snippet == "rsa.generate_private_key()"
        assert vuln.recommendation == "Use ML-KEM instead"
        assert vuln.cwe_id == "CWE-327"
    
    def test_scan_stats_dataclass(self):
        """Test ScanStats dataclass."""
        stats = ScanStats(
            files_processed=100,
            files_skipped=5,
            errors_encountered=2,
            vulnerabilities_found=25,
            scan_start_time=1234567890.0,
            performance_metrics={'cpu_usage': 45.2, 'memory_mb': 128}
        )
        
        assert stats.files_processed == 100
        assert stats.files_skipped == 5
        assert stats.errors_encountered == 2
        assert stats.vulnerabilities_found == 25
        assert stats.scan_start_time == 1234567890.0
        assert stats.performance_metrics['cpu_usage'] == 45.2
        assert stats.performance_metrics['memory_mb'] == 128
    
    def test_scan_results_dataclass(self):
        """Test ScanResults dataclass."""
        vuln = Vulnerability(
            file_path="/test/file.py",
            line_number=1,
            algorithm=CryptoAlgorithm.RSA,
            severity=Severity.HIGH,
            description="Test vulnerability",
            code_snippet="test",
            recommendation="test"
        )
        
        stats = ScanStats(
            files_processed=1,
            vulnerabilities_found=1
        )
        
        results = ScanResults(
            vulnerabilities=[vuln],
            scanned_files=1,
            total_lines=50,
            scan_time=1.5,
            scan_path="/test",
            timestamp="2025-01-01 00:00:00",
            languages_detected=['python'],
            metadata={'version': '1.0'},
            scan_stats=stats
        )
        
        assert len(results.vulnerabilities) == 1
        assert results.scanned_files == 1
        assert results.total_lines == 50
        assert results.scan_time == 1.5
        assert results.scan_path == "/test"
        assert results.timestamp == "2025-01-01 00:00:00"
        assert 'python' in results.languages_detected
        assert results.metadata['version'] == '1.0'
        assert results.scan_stats == stats
    
    def test_validation_result_dataclass(self):
        """Test ValidationResult dataclass."""
        # Valid result
        valid_result = ValidationResult(
            is_valid=True,
            error_message=None,
            warnings=['Warning 1', 'Warning 2']
        )
        
        assert valid_result.is_valid is True
        assert valid_result.error_message is None
        assert len(valid_result.warnings) == 2
        assert 'Warning 1' in valid_result.warnings
        
        # Invalid result
        invalid_result = ValidationResult(
            is_valid=False,
            error_message="Validation failed",
            warnings=[]
        )
        
        assert invalid_result.is_valid is False
        assert invalid_result.error_message == "Validation failed"
        assert len(invalid_result.warnings) == 0


class TestExceptionsModule:
    """Test exceptions module."""
    
    def test_scan_exception(self):
        """Test ScanException."""
        ex = ScanException(
            "Scan operation failed",
            error_code="SCAN_FAILED",
            details={'file_count': 100, 'error_file': 'bad.py'}
        )
        
        assert str(ex) == "Scan operation failed"
        assert ex.error_code == "SCAN_FAILED"
        assert ex.details['file_count'] == 100
        assert ex.details['error_file'] == 'bad.py'
        assert isinstance(ex, Exception)
    
    def test_validation_exception(self):
        """Test ValidationException."""
        ex = ValidationException(
            "Invalid input provided",
            error_code="INVALID_INPUT"
        )
        
        assert str(ex) == "Invalid input provided"
        assert ex.error_code == "INVALID_INPUT"
        assert isinstance(ex, Exception)
    
    def test_security_exception(self):
        """Test SecurityException."""
        ex = SecurityException(
            "Security violation detected",
            error_code="SECURITY_VIOLATION"
        )
        
        assert str(ex) == "Security violation detected"
        assert ex.error_code == "SECURITY_VIOLATION"
        assert isinstance(ex, Exception)
    
    def test_filesystem_exception(self):
        """Test FileSystemException."""
        ex = FileSystemException(
            "File system access denied",
            error_code="ACCESS_DENIED"
        )
        
        assert str(ex) == "File system access denied"
        assert ex.error_code == "ACCESS_DENIED"
        assert isinstance(ex, Exception)
    
    def test_scan_timeout_exception(self):
        """Test ScanTimeoutException."""
        ex = ScanTimeoutException(
            timeout_seconds=300,
            files_processed=150
        )
        
        assert "300" in str(ex)
        assert "150" in str(ex)
        assert ex.timeout_seconds == 300
        assert ex.files_processed == 150
        assert isinstance(ex, Exception)


if __name__ == "__main__":
    # Run tests with coverage on core modules
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "--cov=src/pqc_migration_audit/types.py",
        "--cov=src/pqc_migration_audit/exceptions.py",
        "--cov-report=term-missing",
        "--cov-report=html:htmlcov_core",
        "--cov-fail-under=80"
    ])