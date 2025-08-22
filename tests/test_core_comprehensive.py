"""Comprehensive test suite for core PQC Migration Audit functionality."""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from dataclasses import dataclass

from src.pqc_migration_audit.core import (
    CryptoAuditor, CryptoPatterns, FileAnalyzer, RiskAssessment
)
from src.pqc_migration_audit.types import (
    Vulnerability, Severity, CryptoAlgorithm, ScanResults, ScanStats
)
from src.pqc_migration_audit.exceptions import (
    ScanException, ValidationException, FileSystemException
)


class TestCryptoPatterns:
    """Test cryptographic pattern detection."""

    def test_python_rsa_patterns(self):
        """Test RSA pattern matching in Python code."""
        patterns = CryptoPatterns.PYTHON_PATTERNS['rsa_generation']
        test_code = "private_key = rsa.generate_private_key(public_exponent=65537)"
        
        assert any(re.search(pattern, test_code) for pattern in patterns)

    def test_python_ecc_patterns(self):
        """Test ECC pattern matching in Python code."""
        patterns = CryptoPatterns.PYTHON_PATTERNS['ecc_generation']
        test_code = "private_key = ec.generate_private_key(ec.SECP256R1())"
        
        assert any(re.search(pattern, test_code) for pattern in patterns)

    def test_java_rsa_patterns(self):
        """Test RSA pattern matching in Java code."""
        patterns = CryptoPatterns.JAVA_PATTERNS['rsa_generation']
        test_code = 'KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");'
        
        assert any(re.search(pattern, test_code) for pattern in patterns)

    def test_go_crypto_patterns(self):
        """Test Go cryptographic pattern matching."""
        patterns = CryptoPatterns.GO_PATTERNS['rsa_generation']
        test_code = "rsa.GenerateKey(rand.Reader, 2048)"
        
        assert any(re.search(pattern, test_code) for pattern in patterns)


class TestFileAnalyzer:
    """Test file analysis functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = FileAnalyzer()

    def test_analyze_python_file_with_vulnerabilities(self, temp_repo, sample_vulnerable_code):
        """Test analyzing Python file containing vulnerabilities."""
        # Create temp file with vulnerable code
        test_file = temp_repo / "vulnerable.py"
        test_file.write_text(sample_vulnerable_code["rsa_key_gen.py"])
        
        results = self.analyzer.analyze_file(test_file)
        
        assert len(results) > 0
        assert any(vuln.algorithm == CryptoAlgorithm.RSA for vuln in results)
        assert any(vuln.severity == Severity.HIGH for vuln in results)

    def test_analyze_secure_file(self, temp_repo, sample_secure_code):
        """Test analyzing file with PQC-secure code."""
        test_file = temp_repo / "secure.py"
        test_file.write_text(sample_secure_code["kyber_kem.py"])
        
        results = self.analyzer.analyze_file(test_file)
        
        # Should find no vulnerabilities in PQC-secure code
        assert len(results) == 0

    def test_analyze_nonexistent_file(self):
        """Test analyzing a file that doesn't exist."""
        nonexistent_file = Path("/nonexistent/file.py")
        
        with pytest.raises(FileSystemException):
            self.analyzer.analyze_file(nonexistent_file)

    def test_analyze_empty_file(self, temp_repo):
        """Test analyzing an empty file."""
        empty_file = temp_repo / "empty.py"
        empty_file.write_text("")
        
        results = self.analyzer.analyze_file(empty_file)
        assert len(results) == 0

    def test_analyze_binary_file(self, temp_repo):
        """Test analyzing a binary file."""
        binary_file = temp_repo / "binary.bin"
        binary_file.write_bytes(b'\x00\x01\x02\x03\xff\xfe')
        
        # Should handle binary files gracefully
        results = self.analyzer.analyze_file(binary_file)
        assert isinstance(results, list)

    @patch('src.pqc_migration_audit.core.FileAnalyzer._is_supported_file')
    def test_unsupported_file_type(self, mock_is_supported, temp_repo):
        """Test handling of unsupported file types."""
        mock_is_supported.return_value = False
        
        test_file = temp_repo / "unsupported.xyz"
        test_file.write_text("some content")
        
        results = self.analyzer.analyze_file(test_file)
        assert len(results) == 0


class TestCryptoAuditor:
    """Test the main CryptoAuditor class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.auditor = CryptoAuditor()

    def test_scan_directory(self, temp_repo, sample_vulnerable_code):
        """Test scanning a directory with vulnerable files."""
        # Create multiple test files
        for filename, content in sample_vulnerable_code.items():
            test_file = temp_repo / filename
            test_file.write_text(content)
        
        results = self.auditor.scan_directory(temp_repo)
        
        assert isinstance(results, ScanResults)
        assert len(results.vulnerabilities) > 0
        assert results.scanned_files > 0
        assert results.scan_time > 0

    def test_scan_single_file(self, temp_repo, sample_vulnerable_code):
        """Test scanning a single file."""
        test_file = temp_repo / "test.py"
        test_file.write_text(sample_vulnerable_code["rsa_key_gen.py"])
        
        results = self.auditor.scan_file(test_file)
        
        assert isinstance(results, ScanResults)
        assert len(results.vulnerabilities) > 0

    def test_scan_with_filters(self, temp_repo, sample_vulnerable_code):
        """Test scanning with file type filters."""
        # Create files of different types
        py_file = temp_repo / "test.py"
        py_file.write_text(sample_vulnerable_code["rsa_key_gen.py"])
        
        java_file = temp_repo / "Test.java"
        java_file.write_text('KeyPairGenerator.getInstance("RSA");')
        
        txt_file = temp_repo / "readme.txt"
        txt_file.write_text("This is a text file")
        
        # Scan only Python files
        results = self.auditor.scan_directory(temp_repo, file_extensions=['.py'])
        
        assert results.scanned_files == 1
        assert any('.py' in lang for lang in results.languages_detected)

    def test_scan_with_severity_threshold(self, temp_repo, sample_vulnerable_code):
        """Test scanning with severity threshold filtering."""
        test_file = temp_repo / "test.py"
        test_file.write_text(sample_vulnerable_code["rsa_key_gen.py"])
        
        # Scan with high severity threshold
        results = self.auditor.scan_directory(temp_repo, min_severity=Severity.HIGH)
        
        high_severity_count = sum(1 for v in results.vulnerabilities 
                                if v.severity in [Severity.HIGH, Severity.CRITICAL])
        assert len(results.vulnerabilities) == high_severity_count

    def test_scan_performance_tracking(self, temp_repo):
        """Test that scan performance metrics are tracked."""
        # Create a reasonably sized test file
        test_file = temp_repo / "large_test.py"
        content = "# Large test file\n" + "print('hello')\n" * 1000
        test_file.write_text(content)
        
        results = self.auditor.scan_directory(temp_repo)
        
        assert results.scan_time > 0
        assert results.total_lines > 0
        assert hasattr(results, 'scan_stats')

    @patch('src.pqc_migration_audit.core.FileAnalyzer.analyze_file')
    def test_scan_error_handling(self, mock_analyze, temp_repo):
        """Test error handling during scan operations."""
        # Make analyze_file raise an exception
        mock_analyze.side_effect = Exception("Test error")
        
        test_file = temp_repo / "test.py"
        test_file.write_text("print('hello')")
        
        # Should not raise exception, but handle gracefully
        results = self.auditor.scan_directory(temp_repo)
        assert isinstance(results, ScanResults)

    def test_empty_directory_scan(self, temp_repo):
        """Test scanning an empty directory."""
        results = self.auditor.scan_directory(temp_repo)
        
        assert isinstance(results, ScanResults)
        assert len(results.vulnerabilities) == 0
        assert results.scanned_files == 0

    def test_scan_with_exclusions(self, temp_repo, sample_vulnerable_code):
        """Test scanning with file exclusions."""
        # Create test files
        include_file = temp_repo / "include.py"
        include_file.write_text(sample_vulnerable_code["rsa_key_gen.py"])
        
        exclude_file = temp_repo / "exclude.py"
        exclude_file.write_text(sample_vulnerable_code["ecdsa_signing.py"])
        
        # Scan excluding specific file
        results = self.auditor.scan_directory(
            temp_repo, 
            exclude_patterns=['exclude.py']
        )
        
        # Should only scan the included file
        assert results.scanned_files == 1


class TestRiskAssessment:
    """Test risk assessment functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.risk_assessor = RiskAssessment()

    def test_calculate_risk_score(self):
        """Test risk score calculation."""
        vulnerabilities = [
            Vulnerability(
                file_path="test1.py",
                line_number=1,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.HIGH,
                key_size=1024
            ),
            Vulnerability(
                file_path="test2.py", 
                line_number=2,
                algorithm=CryptoAlgorithm.ECC,
                severity=Severity.MEDIUM,
                key_size=256
            )
        ]
        
        risk_score = self.risk_assessor.calculate_risk_score(vulnerabilities)
        
        assert isinstance(risk_score, (int, float))
        assert 0 <= risk_score <= 100

    def test_risk_score_empty_vulnerabilities(self):
        """Test risk score with no vulnerabilities."""
        risk_score = self.risk_assessor.calculate_risk_score([])
        assert risk_score == 0

    def test_risk_score_critical_vulnerabilities(self):
        """Test risk score with critical vulnerabilities."""
        critical_vulns = [
            Vulnerability(
                file_path="critical.py",
                line_number=1,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.CRITICAL,
                key_size=512  # Very weak key
            )
        ]
        
        risk_score = self.risk_assessor.calculate_risk_score(critical_vulns)
        assert risk_score > 80  # Should be high risk

    def test_generate_recommendations(self):
        """Test recommendation generation."""
        vulnerabilities = [
            Vulnerability(
                file_path="test.py",
                line_number=1,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.HIGH
            )
        ]
        
        recommendations = self.risk_assessor.generate_recommendations(vulnerabilities)
        
        assert isinstance(recommendations, list)
        assert len(recommendations) > 0
        assert all(isinstance(rec, str) for rec in recommendations)

    def test_assessment_with_mixed_algorithms(self):
        """Test assessment with multiple algorithm types."""
        mixed_vulns = [
            Vulnerability(
                file_path="rsa_test.py",
                line_number=1,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.HIGH
            ),
            Vulnerability(
                file_path="ecc_test.py",
                line_number=1,
                algorithm=CryptoAlgorithm.ECC,
                severity=Severity.MEDIUM
            ),
            Vulnerability(
                file_path="dsa_test.py",
                line_number=1,
                algorithm=CryptoAlgorithm.DSA,
                severity=Severity.LOW
            )
        ]
        
        risk_score = self.risk_assessor.calculate_risk_score(mixed_vulns)
        recommendations = self.risk_assessor.generate_recommendations(mixed_vulns)
        
        assert risk_score > 0
        assert len(recommendations) >= len(set(v.algorithm for v in mixed_vulns))


# Integration tests
class TestIntegration:
    """Integration tests for core functionality."""

    def test_full_scan_workflow(self, temp_repo, sample_vulnerable_code, sample_config_files):
        """Test complete scan workflow from start to finish."""
        # Set up test repository with various file types
        for filename, content in sample_vulnerable_code.items():
            file_path = temp_repo / filename
            file_path.write_text(content)
        
        for filename, content in sample_config_files.items():
            file_path = temp_repo / filename  
            file_path.write_text(content)
        
        # Execute full scan
        auditor = CryptoAuditor()
        results = auditor.scan_directory(temp_repo)
        
        # Validate comprehensive results
        assert isinstance(results, ScanResults)
        assert len(results.vulnerabilities) > 0
        assert results.scanned_files > 0
        assert results.scan_time > 0
        assert len(results.languages_detected) > 0
        
        # Validate risk assessment
        risk_assessor = RiskAssessment()
        risk_score = risk_assessor.calculate_risk_score(results.vulnerabilities)
        recommendations = risk_assessor.generate_recommendations(results.vulnerabilities)
        
        assert isinstance(risk_score, (int, float))
        assert isinstance(recommendations, list)

    def test_scan_with_all_supported_languages(self, temp_repo):
        """Test scanning files in all supported languages."""
        # Create files for different languages
        test_files = {
            "test.py": 'rsa.generate_private_key()',
            "Test.java": 'KeyPairGenerator.getInstance("RSA")',
            "test.go": 'rsa.GenerateKey(rand.Reader, 2048)',
            "test.js": 'crypto.generateKeyPair("rsa")',
            "test.cpp": 'RSA_generate_key_ex()',
            "test.c": 'RSA_generate_key()',
            "config.yaml": 'cipher_suite: RSA-2048',
            "ssl.conf": 'SSLCipherSuite ECDHE-RSA-AES256'
        }
        
        for filename, content in test_files.items():
            file_path = temp_repo / filename
            file_path.write_text(content)
        
        auditor = CryptoAuditor()
        results = auditor.scan_directory(temp_repo)
        
        # Should detect vulnerabilities across multiple languages
        assert len(results.vulnerabilities) > 0
        assert len(results.languages_detected) > 1


# Performance and stress tests
class TestPerformance:
    """Performance and stress tests."""

    @pytest.mark.performance
    def test_scan_performance_large_files(self, temp_repo):
        """Test scan performance with large files."""
        # Create a large file with scattered vulnerabilities
        large_content = []
        for i in range(1000):
            if i % 100 == 0:
                large_content.append("private_key = rsa.generate_private_key()")
            else:
                large_content.append(f"# Comment line {i}")
        
        large_file = temp_repo / "large_file.py"
        large_file.write_text("\n".join(large_content))
        
        auditor = CryptoAuditor()
        import time
        start_time = time.time()
        
        results = auditor.scan_file(large_file)
        
        scan_duration = time.time() - start_time
        
        # Performance assertions
        assert scan_duration < 5.0  # Should complete within 5 seconds
        assert len(results.vulnerabilities) == 10  # Should find all 10 vulnerabilities

    @pytest.mark.performance
    def test_scan_many_small_files(self, temp_repo):
        """Test scanning many small files."""
        # Create many small files
        for i in range(100):
            file_path = temp_repo / f"file_{i}.py"
            content = f"# File {i}\nprint('hello')"
            if i % 10 == 0:
                content += "\nrsa.generate_private_key()"
            file_path.write_text(content)
        
        auditor = CryptoAuditor()
        import time
        start_time = time.time()
        
        results = auditor.scan_directory(temp_repo)
        
        scan_duration = time.time() - start_time
        
        # Performance assertions
        assert scan_duration < 10.0  # Should complete within 10 seconds
        assert results.scanned_files == 100
        assert len(results.vulnerabilities) == 10  # One per every 10th file


if __name__ == "__main__":
    pytest.main([__file__, "-v"])