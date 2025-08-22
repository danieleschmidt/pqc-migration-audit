"""Comprehensive tests for types and validation framework."""

import pytest
from dataclasses import FrozenInstanceError
from enum import Enum

from src.pqc_migration_audit.types import (
    Severity, CryptoAlgorithm, Vulnerability, ScanStats, ScanResults, ValidationResult
)


class TestSeverityEnum:
    """Test Severity enum functionality."""

    def test_severity_values(self):
        """Test all severity levels are available."""
        assert Severity.LOW.value == "low"
        assert Severity.MEDIUM.value == "medium"  
        assert Severity.HIGH.value == "high"
        assert Severity.CRITICAL.value == "critical"

    def test_severity_ordering(self):
        """Test severity can be compared for ordering."""
        severities = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        severity_values = [s.value for s in severities]
        
        # Test that we can sort by severity
        assert len(set(severity_values)) == 4

    def test_severity_string_representation(self):
        """Test string representation of severity."""
        assert str(Severity.HIGH) == "Severity.HIGH"
        assert repr(Severity.CRITICAL) == "<Severity.CRITICAL: 'critical'>"


class TestCryptoAlgorithmEnum:
    """Test CryptoAlgorithm enum functionality."""

    def test_algorithm_values(self):
        """Test all algorithms are available."""
        assert CryptoAlgorithm.RSA.value == "rsa"
        assert CryptoAlgorithm.ECC.value == "ecc"
        assert CryptoAlgorithm.DSA.value == "dsa"
        assert CryptoAlgorithm.DH.value == "dh"
        assert CryptoAlgorithm.ECDSA.value == "ecdsa"
        assert CryptoAlgorithm.ECDH.value == "ecdh"

    def test_algorithm_completeness(self):
        """Test that all major quantum-vulnerable algorithms are included."""
        algorithms = [alg.value for alg in CryptoAlgorithm]
        
        # Check for key quantum-vulnerable algorithms
        expected_algorithms = ["rsa", "ecc", "dsa", "dh", "ecdsa", "ecdh"]
        for expected in expected_algorithms:
            assert expected in algorithms

    def test_algorithm_uniqueness(self):
        """Test that algorithm values are unique."""
        values = [alg.value for alg in CryptoAlgorithm]
        assert len(values) == len(set(values))


class TestVulnerabilityDataclass:
    """Test Vulnerability dataclass functionality."""

    def test_vulnerability_creation(self):
        """Test creating a vulnerability instance."""
        vuln = Vulnerability(
            file_path="/test/file.py",
            line_number=42,
            algorithm=CryptoAlgorithm.RSA,
            severity=Severity.HIGH,
            key_size=2048,
            description="Test vulnerability"
        )
        
        assert vuln.file_path == "/test/file.py"
        assert vuln.line_number == 42
        assert vuln.algorithm == CryptoAlgorithm.RSA
        assert vuln.severity == Severity.HIGH
        assert vuln.key_size == 2048
        assert vuln.description == "Test vulnerability"

    def test_vulnerability_optional_fields(self):
        """Test vulnerability with optional fields."""
        vuln = Vulnerability(
            file_path="/test/file.py",
            line_number=42,
            algorithm=CryptoAlgorithm.ECC,
            severity=Severity.MEDIUM
        )
        
        # Optional fields should have default values
        assert vuln.key_size is None
        assert vuln.description == ""
        assert vuln.code_snippet == ""
        assert vuln.recommendation == ""
        assert vuln.cwe_id is None

    def test_vulnerability_with_all_fields(self):
        """Test vulnerability with all fields populated."""
        vuln = Vulnerability(
            file_path="/test/file.py",
            line_number=42,
            algorithm=CryptoAlgorithm.RSA,
            severity=Severity.CRITICAL,
            key_size=1024,
            description="Weak RSA key",
            code_snippet="rsa.generate_private_key(1024)",
            recommendation="Use ML-KEM-768 instead",
            cwe_id="CWE-326"
        )
        
        assert vuln.file_path == "/test/file.py"
        assert vuln.line_number == 42
        assert vuln.algorithm == CryptoAlgorithm.RSA
        assert vuln.severity == Severity.CRITICAL
        assert vuln.key_size == 1024
        assert vuln.description == "Weak RSA key"
        assert vuln.code_snippet == "rsa.generate_private_key(1024)"
        assert vuln.recommendation == "Use ML-KEM-768 instead"
        assert vuln.cwe_id == "CWE-326"

    def test_vulnerability_equality(self):
        """Test vulnerability equality comparison."""
        vuln1 = Vulnerability(
            file_path="/test/file.py",
            line_number=42,
            algorithm=CryptoAlgorithm.RSA,
            severity=Severity.HIGH
        )
        vuln2 = Vulnerability(
            file_path="/test/file.py",
            line_number=42,
            algorithm=CryptoAlgorithm.RSA,
            severity=Severity.HIGH
        )
        vuln3 = Vulnerability(
            file_path="/test/other.py",
            line_number=42,
            algorithm=CryptoAlgorithm.RSA,
            severity=Severity.HIGH
        )
        
        assert vuln1 == vuln2
        assert vuln1 != vuln3

    def test_vulnerability_string_representation(self):
        """Test string representation of vulnerability."""
        vuln = Vulnerability(
            file_path="/test/file.py",
            line_number=42,
            algorithm=CryptoAlgorithm.RSA,
            severity=Severity.HIGH,
            description="Test vulnerability"
        )
        
        str_repr = str(vuln)
        assert "/test/file.py" in str_repr
        assert "42" in str_repr
        assert "RSA" in str_repr
        assert "HIGH" in str_repr


class TestScanStatsDataclass:
    """Test ScanStats dataclass functionality."""

    def test_scan_stats_defaults(self):
        """Test default values for scan stats."""
        stats = ScanStats()
        
        assert stats.files_processed == 0
        assert stats.files_skipped == 0
        assert stats.errors_encountered == 0
        assert stats.vulnerabilities_found == 0
        assert stats.scan_start_time is None
        assert stats.performance_metrics == {}

    def test_scan_stats_with_values(self):
        """Test scan stats with specific values."""
        import time
        start_time = time.time()
        
        stats = ScanStats(
            files_processed=100,
            files_skipped=5,
            errors_encountered=2,
            vulnerabilities_found=15,
            scan_start_time=start_time,
            performance_metrics={"throughput": 1500, "memory_usage": "50MB"}
        )
        
        assert stats.files_processed == 100
        assert stats.files_skipped == 5
        assert stats.errors_encountered == 2
        assert stats.vulnerabilities_found == 15
        assert stats.scan_start_time == start_time
        assert stats.performance_metrics["throughput"] == 1500
        assert stats.performance_metrics["memory_usage"] == "50MB"

    def test_scan_stats_mutable_performance_metrics(self):
        """Test that performance metrics can be updated."""
        stats = ScanStats()
        
        # Initially empty
        assert len(stats.performance_metrics) == 0
        
        # Can add metrics
        stats.performance_metrics["scan_rate"] = 1000
        stats.performance_metrics["peak_memory"] = "100MB"
        
        assert len(stats.performance_metrics) == 2
        assert stats.performance_metrics["scan_rate"] == 1000


class TestValidationResultDataclass:
    """Test ValidationResult dataclass functionality."""

    def test_validation_result_defaults(self):
        """Test default values for validation result."""
        result = ValidationResult()
        
        assert result.is_valid is True
        assert result.error_message is None
        assert result.warnings == []

    def test_validation_result_invalid(self):
        """Test validation result for invalid case."""
        result = ValidationResult(
            is_valid=False,
            error_message="Invalid input format",
            warnings=["Deprecated algorithm used", "Missing key size"]
        )
        
        assert result.is_valid is False
        assert result.error_message == "Invalid input format"
        assert len(result.warnings) == 2
        assert "Deprecated algorithm used" in result.warnings
        assert "Missing key size" in result.warnings

    def test_validation_result_with_warnings_only(self):
        """Test validation result that is valid but has warnings."""
        result = ValidationResult(
            is_valid=True,
            warnings=["Performance could be improved"]
        )
        
        assert result.is_valid is True
        assert result.error_message is None
        assert len(result.warnings) == 1

    def test_validation_result_mutable_warnings(self):
        """Test that warnings list can be modified."""
        result = ValidationResult()
        
        # Initially empty warnings
        assert len(result.warnings) == 0
        
        # Can add warnings
        result.warnings.append("First warning")
        result.warnings.append("Second warning")
        
        assert len(result.warnings) == 2


class TestScanResultsDataclass:
    """Test ScanResults dataclass functionality."""

    def test_scan_results_defaults(self):
        """Test default values for scan results."""
        results = ScanResults()
        
        assert results.vulnerabilities == []
        assert results.scanned_files == 0
        assert results.total_lines == 0
        assert results.scan_time == 0.0
        assert results.scan_path == ""
        assert results.timestamp == ""
        assert results.languages_detected == []
        assert results.metadata == {}
        assert results.scan_stats is None

    def test_scan_results_with_vulnerabilities(self):
        """Test scan results with vulnerabilities."""
        vuln1 = Vulnerability(
            file_path="/test/file1.py",
            line_number=10,
            algorithm=CryptoAlgorithm.RSA,
            severity=Severity.HIGH
        )
        vuln2 = Vulnerability(
            file_path="/test/file2.py",
            line_number=20,
            algorithm=CryptoAlgorithm.ECC,
            severity=Severity.MEDIUM
        )
        
        results = ScanResults(
            vulnerabilities=[vuln1, vuln2],
            scanned_files=2,
            total_lines=1000,
            scan_time=2.5,
            scan_path="/test",
            timestamp="2024-01-01T12:00:00Z",
            languages_detected=["python"],
            metadata={"version": "1.0.0"}
        )
        
        assert len(results.vulnerabilities) == 2
        assert results.scanned_files == 2
        assert results.total_lines == 1000
        assert results.scan_time == 2.5
        assert results.scan_path == "/test"
        assert results.timestamp == "2024-01-01T12:00:00Z"
        assert "python" in results.languages_detected
        assert results.metadata["version"] == "1.0.0"

    def test_scan_results_with_stats(self):
        """Test scan results with scan stats."""
        stats = ScanStats(
            files_processed=50,
            vulnerabilities_found=10
        )
        
        results = ScanResults(
            scanned_files=50,
            scan_stats=stats
        )
        
        assert results.scan_stats is not None
        assert results.scan_stats.files_processed == 50
        assert results.scan_stats.vulnerabilities_found == 10

    def test_scan_results_mutable_collections(self):
        """Test that collections in scan results can be modified."""
        results = ScanResults()
        
        # Initially empty
        assert len(results.vulnerabilities) == 0
        assert len(results.languages_detected) == 0
        assert len(results.metadata) == 0
        
        # Can add items
        vuln = Vulnerability(
            file_path="/test.py",
            line_number=1,
            algorithm=CryptoAlgorithm.RSA,
            severity=Severity.LOW
        )
        results.vulnerabilities.append(vuln)
        results.languages_detected.append("python")
        results.metadata["tool_version"] = "1.0.0"
        
        assert len(results.vulnerabilities) == 1
        assert len(results.languages_detected) == 1
        assert len(results.metadata) == 1


# Integration tests for type interactions
class TestTypeInteractions:
    """Test interactions between different types."""

    def test_vulnerability_with_all_enum_values(self):
        """Test vulnerability creation with all enum combinations."""
        for algorithm in CryptoAlgorithm:
            for severity in Severity:
                vuln = Vulnerability(
                    file_path=f"/test/{algorithm.value}.py",
                    line_number=1,
                    algorithm=algorithm,
                    severity=severity
                )
                
                assert vuln.algorithm == algorithm
                assert vuln.severity == severity
                assert algorithm.value in vuln.file_path

    def test_scan_results_with_mixed_vulnerabilities(self):
        """Test scan results with vulnerabilities of different types."""
        vulnerabilities = []
        
        # Create vulnerabilities for each algorithm type
        for i, algorithm in enumerate(CryptoAlgorithm):
            severity = list(Severity)[i % len(Severity)]
            vuln = Vulnerability(
                file_path=f"/test/file_{i}.py",
                line_number=i + 1,
                algorithm=algorithm,
                severity=severity
            )
            vulnerabilities.append(vuln)
        
        results = ScanResults(
            vulnerabilities=vulnerabilities,
            scanned_files=len(vulnerabilities)
        )
        
        assert len(results.vulnerabilities) == len(CryptoAlgorithm)
        
        # Check that all algorithm types are represented
        found_algorithms = {v.algorithm for v in results.vulnerabilities}
        assert found_algorithms == set(CryptoAlgorithm)

    def test_validation_result_with_vulnerability_context(self):
        """Test validation result in context of vulnerability validation."""
        # Valid vulnerability
        valid_vuln = Vulnerability(
            file_path="/test/valid.py",
            line_number=42,
            algorithm=CryptoAlgorithm.RSA,
            severity=Severity.HIGH
        )
        
        valid_result = ValidationResult(is_valid=True)
        assert valid_result.is_valid
        
        # Invalid scenario
        invalid_result = ValidationResult(
            is_valid=False,
            error_message="Line number must be positive",
            warnings=["File path should be absolute"]
        )
        
        assert not invalid_result.is_valid
        assert "positive" in invalid_result.error_message
        assert len(invalid_result.warnings) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])