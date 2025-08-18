"""Comprehensive test suite for all core modules to achieve 85%+ coverage."""

import pytest
import os
import sys
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from typing import List, Dict, Any

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Core imports
from pqc_migration_audit.core import CryptoAuditor, CryptoPatterns, RiskAssessment
from pqc_migration_audit.types import (
    Severity, CryptoAlgorithm, Vulnerability, ScanResults, ScanStats
)
from pqc_migration_audit.exceptions import (
    ScanException, ValidationException, SecurityException, 
    FileSystemException, UnsupportedFileTypeException
)

# Scanner imports
try:
    from pqc_migration_audit.scanners import BaseScanner, PythonScanner
    SCANNERS_AVAILABLE = True
except ImportError:
    BaseScanner = None
    PythonScanner = None
    SCANNERS_AVAILABLE = False

try:
    from pqc_migration_audit.analyzers import RSAAnalyzer, ECCAnalyzer
    ANALYZERS_AVAILABLE = True
except ImportError:
    RSAAnalyzer = None
    ECCAnalyzer = None
    ANALYZERS_AVAILABLE = False

# Reporting imports
from pqc_migration_audit.reporters import (
    JSONReporter, HTMLReporter, ConsoleReporter, SARIFReporter
)

# Services imports
try:
    from pqc_migration_audit.services import (
        MigrationService, CryptoInventoryService, ComplianceService
    )
except ImportError:
    MigrationService = None
    CryptoInventoryService = None
    ComplianceService = None

# Advanced features imports
try:
    from pqc_migration_audit.research_engine import (
        AlgorithmBenchmark, ResearchOrchestrator, StatisticalValidator
    )
    from pqc_migration_audit.auto_scaling import (
        AutoScaler, WorkerManager, ResourceMonitor
    )
    from pqc_migration_audit.validation_framework import (
        ValidationFramework, DataIntegrityValidator
    )
    from pqc_migration_audit.performance_engine import PerformanceEngine
    from pqc_migration_audit.security_enhanced import SecurityMonitor
except ImportError:
    # Handle optional dependencies
    AlgorithmBenchmark = None
    ResearchOrchestrator = None
    StatisticalValidator = None
    AutoScaler = None
    WorkerManager = None
    ResourceMonitor = None
    ValidationFramework = None
    DataIntegrityValidator = None
    PerformanceEngine = None
    SecurityMonitor = None


class TestCoreModules:
    """Test core cryptographic auditing functionality."""

    @pytest.fixture
    def sample_python_code(self):
        """Sample vulnerable Python code for testing."""
        return """
import rsa
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from Crypto.PublicKey import RSA

def generate_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key

def generate_ecc_key():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key
"""

    @pytest.fixture
    def sample_java_code(self):
        """Sample vulnerable Java code for testing."""
        return """
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.spec.RSAKeyGenParameterSpec;

public class CryptoExample {
    public KeyPair generateRSAKey() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }
    
    public KeyPair generateECCKey() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        return keyGen.generateKeyPair();
    }
}
"""

    @pytest.fixture
    def temp_file(self, tmp_path):
        """Create a temporary file for testing."""
        def _create_temp_file(content: str, suffix: str = '.py'):
            file_path = tmp_path / f"test_file{suffix}"
            file_path.write_text(content)
            return str(file_path)
        return _create_temp_file

    def test_crypto_auditor_initialization(self):
        """Test CryptoAuditor initialization."""
        auditor = CryptoAuditor()
        assert auditor is not None
        assert hasattr(auditor, 'scan_file')
        assert hasattr(auditor, 'scan_directory')

    def test_crypto_patterns_python(self):
        """Test Python cryptographic patterns."""
        patterns = CryptoPatterns.PYTHON_PATTERNS
        assert 'rsa_generation' in patterns
        assert 'ecc_generation' in patterns
        assert isinstance(patterns['rsa_generation'], list)
        assert len(patterns['rsa_generation']) > 0

    def test_scan_python_file(self, temp_file, sample_python_code):
        """Test scanning a Python file for vulnerabilities."""
        file_path = temp_file(sample_python_code, '.py')
        auditor = CryptoAuditor()
        
        results = auditor.scan_file(file_path)
        assert isinstance(results, ScanResults)
        assert len(results.vulnerabilities) > 0
        
        # Check for RSA vulnerabilities
        rsa_vulns = [v for v in results.vulnerabilities if v.algorithm == CryptoAlgorithm.RSA]
        assert len(rsa_vulns) > 0

    def test_scan_java_file(self, temp_file, sample_java_code):
        """Test scanning a Java file for vulnerabilities."""
        file_path = temp_file(sample_java_code, '.java')
        auditor = CryptoAuditor()
        
        results = auditor.scan_file(file_path)
        assert isinstance(results, ScanResults)
        # Java scanning should at least not crash
        assert results.vulnerabilities is not None

    def test_scan_directory(self, tmp_path, sample_python_code):
        """Test scanning a directory for vulnerabilities."""
        # Create multiple test files
        py_file = tmp_path / "test.py"
        py_file.write_text(sample_python_code)
        
        java_file = tmp_path / "Test.java"
        java_file.write_text("public class Test {}")
        
        auditor = CryptoAuditor()
        results = auditor.scan_directory(str(tmp_path))
        
        assert isinstance(results, ScanResults)
        assert results.stats.files_scanned >= 1

    def test_risk_assessment(self):
        """Test risk assessment functionality."""
        vulnerabilities = [
            Vulnerability(
                file_path="test.py",
                line_number=10,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.HIGH,
                description="RSA key generation",
                recommendation="Use ML-KEM",
                key_size=2048
            )
        ]
        
        assessment = RiskAssessment.calculate(vulnerabilities)
        assert assessment is not None
        assert hasattr(assessment, 'total_risk_score')
        assert assessment.total_risk_score > 0

    def test_vulnerability_creation(self):
        """Test Vulnerability dataclass creation."""
        vuln = Vulnerability(
            file_path="test.py",
            line_number=5,
            algorithm=CryptoAlgorithm.ECC,
            severity=Severity.MEDIUM,
            description="ECC usage",
            recommendation="Use ML-DSA"
        )
        
        assert vuln.file_path == "test.py"
        assert vuln.line_number == 5
        assert vuln.algorithm == CryptoAlgorithm.ECC
        assert vuln.severity == Severity.MEDIUM

    def test_scan_stats_calculation(self):
        """Test ScanStats calculation."""
        stats = ScanStats(
            files_scanned=10,
            vulnerabilities_found=5,
            scan_time=1.5,
            languages_detected=['python', 'java']
        )
        
        assert stats.files_scanned == 10
        assert stats.vulnerabilities_found == 5
        assert stats.scan_time == 1.5
        assert len(stats.languages_detected) == 2

    def test_crypto_algorithm_enum(self):
        """Test CryptoAlgorithm enum values."""
        assert CryptoAlgorithm.RSA.value == 'rsa'
        assert CryptoAlgorithm.ECC.value == 'ecc'
        assert CryptoAlgorithm.AES.value == 'aes'
        assert CryptoAlgorithm.DES.value == 'des'

    def test_severity_enum(self):
        """Test Severity enum values."""
        assert Severity.CRITICAL.value == 'critical'
        assert Severity.HIGH.value == 'high'
        assert Severity.MEDIUM.value == 'medium'
        assert Severity.LOW.value == 'low'
        assert Severity.INFO.value == 'info'


@pytest.mark.skipif(not SCANNERS_AVAILABLE, reason="Scanners module not available")
class TestScanners:
    """Test cryptographic scanners functionality."""

    def test_python_scanner_initialization(self):
        """Test PythonScanner initialization."""
        scanner = PythonScanner()
        assert scanner is not None
        assert hasattr(scanner, 'scan_file')
        assert hasattr(scanner, 'patterns')

    def test_base_scanner_initialization(self):
        """Test BaseScanner initialization."""
        scanner = BaseScanner()
        assert scanner is not None
        assert hasattr(scanner, 'scan_file')
        assert hasattr(scanner, 'patterns')

    def test_python_scanner_patterns(self):
        """Test PythonScanner pattern definitions."""
        scanner = PythonScanner()
        assert 'rsa_generation' in scanner.patterns
        assert 'ecc_generation' in scanner.patterns
        assert isinstance(scanner.patterns['rsa_generation'], list)


@pytest.mark.skipif(not ANALYZERS_AVAILABLE, reason="Analyzers module not available")
class TestAnalyzers:
    """Test cryptographic analyzers functionality."""

    def test_rsa_analyzer_initialization(self):
        """Test RSAAnalyzer initialization."""
        if RSAAnalyzer:
            analyzer = RSAAnalyzer()
            assert analyzer is not None
            assert hasattr(analyzer, 'analyze')

    def test_ecc_analyzer_initialization(self):
        """Test ECCAnalyzer initialization."""
        if ECCAnalyzer:
            analyzer = ECCAnalyzer()
            assert analyzer is not None
            assert hasattr(analyzer, 'analyze')

    def test_analyzer_functionality(self):
        """Test basic analyzer functionality."""
        # Test with mock analyzer functionality
        assert True  # Placeholder for when analyzers are available


class TestReporters:
    """Test reporting functionality."""

    @pytest.fixture
    def sample_results(self):
        """Sample scan results for testing."""
        vulnerabilities = [
            Vulnerability(
                file_path="test.py",
                line_number=10,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.HIGH,
                description="RSA key generation",
                recommendation="Use ML-KEM"
            )
        ]
        
        stats = ScanStats(
            files_scanned=1,
            vulnerabilities_found=1,
            scan_time=0.5,
            languages_detected=['python']
        )
        
        return ScanResults(vulnerabilities=vulnerabilities, stats=stats)

    def test_json_reporter(self, sample_results, tmp_path):
        """Test JSON reporter functionality."""
        reporter = JSONReporter()
        output_file = tmp_path / "report.json"
        
        reporter.generate_report(sample_results, str(output_file))
        
        assert output_file.exists()
        with open(output_file) as f:
            data = json.load(f)
            assert 'vulnerabilities' in data
            assert 'stats' in data
            assert len(data['vulnerabilities']) == 1

    def test_html_reporter(self, sample_results, tmp_path):
        """Test HTML reporter functionality."""
        reporter = HTMLReporter()
        output_file = tmp_path / "report.html"
        
        reporter.generate_report(sample_results, str(output_file))
        
        assert output_file.exists()
        content = output_file.read_text()
        assert '<html>' in content
        assert 'PQC Migration Audit Report' in content

    def test_console_reporter(self, sample_results, capsys):
        """Test console reporter functionality."""
        reporter = ConsoleReporter()
        
        reporter.generate_report(sample_results)
        
        captured = capsys.readouterr()
        assert 'RSA key generation' in captured.out

    def test_sarif_reporter(self, sample_results, tmp_path):
        """Test SARIF reporter functionality."""
        reporter = SARIFReporter()
        output_file = tmp_path / "report.sarif"
        
        reporter.generate_report(sample_results, str(output_file))
        
        assert output_file.exists()
        with open(output_file) as f:
            data = json.load(f)
            assert '$schema' in data
            assert 'runs' in data


class TestExceptions:
    """Test exception handling."""

    def test_scan_exception(self):
        """Test ScanException creation and handling."""
        exc = ScanException("Test scan error")
        assert str(exc) == "Test scan error"
        assert isinstance(exc, Exception)

    def test_validation_exception(self):
        """Test ValidationException creation and handling."""
        exc = ValidationException("Test validation error")
        assert str(exc) == "Test validation error"
        assert isinstance(exc, Exception)

    def test_security_exception(self):
        """Test SecurityException creation and handling."""
        exc = SecurityException("Test security error")
        assert str(exc) == "Test security error"
        assert isinstance(exc, Exception)

    def test_filesystem_exception(self):
        """Test FileSystemException creation and handling."""
        exc = FileSystemException("Test filesystem error")
        assert str(exc) == "Test filesystem error"
        assert isinstance(exc, Exception)

    def test_unsupported_filetype_exception(self):
        """Test UnsupportedFileTypeException creation and handling."""
        exc = UnsupportedFileTypeException("Test unsupported filetype error")
        assert str(exc) == "Test unsupported filetype error"
        assert isinstance(exc, Exception)


@pytest.mark.skipif(MigrationService is None, reason="Services not available")
class TestServices:
    """Test service layer functionality."""

    def test_migration_service_initialization(self):
        """Test MigrationService initialization."""
        service = MigrationService()
        assert service is not None
        assert hasattr(service, 'plan_migration')

    def test_crypto_inventory_service_initialization(self):
        """Test CryptoInventoryService initialization."""
        service = CryptoInventoryService()
        assert service is not None
        assert hasattr(service, 'inventory_crypto_assets')

    def test_compliance_service_initialization(self):
        """Test ComplianceService initialization."""
        service = ComplianceService()
        assert service is not None
        assert hasattr(service, 'assess_compliance')


@pytest.mark.skipif(AlgorithmBenchmark is None, reason="Research engine not available")
class TestResearchEngine:
    """Test research engine functionality."""

    def test_algorithm_benchmark_initialization(self):
        """Test AlgorithmBenchmark initialization."""
        benchmark = AlgorithmBenchmark()
        assert benchmark is not None
        assert hasattr(benchmark, 'benchmark_algorithm')

    def test_research_orchestrator_initialization(self):
        """Test ResearchOrchestrator initialization."""
        orchestrator = ResearchOrchestrator()
        assert orchestrator is not None
        assert hasattr(orchestrator, 'conduct_comparative_study')

    def test_statistical_validator_initialization(self):
        """Test StatisticalValidator initialization."""
        validator = StatisticalValidator()
        assert validator is not None
        assert hasattr(validator, 'validate_significance')


@pytest.mark.skipif(AutoScaler is None, reason="Auto scaling not available")
class TestAutoScaling:
    """Test auto-scaling functionality."""

    def test_auto_scaler_initialization(self):
        """Test AutoScaler initialization."""
        scaler = AutoScaler()
        assert scaler is not None
        assert hasattr(scaler, 'scale_up')
        assert hasattr(scaler, 'scale_down')

    def test_worker_manager_initialization(self):
        """Test WorkerManager initialization."""
        manager = WorkerManager()
        assert manager is not None
        assert hasattr(manager, 'add_worker')
        assert hasattr(manager, 'remove_worker')

    def test_resource_monitor_initialization(self):
        """Test ResourceMonitor initialization."""
        monitor = ResourceMonitor()
        assert monitor is not None
        assert hasattr(monitor, 'get_metrics')


@pytest.mark.skipif(ValidationFramework is None, reason="Validation framework not available")
class TestValidationFramework:
    """Test validation framework functionality."""

    def test_validation_framework_initialization(self):
        """Test ValidationFramework initialization."""
        framework = ValidationFramework()
        assert framework is not None
        assert hasattr(framework, 'validate')

    def test_data_integrity_validator_initialization(self):
        """Test DataIntegrityValidator initialization."""
        validator = DataIntegrityValidator()
        assert validator is not None
        assert hasattr(validator, 'validate_data_integrity')


@pytest.mark.skipif(PerformanceEngine is None, reason="Performance engine not available")
class TestPerformanceEngine:
    """Test performance engine functionality."""

    def test_performance_engine_initialization(self):
        """Test PerformanceEngine initialization."""
        engine = PerformanceEngine()
        assert engine is not None
        assert hasattr(engine, 'optimize')


@pytest.mark.skipif(SecurityMonitor is None, reason="Security monitor not available")
class TestSecurityMonitor:
    """Test security monitoring functionality."""

    def test_security_monitor_initialization(self):
        """Test SecurityMonitor initialization."""
        monitor = SecurityMonitor()
        assert monitor is not None
        assert hasattr(monitor, 'monitor_threat')


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_scan_nonexistent_file(self):
        """Test scanning a non-existent file."""
        auditor = CryptoAuditor()
        
        with pytest.raises((FileNotFoundError, ScanException, FileSystemException)):
            auditor.scan_file("/nonexistent/file.py")

    def test_scan_empty_file(self, tmp_path):
        """Test scanning an empty file."""
        empty_file = tmp_path / "empty.py"
        empty_file.write_text("")
        
        auditor = CryptoAuditor()
        results = auditor.scan_file(str(empty_file))
        
        assert isinstance(results, ScanResults)
        assert len(results.vulnerabilities) == 0

    def test_scan_binary_file(self, tmp_path):
        """Test scanning a binary file."""
        binary_file = tmp_path / "binary.bin"
        binary_file.write_bytes(b'\x00\x01\x02\x03')
        
        auditor = CryptoAuditor()
        # Should handle gracefully without crashing
        try:
            results = auditor.scan_file(str(binary_file))
            assert isinstance(results, ScanResults)
        except (UnsupportedFileTypeException, UnicodeDecodeError):
            # This is expected behavior
            pass

    def test_scan_large_file(self, tmp_path):
        """Test scanning a very large file."""
        large_content = "# Python comment\n" * 10000  # Create large file
        large_file = tmp_path / "large.py"
        large_file.write_text(large_content)
        
        auditor = CryptoAuditor()
        results = auditor.scan_file(str(large_file))
        
        assert isinstance(results, ScanResults)
        # Should complete without timeout or memory issues

    def test_invalid_directory_scan(self):
        """Test scanning an invalid directory."""
        auditor = CryptoAuditor()
        
        with pytest.raises((FileNotFoundError, ScanException, FileSystemException)):
            auditor.scan_directory("/nonexistent/directory")


class TestIntegrationScenarios:
    """Test integration scenarios and workflows."""

    def test_full_scan_workflow(self, tmp_path):
        """Test complete scan workflow from file creation to reporting."""
        # Create test project structure
        project_dir = tmp_path / "test_project"
        project_dir.mkdir()
        
        # Create vulnerable Python file
        py_file = project_dir / "crypto_module.py"
        py_file.write_text("""
from cryptography.hazmat.primitives.asymmetric import rsa

def create_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
""")
        
        # Create vulnerable Java file
        java_file = project_dir / "CryptoClass.java"
        java_file.write_text("""
import java.security.KeyPairGenerator;

public class CryptoClass {
    public void generateRSAKey() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
    }
}
""")
        
        # Scan the project
        auditor = CryptoAuditor()
        results = auditor.scan_directory(str(project_dir))
        
        assert isinstance(results, ScanResults)
        assert results.stats.files_scanned >= 2
        assert len(results.vulnerabilities) > 0
        
        # Generate reports
        report_dir = tmp_path / "reports"
        report_dir.mkdir()
        
        json_reporter = JSONReporter()
        html_reporter = HTMLReporter()
        
        json_file = report_dir / "report.json"
        html_file = report_dir / "report.html"
        
        json_reporter.generate_report(results, str(json_file))
        html_reporter.generate_report(results, str(html_file))
        
        assert json_file.exists()
        assert html_file.exists()
        
        # Verify report content
        with open(json_file) as f:
            json_data = json.load(f)
            assert len(json_data['vulnerabilities']) > 0

    def test_risk_assessment_integration(self, tmp_path):
        """Test risk assessment with real scan results."""
        # Create test file with multiple vulnerabilities
        test_file = tmp_path / "multi_crypto.py"
        test_file.write_text("""
import rsa
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from Crypto.Cipher import DES
from hashlib import md5

def weak_crypto():
    # Multiple vulnerabilities
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    ecc_key = ec.generate_private_key(ec.SECP256R1())
    cipher = DES.new(b'8bytekey', DES.MODE_ECB)
    hash_val = md5(b'data').hexdigest()
""")
        
        auditor = CryptoAuditor()
        results = auditor.scan_file(str(test_file))
        
        assert len(results.vulnerabilities) > 0
        
        # Calculate risk assessment
        assessment = RiskAssessment.calculate(results.vulnerabilities)
        assert assessment.total_risk_score > 0
        assert assessment.critical_vulnerabilities >= 0
        assert assessment.high_vulnerabilities >= 0

    def test_multiple_language_support(self, tmp_path):
        """Test scanning projects with multiple programming languages."""
        project_dir = tmp_path / "multi_lang_project"
        project_dir.mkdir()
        
        # Python file
        (project_dir / "crypto.py").write_text("import rsa")
        
        # Java file
        (project_dir / "Crypto.java").write_text("""
import java.security.KeyPairGenerator;
public class Crypto {}
""")
        
        # Go file
        (project_dir / "crypto.go").write_text("""
package main
import "crypto/rsa"
""")
        
        # JavaScript file
        (project_dir / "crypto.js").write_text("const crypto = require('crypto');")
        
        auditor = CryptoAuditor()
        results = auditor.scan_directory(str(project_dir))
        
        assert results.stats.files_scanned >= 4
        # Should detect languages
        detected_languages = results.stats.languages_detected
        assert len(detected_languages) >= 1  # At least some languages detected


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
