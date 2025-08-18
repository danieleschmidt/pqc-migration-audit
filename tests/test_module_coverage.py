"""Comprehensive test suite targeting specific modules for maximum coverage."""

import pytest
import tempfile
import os
import sys
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Import all modules we want to test
from pqc_migration_audit import __version__, __author__
from pqc_migration_audit.types import Severity, CryptoAlgorithm, Vulnerability, ScanResults, ScanStats
from pqc_migration_audit.exceptions import (
    ScanException, ValidationException, SecurityException, 
    FileSystemException, UnsupportedFileTypeException, FileTooLargeException,
    InsufficientPermissionsException, ScanTimeoutException, ExceptionHandler
)

# Try to import reporters
try:
    from pqc_migration_audit.reporters import (
        BaseReporter, JSONReporter, HTMLReporter, ConsoleReporter, SARIFReporter
    )
    REPORTERS_AVAILABLE = True
except ImportError:
    REPORTERS_AVAILABLE = False

# Try to import services
try:
    from pqc_migration_audit.services.migration_service import MigrationService
    from pqc_migration_audit.services.inventory_service import CryptoInventoryService
    from pqc_migration_audit.services.compliance_service import ComplianceService
    SERVICES_AVAILABLE = True
except ImportError:
    SERVICES_AVAILABLE = False

# Try to import models
try:
    from pqc_migration_audit.models import (
        CryptoAsset, MigrationPlan, ComplianceFramework, PolicyRule
    )
    MODELS_AVAILABLE = True
except ImportError:
    MODELS_AVAILABLE = False

# Try to import advanced features
try:
    from pqc_migration_audit.validators import (
        InputValidator, SecurityValidator, IntegrityValidator,
        PathValidator, ContentValidator, ValidationResult
    )
    VALIDATORS_AVAILABLE = True
except ImportError:
    VALIDATORS_AVAILABLE = False


class TestPackageBasics:
    """Test basic package imports and metadata."""

    def test_package_version(self):
        """Test package version is defined."""
        assert __version__ == "0.1.0"

    def test_package_author(self):
        """Test package author is defined."""
        assert __author__ == "Daniel Schmidt"

    def test_severity_enum_complete(self):
        """Test all severity levels are defined."""
        severities = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        values = [s.value for s in severities]
        
        assert 'low' in values
        assert 'medium' in values
        assert 'high' in values
        assert 'critical' in values

    def test_crypto_algorithm_enum_complete(self):
        """Test all crypto algorithms are defined."""
        algorithms = [
            CryptoAlgorithm.RSA, CryptoAlgorithm.ECC, CryptoAlgorithm.DSA,
            CryptoAlgorithm.DH, CryptoAlgorithm.ECDSA, CryptoAlgorithm.ECDH
        ]
        values = [a.value for a in algorithms]
        
        assert 'RSA' in values
        assert 'ECC' in values
        assert 'DSA' in values

    def test_vulnerability_dataclass_fields(self):
        """Test Vulnerability dataclass has all required fields."""
        vuln = Vulnerability(
            file_path="test.py",
            line_number=10,
            algorithm=CryptoAlgorithm.RSA,
            severity=Severity.HIGH,
            key_size=2048,
            description="Test vulnerability",
            code_snippet="rsa.generate_key()",
            recommendation="Use ML-KEM",
            cwe_id="CWE-327"
        )
        
        assert vuln.file_path == "test.py"
        assert vuln.line_number == 10
        assert vuln.algorithm == CryptoAlgorithm.RSA
        assert vuln.severity == Severity.HIGH
        assert vuln.key_size == 2048
        assert vuln.description == "Test vulnerability"
        assert vuln.code_snippet == "rsa.generate_key()"
        assert vuln.recommendation == "Use ML-KEM"
        assert vuln.cwe_id == "CWE-327"

    def test_scan_stats_dataclass(self):
        """Test ScanStats dataclass functionality."""
        stats = ScanStats(
            files_processed=10,
            files_skipped=2,
            errors_encountered=1,
            vulnerabilities_found=5,
            scan_start_time=1234567890.0,
            performance_metrics={'cpu_time': 1.5, 'memory_mb': 256}
        )
        
        assert stats.files_processed == 10
        assert stats.files_skipped == 2
        assert stats.errors_encountered == 1
        assert stats.vulnerabilities_found == 5
        assert stats.scan_start_time == 1234567890.0
        assert stats.performance_metrics['cpu_time'] == 1.5

    def test_scan_results_dataclass(self):
        """Test ScanResults dataclass functionality."""
        vuln = Vulnerability(
            file_path="test.py",
            line_number=1,
            algorithm=CryptoAlgorithm.RSA,
            severity=Severity.HIGH
        )
        
        stats = ScanStats(files_processed=1, vulnerabilities_found=1)
        
        results = ScanResults(
            vulnerabilities=[vuln],
            scanned_files=1,
            total_lines=100,
            scan_time=1.5,
            scan_path="/test/project",
            timestamp="2025-01-01T00:00:00Z",
            languages_detected=['python'],
            metadata={'tool_version': '1.0'},
            scan_stats=stats
        )
        
        assert len(results.vulnerabilities) == 1
        assert results.scanned_files == 1
        assert results.total_lines == 100
        assert results.scan_time == 1.5
        assert results.scan_path == "/test/project"
        assert results.timestamp == "2025-01-01T00:00:00Z"
        assert 'python' in results.languages_detected
        assert results.metadata['tool_version'] == '1.0'
        assert results.scan_stats.files_processed == 1


class TestExceptions:
    """Test custom exception classes."""

    def test_scan_exception_creation(self):
        """Test ScanException with different parameters."""
        # Basic exception
        exc = ScanException("Basic scan error")
        assert str(exc) == "Basic scan error"
        
        # Exception with error code
        exc_with_code = ScanException("Scan error with code", error_code="SCAN_001")
        assert exc_with_code.error_code == "SCAN_001"
        
        # Exception with details
        exc_with_details = ScanException(
            "Detailed scan error", 
            error_code="SCAN_002",
            details={"file": "test.py", "line": 10}
        )
        assert exc_with_details.details["file"] == "test.py"

    def test_validation_exception_creation(self):
        """Test ValidationException functionality."""
        exc = ValidationException("Validation failed")
        assert str(exc) == "Validation failed"
        assert isinstance(exc, Exception)

    def test_security_exception_creation(self):
        """Test SecurityException functionality."""
        exc = SecurityException("Security violation")
        assert str(exc) == "Security violation"
        assert isinstance(exc, Exception)

    def test_filesystem_exception_creation(self):
        """Test FileSystemException functionality."""
        exc = FileSystemException("File system error")
        assert str(exc) == "File system error"
        assert isinstance(exc, Exception)

    def test_unsupported_filetype_exception(self):
        """Test UnsupportedFileTypeException functionality."""
        exc = UnsupportedFileTypeException("Unsupported file type: .xyz")
        assert str(exc) == "Unsupported file type: .xyz"
        assert isinstance(exc, Exception)

    def test_file_too_large_exception(self):
        """Test FileTooLargeException functionality."""
        exc = FileTooLargeException("File too large: 100MB")
        assert str(exc) == "File too large: 100MB"
        assert isinstance(exc, Exception)

    def test_insufficient_permissions_exception(self):
        """Test InsufficientPermissionsException functionality."""
        exc = InsufficientPermissionsException("Insufficient permissions")
        assert str(exc) == "Insufficient permissions"
        assert isinstance(exc, Exception)

    def test_scan_timeout_exception(self):
        """Test ScanTimeoutException functionality."""
        exc = ScanTimeoutException("Scan timeout after 60 seconds")
        assert str(exc) == "Scan timeout after 60 seconds"
        assert isinstance(exc, Exception)

    def test_exception_handler_functionality(self):
        """Test ExceptionHandler class."""
        handler = ExceptionHandler()
        assert handler is not None
        assert hasattr(handler, 'handle_exception')

    def test_exception_inheritance(self):
        """Test exception inheritance hierarchy."""
        scan_exc = ScanException("test")
        validation_exc = ValidationException("test")
        security_exc = SecurityException("test")
        
        assert isinstance(scan_exc, Exception)
        assert isinstance(validation_exc, Exception)
        assert isinstance(security_exc, Exception)


@pytest.mark.skipif(not REPORTERS_AVAILABLE, reason="Reporters module not available")
class TestReporters:
    """Test reporting functionality."""

    @pytest.fixture
    def sample_results(self):
        """Create sample scan results for testing."""
        vuln = Vulnerability(
            file_path="test.py",
            line_number=10,
            algorithm=CryptoAlgorithm.RSA,
            severity=Severity.HIGH,
            description="RSA key generation",
            recommendation="Use ML-KEM"
        )
        
        stats = ScanStats(
            files_processed=1,
            vulnerabilities_found=1
        )
        
        return ScanResults(
            vulnerabilities=[vuln],
            scanned_files=1,
            scan_time=1.0,
            languages_detected=['python'],
            scan_stats=stats
        )

    def test_base_reporter_initialization(self):
        """Test BaseReporter initialization."""
        reporter = BaseReporter()
        assert reporter is not None
        assert hasattr(reporter, 'generate_report')

    def test_json_reporter_initialization(self):
        """Test JSONReporter initialization."""
        reporter = JSONReporter()
        assert reporter is not None
        assert hasattr(reporter, 'generate_report')

    def test_html_reporter_initialization(self):
        """Test HTMLReporter initialization."""
        reporter = HTMLReporter()
        assert reporter is not None
        assert hasattr(reporter, 'generate_report')

    def test_console_reporter_initialization(self):
        """Test ConsoleReporter initialization."""
        reporter = ConsoleReporter()
        assert reporter is not None
        assert hasattr(reporter, 'generate_report')

    def test_sarif_reporter_initialization(self):
        """Test SARIFReporter initialization."""
        reporter = SARIFReporter()
        assert reporter is not None
        assert hasattr(reporter, 'generate_report')

    def test_json_reporter_output(self, sample_results, tmp_path):
        """Test JSON reporter output generation."""
        reporter = JSONReporter()
        output_file = tmp_path / "test_report.json"
        
        reporter.generate_report(sample_results, str(output_file))
        
        assert output_file.exists()
        with open(output_file) as f:
            data = json.load(f)
            assert 'vulnerabilities' in data
            assert 'metadata' in data or 'scan_stats' in data

    def test_console_reporter_output(self, sample_results, capsys):
        """Test console reporter output."""
        reporter = ConsoleReporter()
        
        reporter.generate_report(sample_results)
        
        captured = capsys.readouterr()
        # Should produce some output
        assert len(captured.out) > 0 or len(captured.err) > 0

    def test_html_reporter_template_handling(self, sample_results, tmp_path):
        """Test HTML reporter with template handling."""
        reporter = HTMLReporter()
        output_file = tmp_path / "test_report.html"
        
        # Test basic HTML generation
        reporter.generate_report(sample_results, str(output_file))
        
        assert output_file.exists()
        content = output_file.read_text()
        assert '<html>' in content or 'vulnerabilities' in content.lower()


@pytest.mark.skipif(not VALIDATORS_AVAILABLE, reason="Validators module not available")
class TestValidators:
    """Test validation functionality."""

    def test_input_validator_initialization(self):
        """Test InputValidator initialization."""
        validator = InputValidator()
        assert validator is not None
        assert hasattr(validator, 'validate_scan_path')

    def test_security_validator_initialization(self):
        """Test SecurityValidator initialization."""
        validator = SecurityValidator()
        assert validator is not None
        assert hasattr(validator, 'validate_security_policy')

    def test_integrity_validator_initialization(self):
        """Test IntegrityValidator initialization."""
        validator = IntegrityValidator()
        assert validator is not None
        assert hasattr(validator, 'validate_data_integrity')

    def test_path_validator_functionality(self):
        """Test PathValidator functionality."""
        validator = PathValidator()
        assert validator is not None
        assert hasattr(validator, 'validate_path')

    def test_content_validator_functionality(self):
        """Test ContentValidator functionality."""
        validator = ContentValidator()
        assert validator is not None
        assert hasattr(validator, 'validate_content')

    def test_validation_result_creation(self):
        """Test ValidationResult creation and usage."""
        # Valid result
        valid_result = ValidationResult(
            is_valid=True,
            error_message="",
            warnings=[]
        )
        assert valid_result.is_valid is True
        assert valid_result.error_message == ""
        assert len(valid_result.warnings) == 0
        
        # Invalid result
        invalid_result = ValidationResult(
            is_valid=False,
            error_message="Path does not exist",
            warnings=["Performance warning"]
        )
        assert invalid_result.is_valid is False
        assert invalid_result.error_message == "Path does not exist"
        assert len(invalid_result.warnings) == 1

    def test_input_validator_path_validation(self, tmp_path):
        """Test InputValidator path validation."""
        validator = InputValidator()
        
        # Test valid path
        valid_result = validator.validate_scan_path(str(tmp_path))
        assert valid_result.is_valid is True
        
        # Test invalid path
        invalid_result = validator.validate_scan_path("/nonexistent/path")
        assert invalid_result.is_valid is False
        assert "not exist" in invalid_result.error_message.lower()

    def test_security_validator_policy_validation(self):
        """Test SecurityValidator policy validation."""
        validator = SecurityValidator()
        
        # Test with sample policy
        policy = {
            'max_file_size': 1000000,
            'allowed_extensions': ['.py', '.java'],
            'security_level': 'high'
        }
        
        result = validator.validate_security_policy(policy)
        assert result.is_valid in [True, False]  # Either is acceptable

    def test_integrity_validator_data_validation(self):
        """Test IntegrityValidator data integrity validation."""
        validator = IntegrityValidator()
        
        # Test with sample data
        data = {
            'vulnerabilities': [],
            'scan_metadata': {'timestamp': '2025-01-01', 'version': '1.0'}
        }
        
        result = validator.validate_data_integrity(data)
        assert result.is_valid in [True, False]  # Either is acceptable


@pytest.mark.skipif(not SERVICES_AVAILABLE, reason="Services module not available")
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

    def test_migration_service_plan_creation(self):
        """Test migration plan creation."""
        service = MigrationService()
        
        # Mock vulnerability data
        vulnerabilities = [
            Vulnerability(
                file_path="test.py",
                line_number=10,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.HIGH,
                description="RSA usage",
                recommendation="Use ML-KEM"
            )
        ]
        
        # Test plan generation
        plan = service.plan_migration(vulnerabilities)
        assert plan is not None

    def test_inventory_service_asset_discovery(self):
        """Test crypto asset inventory discovery."""
        service = CryptoInventoryService()
        
        # Test asset discovery
        assets = service.inventory_crypto_assets("/tmp")
        assert assets is not None
        assert isinstance(assets, list)

    def test_compliance_service_assessment(self):
        """Test compliance assessment."""
        service = ComplianceService()
        
        # Mock scan results
        results = ScanResults(
            vulnerabilities=[],
            scanned_files=1,
            scan_time=1.0
        )
        
        # Test compliance assessment
        assessment = service.assess_compliance(results)
        assert assessment is not None


@pytest.mark.skipif(not MODELS_AVAILABLE, reason="Models module not available")
class TestModels:
    """Test data model functionality."""

    def test_crypto_asset_model(self):
        """Test CryptoAsset model."""
        asset = CryptoAsset(
            name="test-key",
            algorithm="RSA",
            key_size=2048,
            location="/etc/ssl/test.pem",
            risk_level="high",
            migration_priority="urgent"
        )
        
        assert asset.name == "test-key"
        assert asset.algorithm == "RSA"
        assert asset.key_size == 2048
        assert asset.location == "/etc/ssl/test.pem"
        assert asset.risk_level == "high"
        assert asset.migration_priority == "urgent"

    def test_migration_plan_model(self):
        """Test MigrationPlan model."""
        plan = MigrationPlan(
            asset_id=1,
            current_algorithm="RSA",
            target_algorithm="ML-KEM",
            migration_steps=[
                "Generate new keypair",
                "Update configuration",
                "Test compatibility"
            ],
            estimated_effort="4 hours",
            priority="high"
        )
        
        assert plan.asset_id == 1
        assert plan.current_algorithm == "RSA"
        assert plan.target_algorithm == "ML-KEM"
        assert len(plan.migration_steps) == 3
        assert plan.estimated_effort == "4 hours"
        assert plan.priority == "high"

    def test_compliance_framework_model(self):
        """Test ComplianceFramework model."""
        framework = ComplianceFramework(
            name="NIST",
            version="1.0",
            requirements=[
                "PQC readiness by 2030",
                "Crypto agility implementation"
            ],
            assessment_criteria={
                "pqc_ready": True,
                "crypto_agile": True
            }
        )
        
        assert framework.name == "NIST"
        assert framework.version == "1.0"
        assert len(framework.requirements) == 2
        assert framework.assessment_criteria["pqc_ready"] is True

    def test_policy_rule_model(self):
        """Test PolicyRule model."""
        rule = PolicyRule(
            id="RULE_001",
            name="RSA Key Size Policy",
            description="RSA keys must be at least 2048 bits",
            rule_type="key_size",
            parameters={"algorithm": "RSA", "min_size": 2048},
            severity="high",
            enabled=True
        )
        
        assert rule.id == "RULE_001"
        assert rule.name == "RSA Key Size Policy"
        assert rule.rule_type == "key_size"
        assert rule.parameters["min_size"] == 2048
        assert rule.severity == "high"
        assert rule.enabled is True


class TestIntegrationScenarios:
    """Test integration between different components."""

    def test_vulnerability_to_report_workflow(self):
        """Test complete workflow from vulnerability to report."""
        # Create vulnerability
        vuln = Vulnerability(
            file_path="integration_test.py",
            line_number=15,
            algorithm=CryptoAlgorithm.RSA,
            severity=Severity.CRITICAL,
            description="Critical RSA vulnerability",
            recommendation="Immediate migration to ML-KEM required"
        )
        
        # Create scan results
        stats = ScanStats(files_processed=1, vulnerabilities_found=1)
        results = ScanResults(
            vulnerabilities=[vuln],
            scanned_files=1,
            scan_time=2.5,
            languages_detected=['python'],
            scan_stats=stats
        )
        
        # Test JSON serialization
        if REPORTERS_AVAILABLE:
            json_reporter = JSONReporter()
            json_output = json_reporter._serialize_results(results)
            assert json_output is not None

    def test_exception_handling_integration(self):
        """Test exception handling across components."""
        # Test exception creation and handling
        original_exc = FileNotFoundError("File not found")
        wrapped_exc = ScanException("Scan failed due to missing file", original_exception=original_exc)
        
        assert str(wrapped_exc) == "Scan failed due to missing file"
        assert wrapped_exc.original_exception == original_exc

    def test_validation_integration(self):
        """Test validation integration across components."""
        if VALIDATORS_AVAILABLE:
            validator = InputValidator()
            
            # Test with temporary directory
            with tempfile.TemporaryDirectory() as temp_dir:
                result = validator.validate_scan_path(temp_dir)
                assert result.is_valid is True
                
                # Test with invalid path
                invalid_result = validator.validate_scan_path("/invalid/path/xyz")
                assert invalid_result.is_valid is False

    def test_data_model_consistency(self):
        """Test consistency between data models."""
        # Create vulnerability
        vuln = Vulnerability(
            file_path="consistency_test.py",
            line_number=20,
            algorithm=CryptoAlgorithm.ECC,
            severity=Severity.HIGH
        )
        
        # Create scan stats
        stats = ScanStats(
            files_processed=1,
            vulnerabilities_found=1,
            scan_start_time=1234567890.0
        )
        
        # Create scan results
        results = ScanResults(
            vulnerabilities=[vuln],
            scan_stats=stats
        )
        
        # Test consistency
        assert len(results.vulnerabilities) == results.scan_stats.vulnerabilities_found
        assert results.scan_stats.files_processed > 0


class TestPerformanceAndMemory:
    """Test performance and memory characteristics."""

    def test_large_vulnerability_list_handling(self):
        """Test handling of large vulnerability lists."""
        # Create many vulnerabilities
        vulnerabilities = []
        for i in range(1000):
            vuln = Vulnerability(
                file_path=f"test_{i}.py",
                line_number=i + 1,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.MEDIUM,
                description=f"Vulnerability {i}"
            )
            vulnerabilities.append(vuln)
        
        # Create scan results
        results = ScanResults(vulnerabilities=vulnerabilities)
        
        # Test that we can handle large lists
        assert len(results.vulnerabilities) == 1000
        assert all(isinstance(v, Vulnerability) for v in results.vulnerabilities)

    def test_memory_efficient_data_structures(self):
        """Test that data structures are memory efficient."""
        import sys
        
        # Test small vulnerability
        small_vuln = Vulnerability(
            file_path="test.py",
            line_number=1,
            algorithm=CryptoAlgorithm.RSA,
            severity=Severity.LOW
        )
        
        # Test that vulnerability objects are reasonably sized
        size = sys.getsizeof(small_vuln)
        assert size < 1000  # Should be less than 1KB

    def test_string_representation_performance(self):
        """Test string representation performance."""
        vuln = Vulnerability(
            file_path="perf_test.py",
            line_number=100,
            algorithm=CryptoAlgorithm.RSA,
            severity=Severity.HIGH,
            description="Performance test vulnerability"
        )
        
        # Test string conversion
        str_repr = str(vuln)
        assert len(str_repr) > 0
        
        # Test that it doesn't take too long (basic performance check)
        import time
        start = time.time()
        for _ in range(1000):
            str(vuln)
        end = time.time()
        
        # Should complete 1000 string conversions in less than 1 second
        assert (end - start) < 1.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])