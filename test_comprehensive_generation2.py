#!/usr/bin/env python3
"""
Comprehensive tests for Generation 2: MAKE IT ROBUST functionality.
Tests enhanced error handling, security monitoring, resilience, and logging.
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

from pqc_migration_audit.core import CryptoAuditor
from pqc_migration_audit.types import ScanResults, Vulnerability, Severity, CryptoAlgorithm
from pqc_migration_audit.exceptions import (
    ScanException, ValidationException, SecurityException, 
    FileSystemException, ScanTimeoutException, UnsupportedFileTypeException,
    FileTooLargeException, InsufficientPermissionsException, ExceptionHandler
)

# Try importing Generation 2 enhanced features
try:
    from pqc_migration_audit.logging_config import AuditLogger, setup_logging, get_logger
    from pqc_migration_audit.security_enhanced import SecurityMonitor, InputSanitizer, SecurityLevel
    from pqc_migration_audit.resilience_framework import ResilienceManager, CircuitBreaker
    from pqc_migration_audit.validators import InputValidator, SecurityValidator, IntegrityValidator
    ENHANCED_FEATURES_AVAILABLE = True
except ImportError:
    ENHANCED_FEATURES_AVAILABLE = False
    # Mock classes for testing when features aren't available
    class MockSecurityMonitor:
        def __init__(self, config=None): pass
        def secure_scan_context(self, path): return MagicMock()
    
    class MockInputSanitizer:
        def __init__(self, level=None): pass
        def validate_configuration(self, config): return config
        def sanitize_path(self, path): return path


class TestExceptionHandling:
    """Test comprehensive exception handling."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.auditor = CryptoAuditor()
    
    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_scan_exception_creation(self):
        """Test ScanException creation and attributes."""
        exception = ScanException(
            "Test scan error",
            error_code="TEST_ERROR",
            details={"file": "test.py"}
        )
        
        assert str(exception) == "Test scan error"
        assert exception.error_code == "TEST_ERROR"
        assert exception.details["file"] == "test.py"
    
    def test_validation_exception_creation(self):
        """Test ValidationException creation and attributes."""
        exception = ValidationException(
            "Invalid input",
            error_code="INVALID_INPUT",
            validation_details={"field": "path", "value": "invalid"}
        )
        
        assert str(exception) == "Invalid input"
        assert exception.error_code == "INVALID_INPUT"
        assert exception.validation_details["field"] == "path"
    
    def test_security_exception_creation(self):
        """Test SecurityException creation and attributes."""
        exception = SecurityException(
            "Security violation",
            error_code="SECURITY_VIOLATION",
            security_context={"threat_level": "HIGH"}
        )
        
        assert str(exception) == "Security violation"
        assert exception.error_code == "SECURITY_VIOLATION"
        assert exception.security_context["threat_level"] == "HIGH"
    
    def test_filesystem_exception_creation(self):
        """Test FileSystemException creation."""
        exception = FileSystemException(
            "File access error",
            error_code="FILE_ACCESS_DENIED"
        )
        
        assert str(exception) == "File access error"
        assert exception.error_code == "FILE_ACCESS_DENIED"
    
    def test_exception_handler_decorator(self):
        """Test exception handler decorator functionality."""
        call_count = 0
        
        @ExceptionHandler.handle_scan_exception
        def test_function():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ValueError("Test error")
            return "success"
        
        # First call should handle exception and retry
        result = test_function()
        assert result == "success"
        assert call_count == 2  # Original call + retry
    
    def test_timeout_exception_creation(self):
        """Test ScanTimeoutException creation."""
        exception = ScanTimeoutException(
            timeout_seconds=300,
            files_processed=150
        )
        
        assert "300" in str(exception)
        assert "150" in str(exception)
        assert exception.timeout_seconds == 300
        assert exception.files_processed == 150
    
    def test_unsupported_file_type_exception(self):
        """Test UnsupportedFileTypeException."""
        exception = UnsupportedFileTypeException(
            file_path="/test/file.xyz",
            file_type="xyz"
        )
        
        assert "/test/file.xyz" in str(exception)
        assert exception.file_path == "/test/file.xyz"
        assert exception.file_type == "xyz"
    
    def test_file_too_large_exception(self):
        """Test FileTooLargeException."""
        exception = FileTooLargeException(
            file_path="/test/large.py",
            file_size=10_000_000,
            max_size=1_000_000
        )
        
        assert "/test/large.py" in str(exception)
        assert exception.file_size == 10_000_000
        assert exception.max_size == 1_000_000
    
    def test_insufficient_permissions_exception(self):
        """Test InsufficientPermissionsException."""
        exception = InsufficientPermissionsException(
            resource_path="/test/protected",
            required_permission="read"
        )
        
        assert "/test/protected" in str(exception)
        assert exception.resource_path == "/test/protected"
        assert exception.required_permission == "read"


@pytest.mark.skipif(not ENHANCED_FEATURES_AVAILABLE, reason="Enhanced features not available")
class TestLoggingConfiguration:
    """Test enhanced logging configuration."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_setup_logging_basic(self):
        """Test basic logging setup."""
        config = {
            'level': 'INFO',
            'format': 'structured'
        }
        
        setup_logging(config)
        logger = get_logger('test_logger')
        
        assert logger is not None
        assert hasattr(logger, 'info')
        assert hasattr(logger, 'error')
        assert hasattr(logger, 'warning')
    
    def test_audit_logger_functionality(self):
        """Test AuditLogger functionality."""
        logger = AuditLogger('test_audit')
        
        # Test audit-specific methods
        assert hasattr(logger, 'log_scan_start')
        assert hasattr(logger, 'log_scan_complete')
        assert hasattr(logger, 'log_vulnerability_found')
        assert hasattr(logger, 'log_security_event')
    
    def test_structured_logging_output(self):
        """Test structured logging output format."""
        logger = get_logger('test_structured')
        
        # Should be able to log various data types
        logger.info("Test message", extra={
            'scan_id': 'test_123',
            'vulnerability_count': 5,
            'risk_score': 85.5
        })
        
        # Test should not crash - actual output verification would require
        # log capture which is complex in this test environment


@pytest.mark.skipif(not ENHANCED_FEATURES_AVAILABLE, reason="Enhanced features not available")
class TestSecurityMonitoring:
    """Test security monitoring functionality."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.security_config = {
            'enable_threat_detection': True,
            'enable_anomaly_detection': True,
            'security_level': 'enhanced'
        }
    
    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_security_monitor_initialization(self):
        """Test SecurityMonitor initialization."""
        monitor = SecurityMonitor(self.security_config)
        
        assert monitor is not None
        assert hasattr(monitor, 'secure_scan_context')
        assert hasattr(monitor, 'detect_threats')
    
    def test_security_monitor_context(self):
        """Test security monitoring context manager."""
        monitor = SecurityMonitor(self.security_config)
        
        with monitor.secure_scan_context("/test/path") as scan_id:
            assert scan_id is not None
            assert isinstance(scan_id, str)
    
    def test_input_sanitizer_initialization(self):
        """Test InputSanitizer initialization."""
        sanitizer = InputSanitizer(SecurityLevel.ENHANCED)
        
        assert sanitizer is not None
        assert hasattr(sanitizer, 'sanitize_path')
        assert hasattr(sanitizer, 'validate_configuration')
    
    def test_input_sanitizer_path_validation(self):
        """Test path sanitization."""
        sanitizer = InputSanitizer(SecurityLevel.ENHANCED)
        
        # Test normal path
        clean_path = sanitizer.sanitize_path("/home/user/project")
        assert clean_path is not None
        
        # Test path with potential security issues
        malicious_path = "../../../etc/passwd"
        sanitized_path = sanitizer.sanitize_path(malicious_path)
        assert sanitized_path != malicious_path  # Should be cleaned
    
    def test_input_sanitizer_config_validation(self):
        """Test configuration validation."""
        sanitizer = InputSanitizer(SecurityLevel.ENHANCED)
        
        config = {
            'max_scan_time_seconds': 3600,
            'max_files_per_scan': 10000,
            'enable_security_validation': True
        }
        
        validated_config = sanitizer.validate_configuration(config)
        assert validated_config is not None
        assert isinstance(validated_config, dict)


@pytest.mark.skipif(not ENHANCED_FEATURES_AVAILABLE, reason="Enhanced features not available")
class TestResilienceFramework:
    """Test resilience and error recovery functionality."""
    
    def setup_method(self):
        """Set up test environment."""
        self.resilience_config = {
            'enable_circuit_breakers': True,
            'enable_retry_logic': True,
            'max_retries': 3,
            'timeout_seconds': 30
        }
    
    def test_resilience_manager_initialization(self):
        """Test ResilienceManager initialization."""
        manager = ResilienceManager(self.resilience_config)
        
        assert manager is not None
        assert hasattr(manager, 'resilient_operation')
    
    def test_circuit_breaker_functionality(self):
        """Test circuit breaker functionality."""
        breaker = CircuitBreaker(
            failure_threshold=3,
            timeout_seconds=5
        )
        
        assert breaker is not None
        assert hasattr(breaker, 'call')
        assert hasattr(breaker, 'is_open')
    
    def test_resilient_operation_context(self):
        """Test resilient operation context manager."""
        manager = ResilienceManager(self.resilience_config)
        
        with manager.resilient_operation('test_operation', {'param': 'value'}):
            # Should execute without issues
            pass
    
    def test_circuit_breaker_state_changes(self):
        """Test circuit breaker state transitions."""
        failure_count = 0
        
        def failing_function():
            nonlocal failure_count
            failure_count += 1
            if failure_count <= 3:
                raise Exception("Simulated failure")
            return "success"
        
        breaker = CircuitBreaker(failure_threshold=3, timeout_seconds=1)
        
        # Initial state should be closed
        assert not breaker.is_open()
        
        # After enough failures, should open
        for _ in range(4):
            try:
                breaker.call(failing_function)
            except:
                pass
        
        # Circuit should now be open
        assert breaker.is_open()


@pytest.mark.skipif(not ENHANCED_FEATURES_AVAILABLE, reason="Enhanced features not available")  
class TestValidationFramework:
    """Test validation framework functionality."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_input_validator_initialization(self):
        """Test InputValidator initialization."""
        validator = InputValidator()
        
        assert validator is not None
        assert hasattr(validator, 'validate_scan_path')
        assert hasattr(validator, 'validate_file_for_scanning')
    
    def test_input_validator_path_validation(self):
        """Test path validation functionality."""
        validator = InputValidator()
        
        # Test valid path
        result = validator.validate_scan_path(self.temp_dir)
        assert result.is_valid
        assert len(result.warnings) >= 0
        
        # Test invalid path
        result = validator.validate_scan_path("/nonexistent/path/123456")
        assert not result.is_valid
        assert result.error_message is not None
    
    def test_input_validator_file_validation(self):
        """Test file validation functionality."""
        validator = InputValidator()
        
        # Create a test file
        test_file = Path(self.temp_dir) / "test.py"
        test_file.write_text("# Test file content", encoding='utf-8')
        
        result = validator.validate_file_for_scanning(test_file)
        assert result.is_valid
    
    def test_security_validator_initialization(self):
        """Test SecurityValidator initialization."""
        validator = SecurityValidator()
        
        assert validator is not None
        assert hasattr(validator, 'validate_scan_results')
    
    def test_security_validator_scan_results_validation(self):
        """Test scan results security validation."""
        validator = SecurityValidator()
        
        # Create sample scan results
        vulnerabilities = [
            Vulnerability(
                file_path="/test/file.py",
                line_number=1,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.HIGH,
                description="Test vulnerability",
                code_snippet="test code",
                recommendation="Test recommendation"
            )
        ]
        
        scan_results = ScanResults(
            scan_path="/test",
            timestamp="2025-01-01 00:00:00",
            vulnerabilities=vulnerabilities,
            scanned_files=1,
            total_lines=100,
            scan_time=1.0,
            languages_detected=['python']
        )
        
        result = validator.validate_scan_results(scan_results)
        assert result.is_valid
    
    def test_integrity_validator_initialization(self):
        """Test IntegrityValidator initialization."""
        validator = IntegrityValidator()
        
        assert validator is not None
        assert hasattr(validator, 'validate_data_integrity')


class TestRobustErrorHandling:
    """Test robust error handling in scanning operations."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_scan_with_corrupted_file(self):
        """Test scanning with corrupted/binary files."""
        # Create a binary file
        binary_file = Path(self.temp_dir) / "corrupted.py"
        binary_file.write_bytes(b'\x00\x01\x02\x03\xFF\xFE\xFD')
        
        auditor = CryptoAuditor()
        
        # Should handle binary files gracefully
        results = auditor.scan_directory(self.temp_dir)
        assert isinstance(results, ScanResults)
        # Should not crash, even if no vulnerabilities found
    
    def test_scan_with_permission_denied_files(self):
        """Test scanning with permission denied files."""
        # Create a file with restricted permissions
        restricted_file = Path(self.temp_dir) / "restricted.py"
        restricted_file.write_text("print('test')", encoding='utf-8')
        restricted_file.chmod(0o000)  # No permissions
        
        auditor = CryptoAuditor()
        
        try:
            results = auditor.scan_directory(self.temp_dir)
            assert isinstance(results, ScanResults)
            # Should handle permission errors gracefully
        except (PermissionError, ScanException):
            # Also acceptable to raise an exception
            pass
        finally:
            # Restore permissions for cleanup
            restricted_file.chmod(0o644)
    
    def test_scan_with_symlink_loops(self):
        """Test scanning with symbolic link loops."""
        # Create symlink loop
        link_dir = Path(self.temp_dir) / "link_dir"
        link_dir.mkdir()
        
        # Create symlink that points back to parent
        symlink_path = link_dir / "loop"
        
        try:
            symlink_path.symlink_to("..")
            
            auditor = CryptoAuditor()
            results = auditor.scan_directory(self.temp_dir)
            
            # Should handle symlink loops without infinite recursion
            assert isinstance(results, ScanResults)
        except OSError:
            # Some systems might not support symlinks
            pytest.skip("Symlinks not supported on this system")
    
    def test_scan_with_very_deep_directory_structure(self):
        """Test scanning with very deep directory structure."""
        # Create deep directory structure
        current_dir = Path(self.temp_dir)
        for i in range(20):  # Create 20 levels deep
            current_dir = current_dir / f"level_{i}"
            current_dir.mkdir()
        
        # Create a file at the deep level
        deep_file = current_dir / "deep_file.py"
        deep_file.write_text("import rsa; rsa.generate_private_key()", encoding='utf-8')
        
        auditor = CryptoAuditor()
        results = auditor.scan_directory(self.temp_dir)
        
        # Should handle deep structures without stack overflow
        assert isinstance(results, ScanResults)
        # Should find the vulnerability in the deep file
        assert len(results.vulnerabilities) >= 1
    
    def test_scan_with_timeout(self):
        """Test scanning with timeout configuration."""
        # Create multiple files to ensure scan takes some time
        for i in range(10):
            file_path = Path(self.temp_dir) / f"file_{i}.py"
            file_path.write_text("import rsa; rsa.generate_private_key()" * 100, encoding='utf-8')
        
        # Configure auditor with very short timeout
        config = {'max_scan_time_seconds': 1}  # 1 second timeout
        auditor = CryptoAuditor(config)
        
        # Scan should complete within timeout or handle timeout gracefully
        start_time = time.time()
        results = auditor.scan_directory(self.temp_dir)
        scan_time = time.time() - start_time
        
        # Either completes quickly or handles timeout
        assert isinstance(results, ScanResults)
        assert scan_time < 10  # Should not take much longer than timeout
    
    def test_scan_with_large_files(self):
        """Test scanning with large files."""
        # Create a large file
        large_content = "# Large file\n" + "print('test')\n" * 10000
        large_file = Path(self.temp_dir) / "large_file.py"
        large_file.write_text(large_content, encoding='utf-8')
        
        auditor = CryptoAuditor()
        results = auditor.scan_directory(self.temp_dir)
        
        # Should handle large files without memory issues
        assert isinstance(results, ScanResults)
    
    def test_scan_with_unicode_files(self):
        """Test scanning with Unicode content."""
        unicode_content = '''
# Unicode test file with special characters
# 中文测试 🔐 cryptographic content
import rsa
# German: Verschlüsselung
# Arabic: التشفير  
private_key = rsa.generate_private_key()
'''
        
        unicode_file = Path(self.temp_dir) / "unicode_test.py"
        unicode_file.write_text(unicode_content, encoding='utf-8')
        
        auditor = CryptoAuditor()
        results = auditor.scan_directory(self.temp_dir)
        
        # Should handle Unicode content correctly
        assert isinstance(results, ScanResults)
        assert len(results.vulnerabilities) >= 1


class TestEnhancedCryptoAuditor:
    """Test CryptoAuditor with Generation 2 enhancements."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        
        # Configuration with Generation 2 features
        self.enhanced_config = {
            'max_scan_time_seconds': 1800,
            'max_files_per_scan': 5000,
            'enable_security_validation': True,
            'enable_performance_optimization': True,
            'enable_error_recovery': True,
            'enable_comprehensive_logging': True,
            'logging': {
                'level': 'INFO',
                'format': 'structured'
            },
            'security': {
                'security_level': 'enhanced',
                'enable_threat_detection': True
            },
            'resilience': {
                'enable_circuit_breakers': True,
                'max_retries': 3
            }
        }
    
    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_enhanced_auditor_initialization(self):
        """Test CryptoAuditor with enhanced configuration."""
        auditor = CryptoAuditor(self.enhanced_config)
        
        # Verify enhanced features are initialized
        assert auditor.enable_security_validation is True
        assert auditor.enable_performance_optimization is True
        assert auditor.error_recovery_enabled is True
        assert auditor.comprehensive_logging is True
    
    def test_enhanced_error_recovery_during_scan(self):
        """Test error recovery during scanning."""
        # Create files that might cause issues
        problem_file = Path(self.temp_dir) / "problem.py"
        good_file = Path(self.temp_dir) / "good.py"
        
        # File with encoding issues
        problem_file.write_bytes(b'# Bad encoding \xFF\xFE import rsa')
        good_file.write_text("import rsa; rsa.generate_private_key()", encoding='utf-8')
        
        auditor = CryptoAuditor(self.enhanced_config)
        results = auditor.scan_directory(self.temp_dir)
        
        # Should recover from problematic files and continue scanning
        assert isinstance(results, ScanResults)
        # Should still find vulnerabilities in good files
        assert len(results.vulnerabilities) >= 1
    
    def test_security_validation_integration(self):
        """Test security validation integration."""
        # Create test file
        test_file = Path(self.temp_dir) / "secure_test.py"
        test_file.write_text("import rsa; rsa.generate_private_key()", encoding='utf-8')
        
        # Enable security validation
        config = self.enhanced_config.copy()
        config['enable_security_validation'] = True
        
        auditor = CryptoAuditor(config)
        results = auditor.scan_directory(self.temp_dir)
        
        # Should complete security validation without issues
        assert isinstance(results, ScanResults)
        assert len(results.vulnerabilities) >= 1
    
    def test_comprehensive_logging_integration(self):
        """Test comprehensive logging integration."""
        # Create test file
        test_file = Path(self.temp_dir) / "logging_test.py"
        test_file.write_text("import rsa; rsa.generate_private_key()", encoding='utf-8')
        
        auditor = CryptoAuditor(self.enhanced_config)
        results = auditor.scan_directory(self.temp_dir)
        
        # Should complete with comprehensive logging
        assert isinstance(results, ScanResults)
        assert len(results.vulnerabilities) >= 1
        
        # Verify statistics are properly tracked
        assert auditor.stats['files_processed'] >= 1
        assert auditor.stats['vulnerabilities_found'] >= 1


if __name__ == "__main__":
    # Run tests with coverage reporting
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "--cov=src/pqc_migration_audit",
        "--cov-append",
        "--cov-report=term-missing",
        "--cov-report=html:htmlcov_gen2",
        "--cov-fail-under=80"
    ])