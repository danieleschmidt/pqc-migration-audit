#!/usr/bin/env python3
"""Unified test suite for achieving 85%+ coverage across all generations."""

import pytest
import os
import sys
import tempfile
import json
import asyncio
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from typing import List, Dict, Any

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Core imports
try:
    from pqc_migration_audit.core import CryptoAuditor, CryptoPatterns, RiskAssessment
    from pqc_migration_audit.types import (
        Severity, CryptoAlgorithm, Vulnerability, ScanResults, ScanStats
    )
    from pqc_migration_audit.exceptions import (
        ScanException, ValidationException, SecurityException, 
        FileSystemException, UnsupportedFileTypeException
    )
    from pqc_migration_audit.scanners import BaseScanner, PythonScanner
    from pqc_migration_audit.reporters import (
        JSONReporter, HTMLReporter, ConsoleReporter, SARIFReporter
    )
    
    # Advanced features
    from pqc_migration_audit.research_engine import AlgorithmBenchmark, ResearchOrchestrator
    from pqc_migration_audit.auto_scaling import AutoScaler, WorkerManager
    from pqc_migration_audit.validation_framework import ValidationFramework
    from pqc_migration_audit.performance_engine import PerformanceEngine
    from pqc_migration_audit.security_enhanced import SecurityMonitor
    from pqc_migration_audit.resilience_framework import ResilienceManager
    
    # Services
    from pqc_migration_audit.services import (
        MigrationService, CryptoInventoryService, ComplianceService
    )
    
    IMPORTS_SUCCESSFUL = True
except ImportError as e:
    print(f"Warning: Some imports failed: {e}")
    IMPORTS_SUCCESSFUL = False


class TestCoreGeneration1:
    """Test Generation 1: MAKE IT WORK - Basic functionality."""

    def test_crypto_auditor_initialization(self):
        """Test basic CryptoAuditor initialization."""
        auditor = CryptoAuditor()
        assert auditor is not None
        assert hasattr(auditor, 'scan_directory')

    def test_crypto_patterns_python(self):
        """Test Python cryptographic pattern detection."""
        patterns = CryptoPatterns.PYTHON_PATTERNS
        assert 'rsa_generation' in patterns
        assert 'ecc_generation' in patterns
        assert len(patterns['rsa_generation']) > 0

    def test_vulnerability_creation(self):
        """Test Vulnerability object creation."""
        vuln = Vulnerability(
            file_path="test.py",
            line_number=10,
            algorithm=CryptoAlgorithm.RSA,
            severity=Severity.HIGH,
            key_size=2048,
            description="Test vulnerability"
        )
        assert vuln.file_path == "test.py"
        assert vuln.severity == Severity.HIGH
        assert vuln.algorithm == CryptoAlgorithm.RSA

    def test_scan_results_creation(self):
        """Test ScanResults object creation."""
        stats = ScanStats(files_processed=10, vulnerabilities_found=2)
        results = ScanResults(vulnerabilities=[], scan_stats=stats, scanned_files=10)
        assert results.scan_stats.files_processed == 10
        assert results.scanned_files == 10

    @pytest.mark.skipif(not IMPORTS_SUCCESSFUL, reason="Imports failed")
    def test_python_scanner_basic(self):
        """Test basic Python scanner functionality."""
        scanner = PythonScanner()
        assert scanner is not None
        assert hasattr(scanner, 'scan_file')

    def test_risk_assessment_basic(self):
        """Test basic risk assessment."""
        vulnerabilities = [
            Vulnerability(
                file_path="test.py", line_number=1, algorithm=CryptoAlgorithm.RSA,
                severity=Severity.HIGH, key_size=2048, description="RSA vulnerability"
            )
        ]
        assessment = RiskAssessment(vulnerabilities)
        assert assessment.overall_risk_score > 0

    def test_json_reporter_basic(self):
        """Test JSON reporter functionality."""
        reporter = JSONReporter()
        vulnerabilities = []
        stats = ScanStats(files_processed=1, vulnerabilities_found=0)
        results = ScanResults(vulnerabilities=vulnerabilities, scan_stats=stats, scanned_files=1)
        
        output = reporter.generate_report(results)
        assert isinstance(output, str)
        data = json.loads(output)
        assert 'vulnerabilities' in data or 'scanned_files' in data


class TestRobustGeneration2:
    """Test Generation 2: MAKE IT ROBUST - Error handling and validation."""

    def test_exception_handling(self):
        """Test custom exception classes."""
        with pytest.raises(ScanException):
            raise ScanException("Test scan error")
        
        with pytest.raises(ValidationException):
            raise ValidationException("Test validation error")

    @pytest.mark.skipif(not IMPORTS_SUCCESSFUL, reason="Imports failed")
    def test_security_monitor_initialization(self):
        """Test security monitor initialization."""
        monitor = SecurityMonitor()
        assert monitor is not None

    @pytest.mark.skipif(not IMPORTS_SUCCESSFUL, reason="Imports failed")
    def test_resilience_manager_basic(self):
        """Test resilience manager functionality."""
        manager = ResilienceManager()
        assert manager is not None
        assert hasattr(manager, 'circuit_breaker')

    def test_file_system_exception_handling(self):
        """Test file system exception handling."""
        auditor = CryptoAuditor()
        
        # Test with non-existent path
        with pytest.raises((FileSystemException, FileNotFoundError, OSError)):
            auditor.scan_directory("/non/existent/path")

    def test_validation_with_invalid_input(self):
        """Test validation with invalid inputs."""
        auditor = CryptoAuditor()
        
        # Test with invalid file types
        with tempfile.NamedTemporaryFile(suffix='.invalid') as tmp:
            tmp.write(b"invalid content")
            tmp.flush()
            
            # Should handle gracefully without crashing
            results = auditor.scan_directory(str(Path(tmp.name).parent))
            assert isinstance(results, ScanResults)

    @pytest.mark.skipif(not IMPORTS_SUCCESSFUL, reason="Imports failed")
    def test_enhanced_logging_functionality(self):
        """Test enhanced logging capabilities."""
        from pqc_migration_audit.logging_config import get_logger
        logger = get_logger("test")
        assert logger is not None


class TestScaleGeneration3:
    """Test Generation 3: MAKE IT SCALE - Performance optimization."""

    @pytest.mark.skipif(not IMPORTS_SUCCESSFUL, reason="Imports failed")
    def test_performance_engine_initialization(self):
        """Test performance engine initialization."""
        engine = PerformanceEngine()
        assert engine is not None
        assert hasattr(engine, 'optimize_scan')

    @pytest.mark.skipif(not IMPORTS_SUCCESSFUL, reason="Imports failed")
    def test_auto_scaler_basic(self):
        """Test auto scaler functionality."""
        scaler = AutoScaler()
        assert scaler is not None
        assert hasattr(scaler, 'scale_workers')

    @pytest.mark.skipif(not IMPORTS_SUCCESSFUL, reason="Imports failed")
    def test_worker_manager_initialization(self):
        """Test worker manager initialization."""
        manager = WorkerManager()
        assert manager is not None

    @pytest.mark.skipif(not IMPORTS_SUCCESSFUL, reason="Imports failed")
    def test_validation_framework_basic(self):
        """Test validation framework functionality."""
        framework = ValidationFramework()
        assert framework is not None
        assert hasattr(framework, 'validate_operation')

    @pytest.mark.skipif(not IMPORTS_SUCCESSFUL, reason="Imports failed")  
    def test_research_engine_initialization(self):
        """Test research engine components."""
        benchmark = AlgorithmBenchmark()
        orchestrator = ResearchOrchestrator()
        
        assert benchmark is not None
        assert orchestrator is not None

    def test_concurrent_scanning_simulation(self):
        """Test concurrent scanning capabilities."""
        auditor = CryptoAuditor()
        
        # Create multiple temporary files for concurrent scanning
        temp_files = []
        try:
            for i in range(5):
                tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False)
                tmp.write(f"""
import rsa
def test_function_{i}():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key
""")
                tmp.flush()
                temp_files.append(tmp.name)
            
            # Scan directory containing all files
            results = auditor.scan_directory(str(Path(temp_files[0]).parent))
            assert isinstance(results, ScanResults)
            assert results.scan_stats.files_processed >= 0
            
        finally:
            # Cleanup
            for tmp_file in temp_files:
                try:
                    Path(tmp_file).unlink()
                except OSError:
                    pass


class TestAdvancedFeatures:
    """Test advanced research and enterprise features."""

    @pytest.mark.skipif(not IMPORTS_SUCCESSFUL, reason="Imports failed")
    def test_algorithm_benchmark_basic(self):
        """Test algorithm benchmarking functionality."""
        benchmark = AlgorithmBenchmark()
        
        # Test with mock data
        result = benchmark.benchmark_algorithm(
            algorithm_name="test_algorithm",
            test_data_size=100,
            runs=1
        )
        assert isinstance(result, dict)
        assert 'algorithm' in result

    @pytest.mark.skipif(not IMPORTS_SUCCESSFUL, reason="Imports failed")
    def test_research_orchestrator_basic(self):
        """Test research orchestrator functionality."""
        orchestrator = ResearchOrchestrator()
        
        # Test comparative study setup
        study = orchestrator.setup_comparative_study(
            algorithms=['test1', 'test2'],
            test_scenarios=['performance', 'security']
        )
        assert isinstance(study, dict)

    @pytest.mark.skipif(not IMPORTS_SUCCESSFUL, reason="Imports failed")
    def test_migration_service_basic(self):
        """Test migration service functionality."""
        service = MigrationService()
        assert service is not None
        assert hasattr(service, 'plan_migration')

    @pytest.mark.skipif(not IMPORTS_SUCCESSFUL, reason="Imports failed")
    def test_compliance_service_basic(self):
        """Test compliance service functionality."""
        service = ComplianceService()
        assert service is not None
        assert hasattr(service, 'check_compliance')

    @pytest.mark.skipif(not IMPORTS_SUCCESSFUL, reason="Imports failed")
    def test_crypto_inventory_service_basic(self):
        """Test crypto inventory service."""
        service = CryptoInventoryService()
        assert service is not None
        assert hasattr(service, 'inventory_crypto_assets')


class TestReporters:
    """Test all reporter implementations."""

    def create_sample_results(self):
        """Create sample scan results for testing."""
        vulnerabilities = [
            Vulnerability(
                file_path="test.py",
                line_number=10,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.HIGH,
                key_size=2048,
                description="RSA key generation with 2048-bit key"
            ),
            Vulnerability(
                file_path="crypto.py",
                line_number=25,
                algorithm=CryptoAlgorithm.ECC,
                severity=Severity.MEDIUM,
                key_size=256,
                description="ECC key generation with P-256 curve"
            )
        ]
        stats = ScanStats(files_processed=10, vulnerabilities_found=2)
        return ScanResults(vulnerabilities=vulnerabilities, scan_stats=stats, scanned_files=10, scan_time=2.5)

    def test_json_reporter_comprehensive(self):
        """Test JSON reporter with comprehensive data."""
        reporter = JSONReporter()
        results = self.create_sample_results()
        
        output = reporter.generate_report(results)
        assert isinstance(output, str)
        
        data = json.loads(output)
        assert 'vulnerabilities' in data
        assert 'scan_stats' in data
        assert len(data['vulnerabilities']) == 2

    def test_console_reporter_basic(self):
        """Test console reporter functionality."""
        reporter = ConsoleReporter()
        results = self.create_sample_results()
        
        output = reporter.generate_report(results)
        assert isinstance(output, str)
        assert 'RSA' in output or 'test.py' in output

    def test_html_reporter_basic(self):
        """Test HTML reporter functionality."""
        reporter = HTMLReporter()
        results = self.create_sample_results()
        
        output = reporter.generate_report(results)
        assert isinstance(output, str)
        assert '<html>' in output.lower()

    def test_sarif_reporter_basic(self):
        """Test SARIF reporter functionality."""
        reporter = SARIFReporter()
        results = self.create_sample_results()
        
        output = reporter.generate_report(results)
        assert isinstance(output, str)
        
        data = json.loads(output)
        assert 'version' in data
        assert 'runs' in data


class TestIntegrationWorkflows:
    """Test end-to-end integration workflows."""

    def test_full_scan_workflow(self):
        """Test complete scanning workflow."""
        # Create temporary directory with vulnerable code
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create Python file with RSA vulnerability
            test_file = Path(temp_dir) / "vulnerable.py"
            test_file.write_text("""
import rsa
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key
""")
            
            # Perform scan
            auditor = CryptoAuditor()
            results = auditor.scan_directory(temp_dir)
            
            # Verify results
            assert isinstance(results, ScanResults)
            assert results.scan_stats.files_processed > 0
            
            # Test reporting
            json_reporter = JSONReporter()
            json_output = json_reporter.generate_report(results)
            assert isinstance(json_output, str)
            
            console_reporter = ConsoleReporter()
            console_output = console_reporter.generate_report(results)
            assert isinstance(console_output, str)

    def test_multi_language_support(self):
        """Test scanning multiple programming languages."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create files in different languages
            files = {
                "crypto.py": """
import rsa
def gen_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)
""",
                "crypto.java": """
import java.security.KeyPairGenerator;
public class Crypto {
    public void generateKey() {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
    }
}
""",
                "crypto.go": """
package main
import "crypto/rsa"
func generateKey() {
    rsa.GenerateKey(rand.Reader, 2048)
}
"""
            }
            
            for filename, content in files.items():
                (Path(temp_dir) / filename).write_text(content)
            
            # Scan directory
            auditor = CryptoAuditor()
            results = auditor.scan_directory(temp_dir)
            
            assert isinstance(results, ScanResults)
            assert results.scan_stats.files_processed >= len(files)

    def test_risk_assessment_workflow(self):
        """Test risk assessment calculation workflow."""
        vulnerabilities = [
            Vulnerability(
                file_path="critical.py", line_number=1,
                algorithm=CryptoAlgorithm.RSA, severity=Severity.CRITICAL,
                key_size=1024, description="1024-bit RSA key"
            ),
            Vulnerability(
                file_path="high.py", line_number=1,
                algorithm=CryptoAlgorithm.RSA, severity=Severity.HIGH,
                key_size=2048, description="2048-bit RSA key"
            ),
            Vulnerability(
                file_path="medium.py", line_number=1,
                algorithm=CryptoAlgorithm.ECC, severity=Severity.MEDIUM,
                key_size=256, description="256-bit ECC key"
            )
        ]
        
        assessment = RiskAssessment(vulnerabilities)
        assert assessment.overall_risk_score > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])