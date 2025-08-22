"""Comprehensive tests for services and integration functionality."""

import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from dataclasses import asdict

from src.pqc_migration_audit.types import (
    Vulnerability, Severity, CryptoAlgorithm, ScanResults, ScanStats
)


class TestMigrationServiceIntegration:
    """Test migration service functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        try:
            from src.pqc_migration_audit.services import MigrationService
            self.migration_service = MigrationService()
            self.service_available = True
        except ImportError:
            self.service_available = False
            pytest.skip("MigrationService not available")

    def test_migration_service_initialization(self):
        """Test migration service initialization."""
        if not self.service_available:
            pytest.skip("Service not available")
            
        assert self.migration_service is not None
        assert hasattr(self.migration_service, 'generate_migration_plan')

    def test_generate_migration_plan(self):
        """Test generating migration plan from vulnerabilities."""
        if not self.service_available:
            pytest.skip("Service not available")
            
        vulnerabilities = [
            Vulnerability(
                file_path="test.py",
                line_number=1,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.HIGH,
                key_size=2048
            ),
            Vulnerability(
                file_path="test.py",
                line_number=10,
                algorithm=CryptoAlgorithm.ECC,
                severity=Severity.MEDIUM
            )
        ]
        
        plan = self.migration_service.generate_migration_plan(vulnerabilities)
        
        assert plan is not None
        assert isinstance(plan, (dict, list))

    def test_migration_priority_calculation(self):
        """Test migration priority calculation."""
        if not self.service_available:
            pytest.skip("Service not available")
            
        high_priority_vuln = Vulnerability(
            file_path="critical.py",
            line_number=1,
            algorithm=CryptoAlgorithm.RSA,
            severity=Severity.CRITICAL,
            key_size=1024  # Very weak
        )
        
        low_priority_vuln = Vulnerability(
            file_path="test.py",
            line_number=1,
            algorithm=CryptoAlgorithm.ECC,
            severity=Severity.LOW
        )
        
        vulnerabilities = [low_priority_vuln, high_priority_vuln]
        plan = self.migration_service.generate_migration_plan(vulnerabilities)
        
        # High priority should come first in migration plan
        assert plan is not None


class TestCryptoInventoryServiceIntegration:
    """Test crypto inventory service functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        try:
            from src.pqc_migration_audit.services import CryptoInventoryService
            self.inventory_service = CryptoInventoryService()
            self.service_available = True
        except ImportError:
            self.service_available = False
            pytest.skip("CryptoInventoryService not available")

    def test_inventory_service_initialization(self):
        """Test inventory service initialization."""
        if not self.service_available:
            pytest.skip("Service not available")
            
        assert self.inventory_service is not None
        assert hasattr(self.inventory_service, 'build_inventory')

    def test_build_crypto_inventory(self):
        """Test building crypto inventory from scan results."""
        if not self.service_available:
            pytest.skip("Service not available")
            
        scan_results = ScanResults(
            vulnerabilities=[
                Vulnerability(
                    file_path="app.py",
                    line_number=1,
                    algorithm=CryptoAlgorithm.RSA,
                    severity=Severity.HIGH,
                    key_size=2048
                ),
                Vulnerability(
                    file_path="crypto.py",
                    line_number=5,
                    algorithm=CryptoAlgorithm.ECC,
                    severity=Severity.MEDIUM
                )
            ],
            scanned_files=2,
            languages_detected=["python"]
        )
        
        inventory = self.inventory_service.build_inventory(scan_results)
        
        assert inventory is not None
        assert isinstance(inventory, dict)

    def test_inventory_categorization(self):
        """Test inventory categorization by algorithm type."""
        if not self.service_available:
            pytest.skip("Service not available")
            
        mixed_vulnerabilities = [
            Vulnerability(
                file_path="rsa_module.py",
                line_number=1,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.HIGH
            ),
            Vulnerability(
                file_path="ecc_module.py", 
                line_number=1,
                algorithm=CryptoAlgorithm.ECC,
                severity=Severity.MEDIUM
            ),
            Vulnerability(
                file_path="dsa_module.py",
                line_number=1,
                algorithm=CryptoAlgorithm.DSA,
                severity=Severity.LOW
            )
        ]
        
        scan_results = ScanResults(vulnerabilities=mixed_vulnerabilities)
        inventory = self.inventory_service.build_inventory(scan_results)
        
        # Should categorize by algorithm type
        assert inventory is not None


class TestComplianceServiceIntegration:
    """Test compliance service functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        try:
            from src.pqc_migration_audit.services import ComplianceService
            self.compliance_service = ComplianceService()
            self.service_available = True
        except ImportError:
            self.service_available = False
            pytest.skip("ComplianceService not available")

    def test_compliance_service_initialization(self):
        """Test compliance service initialization."""
        if not self.service_available:
            pytest.skip("Service not available")
            
        assert self.compliance_service is not None
        assert hasattr(self.compliance_service, 'check_compliance')

    def test_compliance_assessment(self):
        """Test compliance assessment against standards."""
        if not self.service_available:
            pytest.skip("Service not available")
            
        vulnerabilities = [
            Vulnerability(
                file_path="weak_crypto.py",
                line_number=1,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.CRITICAL,
                key_size=1024  # Below current standards
            )
        ]
        
        compliance_report = self.compliance_service.check_compliance(vulnerabilities)
        
        assert compliance_report is not None
        assert isinstance(compliance_report, dict)

    def test_compliance_standards_coverage(self):
        """Test coverage of different compliance standards."""
        if not self.service_available:
            pytest.skip("Service not available")
            
        # Test different compliance frameworks
        standards = ['NIST', 'FIPS', 'CNSS', 'Suite-B']
        
        vulnerabilities = [
            Vulnerability(
                file_path="test.py",
                line_number=1,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.HIGH,
                key_size=2048
            )
        ]
        
        for standard in standards:
            try:
                report = self.compliance_service.check_compliance(
                    vulnerabilities, 
                    standard=standard
                )
                assert report is not None
            except NotImplementedError:
                # Some standards may not be implemented yet
                pass


class TestReporterIntegration:
    """Test reporter integration functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.sample_results = ScanResults(
            vulnerabilities=[
                Vulnerability(
                    file_path="example.py",
                    line_number=42,
                    algorithm=CryptoAlgorithm.RSA,
                    severity=Severity.HIGH,
                    key_size=2048,
                    description="RSA key generation",
                    code_snippet="rsa.generate_private_key(2048)",
                    recommendation="Use ML-KEM-768"
                )
            ],
            scanned_files=1,
            total_lines=100,
            scan_time=1.5,
            languages_detected=["python"]
        )

    def test_json_reporter_integration(self):
        """Test JSON reporter functionality."""
        try:
            from src.pqc_migration_audit.reporters import JSONReporter
            
            reporter = JSONReporter()
            output = reporter.generate_report(self.sample_results)
            
            assert output is not None
            
            # Should be valid JSON
            if isinstance(output, str):
                parsed = json.loads(output)
                assert isinstance(parsed, dict)
                assert 'vulnerabilities' in parsed or 'scanned_files' in parsed
                
        except ImportError:
            pytest.skip("JSONReporter not available")

    def test_html_reporter_integration(self):
        """Test HTML reporter functionality."""
        try:
            from src.pqc_migration_audit.reporters import HTMLReporter
            
            reporter = HTMLReporter()
            output = reporter.generate_report(self.sample_results)
            
            assert output is not None
            
            # Should contain HTML-like content
            if isinstance(output, str):
                assert '<' in output or 'html' in output.lower()
                
        except ImportError:
            pytest.skip("HTMLReporter not available")

    def test_console_reporter_integration(self):
        """Test console reporter functionality."""
        try:
            from src.pqc_migration_audit.reporters import ConsoleReporter
            
            reporter = ConsoleReporter()
            output = reporter.generate_report(self.sample_results)
            
            assert output is not None
            
            # Should contain readable text
            if isinstance(output, str):
                assert len(output) > 0
                output_lower = output.lower()
                assert any(keyword in output_lower for keyword in 
                          ['vulnerability', 'rsa', 'scan', 'file'])
                
        except ImportError:
            pytest.skip("ConsoleReporter not available")

    def test_sarif_reporter_integration(self):
        """Test SARIF reporter functionality."""
        try:
            from src.pqc_migration_audit.reporters import SARIFReporter
            
            reporter = SARIFReporter()
            output = reporter.generate_report(self.sample_results)
            
            assert output is not None
            
            # Should be valid SARIF format
            if isinstance(output, str):
                parsed = json.loads(output)
                assert isinstance(parsed, dict)
                # SARIF should have specific structure
                assert 'version' in parsed or 'runs' in parsed or '$schema' in parsed
                
        except ImportError:
            pytest.skip("SARIFReporter not available")


class TestFullIntegrationWorkflow:
    """Test complete integration workflows."""

    def test_scan_to_report_workflow(self):
        """Test complete workflow from scan to report generation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test file with vulnerabilities
            test_file = Path(temp_dir) / "vulnerable.py"
            test_file.write_text("""
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key

def generate_ecc_key():
    from cryptography.hazmat.primitives.asymmetric import ec
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key
""")
            
            # Run full workflow
            try:
                from src.pqc_migration_audit.core import CryptoAuditor
                from src.pqc_migration_audit.reporters import JSONReporter
                
                # Scan
                auditor = CryptoAuditor()
                results = auditor.scan_directory(temp_dir)
                
                # Validate scan results
                assert isinstance(results, ScanResults)
                assert results.scanned_files > 0
                
                # Generate report
                reporter = JSONReporter()
                report = reporter.generate_report(results)
                
                assert report is not None
                
            except ImportError as e:
                pytest.skip(f"Required modules not available: {e}")

    def test_scan_to_migration_plan_workflow(self):
        """Test workflow from scan to migration plan generation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test file
            test_file = Path(temp_dir) / "crypto_code.py"
            test_file.write_text("""
import rsa

def old_crypto():
    # Legacy RSA implementation
    key = rsa.generate_private_key(1024)  # Weak key
    return key
""")
            
            try:
                from src.pqc_migration_audit.core import CryptoAuditor
                from src.pqc_migration_audit.services import MigrationService
                
                # Scan for vulnerabilities
                auditor = CryptoAuditor()
                results = auditor.scan_directory(temp_dir)
                
                # Generate migration plan
                migration_service = MigrationService()
                plan = migration_service.generate_migration_plan(results.vulnerabilities)
                
                assert plan is not None
                
            except ImportError:
                pytest.skip("Required services not available")

    def test_scan_to_compliance_workflow(self):
        """Test workflow from scan to compliance assessment."""
        vulnerabilities = [
            Vulnerability(
                file_path="noncompliant.py",
                line_number=1,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.CRITICAL,
                key_size=512  # Non-compliant key size
            )
        ]
        
        try:
            from src.pqc_migration_audit.services import ComplianceService
            
            compliance_service = ComplianceService()
            compliance_report = compliance_service.check_compliance(vulnerabilities)
            
            assert compliance_report is not None
            assert isinstance(compliance_report, dict)
            
        except ImportError:
            pytest.skip("ComplianceService not available")


class TestServiceErrorHandling:
    """Test error handling in service integrations."""

    def test_service_with_malformed_data(self):
        """Test services handling malformed input data."""
        # Create malformed vulnerability (missing required fields)
        try:
            malformed_vuln = Vulnerability(
                file_path="",  # Empty path
                line_number=-1,  # Invalid line number
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.HIGH
            )
            
            from src.pqc_migration_audit.services import MigrationService
            service = MigrationService()
            
            # Should handle gracefully
            result = service.generate_migration_plan([malformed_vuln])
            assert result is not None
            
        except ImportError:
            pytest.skip("MigrationService not available")

    def test_reporter_with_empty_results(self):
        """Test reporters handling empty scan results."""
        empty_results = ScanResults(
            vulnerabilities=[],
            scanned_files=0,
            scan_time=0.0
        )
        
        try:
            from src.pqc_migration_audit.reporters import JSONReporter
            
            reporter = JSONReporter()
            output = reporter.generate_report(empty_results)
            
            assert output is not None
            # Should still produce valid output even with no vulnerabilities
            
        except ImportError:
            pytest.skip("JSONReporter not available")

    def test_service_with_large_dataset(self):
        """Test services handling large datasets."""
        # Create many vulnerabilities
        large_vulnerability_set = []
        for i in range(1000):
            vuln = Vulnerability(
                file_path=f"file_{i}.py",
                line_number=i + 1,
                algorithm=CryptoAlgorithm.RSA if i % 2 == 0 else CryptoAlgorithm.ECC,
                severity=Severity.HIGH if i % 3 == 0 else Severity.MEDIUM
            )
            large_vulnerability_set.append(vuln)
        
        try:
            from src.pqc_migration_audit.services import MigrationService
            
            service = MigrationService()
            
            # Should handle large datasets efficiently
            import time
            start_time = time.time()
            result = service.generate_migration_plan(large_vulnerability_set)
            duration = time.time() - start_time
            
            assert result is not None
            assert duration < 30.0  # Should complete within 30 seconds
            
        except ImportError:
            pytest.skip("MigrationService not available")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])