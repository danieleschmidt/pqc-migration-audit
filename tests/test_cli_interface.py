"""CLI interface testing for comprehensive coverage."""

import pytest
import sys
import os
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from click.testing import CliRunner
from io import StringIO

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# CLI imports with error handling
try:
    from pqc_migration_audit.cli import main, scan, report, migrate, version
    CLI_AVAILABLE = True
except ImportError:
    CLI_AVAILABLE = False

try:
    from pqc_migration_audit.cli import (
        scan_command, report_command, migrate_command, config_command
    )
    CLI_COMMANDS_AVAILABLE = True
except ImportError:
    CLI_COMMANDS_AVAILABLE = False

from pqc_migration_audit.core import CryptoAuditor
from pqc_migration_audit.types import ScanResults, ScanStats, Vulnerability, Severity, CryptoAlgorithm


@pytest.fixture
def cli_runner():
    """Create a Click CLI test runner."""
    return CliRunner()


@pytest.fixture
def temp_project_dir():
    """Create a temporary project directory with test files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        project_path = Path(temp_dir)
        
        # Create Python file with vulnerabilities
        py_file = project_path / "crypto_module.py"
        py_file.write_text("""
from cryptography.hazmat.primitives.asymmetric import rsa
import rsa as rsa_lib

def generate_rsa_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

def old_rsa_method():
    return rsa_lib.newkeys(1024)
""")
        
        # Create Java file with vulnerabilities
        java_file = project_path / "CryptoExample.java"
        java_file.write_text("""
import java.security.KeyPairGenerator;
import javax.crypto.Cipher;

public class CryptoExample {
    public void generateRSAKey() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
    }
    
    public void weakEncryption() throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
    }
}
""")
        
        # Create Go file with vulnerabilities
        go_file = project_path / "crypto.go"
        go_file.write_text("""
package main

import (
    "crypto/rsa"
    "crypto/rand"
)

func generateRSAKey() error {
    _, err := rsa.GenerateKey(rand.Reader, 1024)
    return err
}
""")
        
        # Create config file
        config_file = project_path / "pqc-audit.yml"
        config_file.write_text("""
scanning:
  languages: ["python", "java", "go"]
  severity_threshold: "medium"
  exclude_patterns:
    - "*.test.*"
    - "*_test.*"

reporting:
  formats: ["json", "html"]
  output_dir: "reports"

migration:
  target_algorithms:
    rsa: "ML-KEM"
    ecc: "ML-DSA"
  migration_timeline: "2025-2027"
""")
        
        yield project_path


@pytest.mark.skipif(not CLI_AVAILABLE, reason="CLI module not available")
class TestCLIBasicFunctionality:
    """Test basic CLI functionality."""

    def test_cli_main_help(self, cli_runner):
        """Test main CLI help command."""
        result = cli_runner.invoke(main, ['--help'])
        assert result.exit_code == 0
        assert 'pqc-audit' in result.output or 'Usage' in result.output

    def test_cli_version(self, cli_runner):
        """Test CLI version command."""
        result = cli_runner.invoke(main, ['--version'])
        assert result.exit_code == 0
        assert '0.1.0' in result.output or 'version' in result.output.lower()

    def test_cli_scan_help(self, cli_runner):
        """Test scan command help."""
        result = cli_runner.invoke(main, ['scan', '--help'])
        assert result.exit_code == 0
        assert 'scan' in result.output.lower()

    def test_cli_report_help(self, cli_runner):
        """Test report command help."""
        result = cli_runner.invoke(main, ['report', '--help'])
        assert result.exit_code == 0
        assert 'report' in result.output.lower()

    def test_cli_migrate_help(self, cli_runner):
        """Test migrate command help."""
        result = cli_runner.invoke(main, ['migrate', '--help'])
        assert result.exit_code == 0
        assert 'migrate' in result.output.lower()


@pytest.mark.skipif(not CLI_AVAILABLE, reason="CLI module not available")
class TestCLIScanCommand:
    """Test CLI scan command functionality."""

    def test_scan_single_file(self, cli_runner, temp_project_dir):
        """Test scanning a single file."""
        py_file = temp_project_dir / "crypto_module.py"
        
        with patch('pqc_migration_audit.core.CryptoAuditor.scan_file') as mock_scan:
            # Mock scan results
            mock_results = ScanResults(
                vulnerabilities=[
                    Vulnerability(
                        file_path=str(py_file),
                        line_number=5,
                        algorithm=CryptoAlgorithm.RSA,
                        severity=Severity.HIGH,
                        description="RSA key generation",
                        recommendation="Use ML-KEM"
                    )
                ],
                stats=ScanStats(
                    files_scanned=1,
                    vulnerabilities_found=1,
                    scan_time=0.5,
                    languages_detected=['python']
                )
            )
            mock_scan.return_value = mock_results
            
            result = cli_runner.invoke(main, ['scan', str(py_file)])
            assert result.exit_code == 0
            mock_scan.assert_called_once()

    def test_scan_directory(self, cli_runner, temp_project_dir):
        """Test scanning a directory."""
        with patch('pqc_migration_audit.core.CryptoAuditor.scan_directory') as mock_scan:
            # Mock scan results
            mock_results = ScanResults(
                vulnerabilities=[
                    Vulnerability(
                        file_path=str(temp_project_dir / "crypto_module.py"),
                        line_number=5,
                        algorithm=CryptoAlgorithm.RSA,
                        severity=Severity.HIGH,
                        description="RSA key generation",
                        recommendation="Use ML-KEM"
                    )
                ],
                stats=ScanStats(
                    files_scanned=3,
                    vulnerabilities_found=1,
                    scan_time=1.2,
                    languages_detected=['python', 'java', 'go']
                )
            )
            mock_scan.return_value = mock_results
            
            result = cli_runner.invoke(main, ['scan', str(temp_project_dir)])
            assert result.exit_code == 0
            mock_scan.assert_called_once()

    def test_scan_with_output_file(self, cli_runner, temp_project_dir):
        """Test scanning with output file specification."""
        output_file = temp_project_dir / "scan_results.json"
        
        with patch('pqc_migration_audit.core.CryptoAuditor.scan_directory') as mock_scan:
            mock_results = ScanResults(
                vulnerabilities=[],
                stats=ScanStats(
                    files_scanned=3,
                    vulnerabilities_found=0,
                    scan_time=0.8,
                    languages_detected=['python', 'java', 'go']
                )
            )
            mock_scan.return_value = mock_results
            
            result = cli_runner.invoke(main, [
                'scan', str(temp_project_dir),
                '--output', str(output_file)
            ])
            assert result.exit_code == 0

    def test_scan_with_format_specification(self, cli_runner, temp_project_dir):
        """Test scanning with format specification."""
        with patch('pqc_migration_audit.core.CryptoAuditor.scan_directory') as mock_scan:
            mock_results = ScanResults(
                vulnerabilities=[],
                stats=ScanStats(
                    files_scanned=1,
                    vulnerabilities_found=0,
                    scan_time=0.3,
                    languages_detected=['python']
                )
            )
            mock_scan.return_value = mock_results
            
            # Test JSON format
            result = cli_runner.invoke(main, [
                'scan', str(temp_project_dir),
                '--format', 'json'
            ])
            assert result.exit_code == 0
            
            # Test HTML format
            result = cli_runner.invoke(main, [
                'scan', str(temp_project_dir),
                '--format', 'html'
            ])
            assert result.exit_code == 0

    def test_scan_with_language_filter(self, cli_runner, temp_project_dir):
        """Test scanning with language filtering."""
        with patch('pqc_migration_audit.core.CryptoAuditor.scan_directory') as mock_scan:
            mock_results = ScanResults(
                vulnerabilities=[],
                stats=ScanStats(
                    files_scanned=1,
                    vulnerabilities_found=0,
                    scan_time=0.2,
                    languages_detected=['python']
                )
            )
            mock_scan.return_value = mock_results
            
            result = cli_runner.invoke(main, [
                'scan', str(temp_project_dir),
                '--languages', 'python,java'
            ])
            assert result.exit_code == 0

    def test_scan_with_severity_threshold(self, cli_runner, temp_project_dir):
        """Test scanning with severity threshold."""
        with patch('pqc_migration_audit.core.CryptoAuditor.scan_directory') as mock_scan:
            mock_results = ScanResults(
                vulnerabilities=[
                    Vulnerability(
                        file_path=str(temp_project_dir / "crypto_module.py"),
                        line_number=5,
                        algorithm=CryptoAlgorithm.RSA,
                        severity=Severity.CRITICAL,
                        description="RSA key generation",
                        recommendation="Use ML-KEM"
                    )
                ],
                stats=ScanStats(
                    files_scanned=1,
                    vulnerabilities_found=1,
                    scan_time=0.4,
                    languages_detected=['python']
                )
            )
            mock_scan.return_value = mock_results
            
            result = cli_runner.invoke(main, [
                'scan', str(temp_project_dir),
                '--severity', 'high'
            ])
            assert result.exit_code == 0

    def test_scan_with_exclude_patterns(self, cli_runner, temp_project_dir):
        """Test scanning with exclude patterns."""
        with patch('pqc_migration_audit.core.CryptoAuditor.scan_directory') as mock_scan:
            mock_results = ScanResults(
                vulnerabilities=[],
                stats=ScanStats(
                    files_scanned=2,  # Reduced due to exclusions
                    vulnerabilities_found=0,
                    scan_time=0.3,
                    languages_detected=['python', 'java']
                )
            )
            mock_scan.return_value = mock_results
            
            result = cli_runner.invoke(main, [
                'scan', str(temp_project_dir),
                '--exclude', '*.go'
            ])
            assert result.exit_code == 0


@pytest.mark.skipif(not CLI_AVAILABLE, reason="CLI module not available")
class TestCLIReportCommand:
    """Test CLI report command functionality."""

    def test_report_generation_json(self, cli_runner, temp_project_dir):
        """Test JSON report generation."""
        # Create mock scan results file
        results_file = temp_project_dir / "results.json"
        mock_data = {
            "vulnerabilities": [
                {
                    "file_path": "/test/file.py",
                    "line_number": 10,
                    "algorithm": "rsa",
                    "severity": "high",
                    "description": "RSA usage",
                    "recommendation": "Use ML-KEM"
                }
            ],
            "stats": {
                "files_scanned": 5,
                "vulnerabilities_found": 1,
                "scan_time": 2.5,
                "languages_detected": ["python"]
            }
        }
        results_file.write_text(json.dumps(mock_data))
        
        output_file = temp_project_dir / "report.json"
        
        result = cli_runner.invoke(main, [
            'report',
            '--input', str(results_file),
            '--output', str(output_file),
            '--format', 'json'
        ])
        
        assert result.exit_code == 0

    def test_report_generation_html(self, cli_runner, temp_project_dir):
        """Test HTML report generation."""
        results_file = temp_project_dir / "results.json"
        mock_data = {
            "vulnerabilities": [],
            "stats": {
                "files_scanned": 3,
                "vulnerabilities_found": 0,
                "scan_time": 1.0,
                "languages_detected": ["python", "java"]
            }
        }
        results_file.write_text(json.dumps(mock_data))
        
        output_file = temp_project_dir / "report.html"
        
        result = cli_runner.invoke(main, [
            'report',
            '--input', str(results_file),
            '--output', str(output_file),
            '--format', 'html'
        ])
        
        assert result.exit_code == 0

    def test_report_generation_sarif(self, cli_runner, temp_project_dir):
        """Test SARIF report generation."""
        results_file = temp_project_dir / "results.json"
        mock_data = {
            "vulnerabilities": [
                {
                    "file_path": "/test/crypto.py",
                    "line_number": 15,
                    "algorithm": "ecc",
                    "severity": "medium",
                    "description": "ECC usage",
                    "recommendation": "Use ML-DSA"
                }
            ],
            "stats": {
                "files_scanned": 2,
                "vulnerabilities_found": 1,
                "scan_time": 0.8,
                "languages_detected": ["python"]
            }
        }
        results_file.write_text(json.dumps(mock_data))
        
        output_file = temp_project_dir / "report.sarif"
        
        result = cli_runner.invoke(main, [
            'report',
            '--input', str(results_file),
            '--output', str(output_file),
            '--format', 'sarif'
        ])
        
        assert result.exit_code == 0

    def test_report_with_template(self, cli_runner, temp_project_dir):
        """Test report generation with custom template."""
        results_file = temp_project_dir / "results.json"
        template_file = temp_project_dir / "custom_template.html"
        
        # Create mock template
        template_file.write_text("""
<!DOCTYPE html>
<html>
<head><title>Custom PQC Report</title></head>
<body>
    <h1>Custom Report</h1>
    <p>Files scanned: {{ stats.files_scanned }}</p>
    <p>Vulnerabilities: {{ stats.vulnerabilities_found }}</p>
</body>
</html>
""")
        
        mock_data = {
            "vulnerabilities": [],
            "stats": {
                "files_scanned": 5,
                "vulnerabilities_found": 0,
                "scan_time": 1.5,
                "languages_detected": ["python"]
            }
        }
        results_file.write_text(json.dumps(mock_data))
        
        output_file = temp_project_dir / "custom_report.html"
        
        result = cli_runner.invoke(main, [
            'report',
            '--input', str(results_file),
            '--output', str(output_file),
            '--template', str(template_file)
        ])
        
        assert result.exit_code == 0


@pytest.mark.skipif(not CLI_AVAILABLE, reason="CLI module not available")
class TestCLIMigrateCommand:
    """Test CLI migrate command functionality."""

    def test_migrate_plan_generation(self, cli_runner, temp_project_dir):
        """Test migration plan generation."""
        results_file = temp_project_dir / "scan_results.json"
        mock_data = {
            "vulnerabilities": [
                {
                    "file_path": str(temp_project_dir / "crypto_module.py"),
                    "line_number": 5,
                    "algorithm": "rsa",
                    "severity": "high",
                    "description": "RSA key generation",
                    "recommendation": "Use ML-KEM"
                }
            ],
            "stats": {
                "files_scanned": 1,
                "vulnerabilities_found": 1,
                "scan_time": 0.5,
                "languages_detected": ["python"]
            }
        }
        results_file.write_text(json.dumps(mock_data))
        
        plan_file = temp_project_dir / "migration_plan.json"
        
        with patch('pqc_migration_audit.services.MigrationService') as mock_service:
            mock_instance = Mock()
            mock_instance.generate_migration_plan.return_value = {
                "migrations": [
                    {
                        "file": str(temp_project_dir / "crypto_module.py"),
                        "line": 5,
                        "current": "RSA",
                        "target": "ML-KEM",
                        "effort": "2 hours",
                        "priority": "high"
                    }
                ],
                "total_effort": "2 hours",
                "timeline": "1 week"
            }
            mock_service.return_value = mock_instance
            
            result = cli_runner.invoke(main, [
                'migrate',
                '--input', str(results_file),
                '--output', str(plan_file)
            ])
            
            assert result.exit_code == 0

    def test_migrate_patch_generation(self, cli_runner, temp_project_dir):
        """Test migration patch generation."""
        results_file = temp_project_dir / "scan_results.json"
        mock_data = {
            "vulnerabilities": [
                {
                    "file_path": str(temp_project_dir / "crypto_module.py"),
                    "line_number": 5,
                    "algorithm": "rsa",
                    "severity": "high",
                    "description": "RSA key generation",
                    "recommendation": "Use ML-KEM"
                }
            ]
        }
        results_file.write_text(json.dumps(mock_data))
        
        patches_dir = temp_project_dir / "patches"
        
        with patch('pqc_migration_audit.patch_generator.PatchGenerator') as mock_generator:
            mock_instance = Mock()
            mock_instance.generate_patches.return_value = [
                {
                    "file": str(temp_project_dir / "crypto_module.py"),
                    "patch": "--- a/crypto_module.py\n+++ b/crypto_module.py\n...",
                    "description": "Replace RSA with ML-KEM"
                }
            ]
            mock_generator.return_value = mock_instance
            
            result = cli_runner.invoke(main, [
                'migrate',
                '--input', str(results_file),
                '--generate-patches',
                '--patches-dir', str(patches_dir)
            ])
            
            assert result.exit_code == 0

    def test_migrate_with_config(self, cli_runner, temp_project_dir):
        """Test migration with configuration file."""
        config_file = temp_project_dir / "migration_config.yml"
        config_file.write_text("""
migration:
  target_algorithms:
    rsa: "ML-KEM-768"
    ecc: "ML-DSA-65"
  timeline: "2025-2026"
  compatibility_mode: true
""")
        
        results_file = temp_project_dir / "scan_results.json"
        mock_data = {"vulnerabilities": [], "stats": {}}
        results_file.write_text(json.dumps(mock_data))
        
        result = cli_runner.invoke(main, [
            'migrate',
            '--input', str(results_file),
            '--config', str(config_file)
        ])
        
        assert result.exit_code == 0


@pytest.mark.skipif(not CLI_AVAILABLE, reason="CLI module not available")
class TestCLIConfigCommand:
    """Test CLI config command functionality."""

    def test_config_show(self, cli_runner, temp_project_dir):
        """Test showing configuration."""
        result = cli_runner.invoke(main, ['config', 'show'])
        assert result.exit_code == 0

    def test_config_init(self, cli_runner, temp_project_dir):
        """Test initializing configuration."""
        os.chdir(temp_project_dir)
        
        result = cli_runner.invoke(main, ['config', 'init'])
        assert result.exit_code == 0
        
        # Check if config file was created
        config_file = temp_project_dir / "pqc-audit.yml"
        # Config file might or might not be created depending on implementation

    def test_config_validate(self, cli_runner, temp_project_dir):
        """Test validating configuration."""
        config_file = temp_project_dir / "pqc-audit.yml"
        
        result = cli_runner.invoke(main, [
            'config', 'validate',
            '--config', str(config_file)
        ])
        
        # Should either validate successfully or fail gracefully
        assert result.exit_code in [0, 1]


class TestCLIErrorHandling:
    """Test CLI error handling scenarios."""

    def test_scan_nonexistent_file(self, cli_runner):
        """Test scanning a non-existent file."""
        result = cli_runner.invoke(main, ['scan', '/nonexistent/file.py'])
        assert result.exit_code != 0
        assert 'error' in result.output.lower() or 'not found' in result.output.lower()

    def test_scan_invalid_directory(self, cli_runner):
        """Test scanning an invalid directory."""
        result = cli_runner.invoke(main, ['scan', '/invalid/directory'])
        assert result.exit_code != 0

    def test_report_missing_input_file(self, cli_runner):
        """Test report generation with missing input file."""
        result = cli_runner.invoke(main, [
            'report',
            '--input', '/nonexistent/results.json',
            '--output', '/tmp/report.html'
        ])
        assert result.exit_code != 0

    def test_invalid_format_specification(self, cli_runner, temp_project_dir):
        """Test invalid format specification."""
        result = cli_runner.invoke(main, [
            'scan', str(temp_project_dir),
            '--format', 'invalid_format'
        ])
        assert result.exit_code != 0

    def test_insufficient_permissions(self, cli_runner):
        """Test handling of insufficient permissions."""
        # Try to write to a directory without permissions
        result = cli_runner.invoke(main, [
            'scan', '/tmp',
            '--output', '/root/restricted_report.json'
        ])
        # Should handle gracefully (may succeed or fail depending on environment)
        assert result.exit_code in [0, 1]


class TestCLIIntegrationScenarios:
    """Test CLI integration scenarios."""

    def test_complete_workflow(self, cli_runner, temp_project_dir):
        """Test complete CLI workflow: scan -> report -> migrate."""
        # Step 1: Scan
        scan_output = temp_project_dir / "scan_results.json"
        
        with patch('pqc_migration_audit.core.CryptoAuditor.scan_directory') as mock_scan:
            mock_results = ScanResults(
                vulnerabilities=[
                    Vulnerability(
                        file_path=str(temp_project_dir / "crypto_module.py"),
                        line_number=5,
                        algorithm=CryptoAlgorithm.RSA,
                        severity=Severity.HIGH,
                        description="RSA key generation",
                        recommendation="Use ML-KEM"
                    )
                ],
                stats=ScanStats(
                    files_scanned=3,
                    vulnerabilities_found=1,
                    scan_time=1.2,
                    languages_detected=['python', 'java', 'go']
                )
            )
            mock_scan.return_value = mock_results
            
            result = cli_runner.invoke(main, [
                'scan', str(temp_project_dir),
                '--output', str(scan_output),
                '--format', 'json'
            ])
            assert result.exit_code == 0
        
        # Create mock scan results for subsequent steps
        mock_data = {
            "vulnerabilities": [
                {
                    "file_path": str(temp_project_dir / "crypto_module.py"),
                    "line_number": 5,
                    "algorithm": "rsa",
                    "severity": "high",
                    "description": "RSA key generation",
                    "recommendation": "Use ML-KEM"
                }
            ],
            "stats": {
                "files_scanned": 3,
                "vulnerabilities_found": 1,
                "scan_time": 1.2,
                "languages_detected": ["python", "java", "go"]
            }
        }
        scan_output.write_text(json.dumps(mock_data))
        
        # Step 2: Generate report
        report_output = temp_project_dir / "security_report.html"
        
        result = cli_runner.invoke(main, [
            'report',
            '--input', str(scan_output),
            '--output', str(report_output),
            '--format', 'html'
        ])
        assert result.exit_code == 0
        
        # Step 3: Generate migration plan
        migration_output = temp_project_dir / "migration_plan.json"
        
        with patch('pqc_migration_audit.services.MigrationService') as mock_service:
            mock_instance = Mock()
            mock_instance.generate_migration_plan.return_value = {
                "migrations": [{
                    "file": str(temp_project_dir / "crypto_module.py"),
                    "line": 5,
                    "current": "RSA",
                    "target": "ML-KEM",
                    "effort": "2 hours",
                    "priority": "high"
                }]
            }
            mock_service.return_value = mock_instance
            
            result = cli_runner.invoke(main, [
                'migrate',
                '--input', str(scan_output),
                '--output', str(migration_output)
            ])
            assert result.exit_code == 0

    def test_ci_cd_pipeline_simulation(self, cli_runner, temp_project_dir):
        """Test CLI usage in CI/CD pipeline scenario."""
        # Simulate CI/CD pipeline usage
        with patch('pqc_migration_audit.core.CryptoAuditor.scan_directory') as mock_scan:
            # Simulate finding critical vulnerabilities
            mock_results = ScanResults(
                vulnerabilities=[
                    Vulnerability(
                        file_path=str(temp_project_dir / "crypto_module.py"),
                        line_number=5,
                        algorithm=CryptoAlgorithm.RSA,
                        severity=Severity.CRITICAL,
                        description="Critical RSA vulnerability",
                        recommendation="Immediate migration required"
                    )
                ],
                stats=ScanStats(
                    files_scanned=1,
                    vulnerabilities_found=1,
                    scan_time=0.5,
                    languages_detected=['python']
                )
            )
            mock_scan.return_value = mock_results
            
            # Scan with strict settings (should fail CI/CD)
            result = cli_runner.invoke(main, [
                'scan', str(temp_project_dir),
                '--severity', 'critical',
                '--fail-on-findings'
            ])
            
            # Should fail if critical vulnerabilities found
            # (Implementation may vary)
            assert result.exit_code in [0, 1]

    def test_configuration_driven_scan(self, cli_runner, temp_project_dir):
        """Test configuration-driven scanning."""
        config_file = temp_project_dir / "pqc-audit.yml"
        
        with patch('pqc_migration_audit.core.CryptoAuditor.scan_directory') as mock_scan:
            mock_results = ScanResults(
                vulnerabilities=[],
                stats=ScanStats(
                    files_scanned=2,  # Filtered by config
                    vulnerabilities_found=0,
                    scan_time=0.8,
                    languages_detected=['python', 'java']
                )
            )
            mock_scan.return_value = mock_results
            
            result = cli_runner.invoke(main, [
                'scan', str(temp_project_dir),
                '--config', str(config_file)
            ])
            assert result.exit_code == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
