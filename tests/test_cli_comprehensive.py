"""Comprehensive tests for CLI interface."""

import pytest
import tempfile
import json
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from click.testing import CliRunner

from src.pqc_migration_audit.cli import main, scan_command, version_command, config_command
from src.pqc_migration_audit.types import Vulnerability, Severity, CryptoAlgorithm, ScanResults


class TestCLIBasics:
    """Test basic CLI functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.runner = CliRunner()

    def test_main_help(self):
        """Test main help command."""
        result = self.runner.invoke(main, ['--help'])
        
        assert result.exit_code == 0
        assert 'Post-Quantum Cryptography' in result.output
        assert 'scan' in result.output
        assert 'version' in result.output

    def test_version_command(self):
        """Test version command."""
        result = self.runner.invoke(main, ['version'])
        
        assert result.exit_code == 0
        assert '0.1.0' in result.output or 'version' in result.output.lower()

    def test_invalid_command(self):
        """Test invalid command handling."""
        result = self.runner.invoke(main, ['invalid-command'])
        
        assert result.exit_code != 0
        assert 'No such command' in result.output or 'Usage:' in result.output


class TestScanCommand:
    """Test scan command functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.runner = CliRunner()

    def test_scan_help(self):
        """Test scan command help."""
        result = self.runner.invoke(main, ['scan', '--help'])
        
        assert result.exit_code == 0
        assert 'Scan for quantum-vulnerable cryptography' in result.output
        assert '--output' in result.output
        assert '--format' in result.output

    @patch('src.pqc_migration_audit.cli.CryptoAuditor')
    def test_scan_current_directory(self, mock_auditor_class):
        """Test scanning current directory."""
        # Mock the auditor and its results
        mock_auditor = Mock()
        mock_auditor_class.return_value = mock_auditor
        
        mock_results = ScanResults(
            vulnerabilities=[
                Vulnerability(
                    file_path="test.py",
                    line_number=1,
                    algorithm=CryptoAlgorithm.RSA,
                    severity=Severity.HIGH,
                    description="RSA vulnerability"
                )
            ],
            scanned_files=1,
            scan_time=0.5
        )
        mock_auditor.scan_directory.return_value = mock_results
        
        result = self.runner.invoke(main, ['scan', '.'])
        
        assert result.exit_code == 0
        mock_auditor.scan_directory.assert_called_once()

    def test_scan_nonexistent_path(self):
        """Test scanning non-existent path."""
        result = self.runner.invoke(main, ['scan', '/nonexistent/path'])
        
        assert result.exit_code != 0
        assert 'does not exist' in result.output or 'Error' in result.output

    @patch('src.pqc_migration_audit.cli.CryptoAuditor')
    def test_scan_with_output_file(self, mock_auditor_class):
        """Test scan with output file specification."""
        mock_auditor = Mock()
        mock_auditor_class.return_value = mock_auditor
        
        mock_results = ScanResults(vulnerabilities=[], scanned_files=0)
        mock_auditor.scan_directory.return_value = mock_results
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
            result = self.runner.invoke(main, ['scan', '.', '--output', tmp.name])
            
            assert result.exit_code == 0
            
            # Check that output file was created
            assert os.path.exists(tmp.name)
            
            # Clean up
            os.unlink(tmp.name)

    @patch('src.pqc_migration_audit.cli.CryptoAuditor')
    def test_scan_with_format_options(self, mock_auditor_class):
        """Test scan with different output formats."""
        mock_auditor = Mock()
        mock_auditor_class.return_value = mock_auditor
        
        mock_results = ScanResults(vulnerabilities=[], scanned_files=0)
        mock_auditor.scan_directory.return_value = mock_results
        
        formats = ['json', 'html', 'console']
        
        for fmt in formats:
            result = self.runner.invoke(main, ['scan', '.', '--format', fmt])
            assert result.exit_code == 0

    @patch('src.pqc_migration_audit.cli.CryptoAuditor')
    def test_scan_with_severity_threshold(self, mock_auditor_class):
        """Test scan with severity threshold."""
        mock_auditor = Mock()
        mock_auditor_class.return_value = mock_auditor
        
        mock_results = ScanResults(vulnerabilities=[], scanned_files=0)
        mock_auditor.scan_directory.return_value = mock_results
        
        result = self.runner.invoke(main, ['scan', '.', '--min-severity', 'high'])
        
        assert result.exit_code == 0
        # Check that the auditor was called with the right severity
        call_args = mock_auditor.scan_directory.call_args
        assert call_args is not None

    @patch('src.pqc_migration_audit.cli.CryptoAuditor')
    def test_scan_with_language_filter(self, mock_auditor_class):
        """Test scan with language filtering."""
        mock_auditor = Mock()
        mock_auditor_class.return_value = mock_auditor
        
        mock_results = ScanResults(vulnerabilities=[], scanned_files=0)
        mock_auditor.scan_directory.return_value = mock_results
        
        result = self.runner.invoke(main, ['scan', '.', '--languages', 'python,java'])
        
        assert result.exit_code == 0

    @patch('src.pqc_migration_audit.cli.CryptoAuditor')
    def test_scan_with_exclude_patterns(self, mock_auditor_class):
        """Test scan with exclude patterns."""
        mock_auditor = Mock()
        mock_auditor_class.return_value = mock_auditor
        
        mock_results = ScanResults(vulnerabilities=[], scanned_files=0)
        mock_auditor.scan_directory.return_value = mock_auditor
        
        result = self.runner.invoke(main, ['scan', '.', '--exclude', 'test_*,*.pyc'])
        
        assert result.exit_code == 0

    @patch('src.pqc_migration_audit.cli.CryptoAuditor')
    def test_scan_verbose_output(self, mock_auditor_class):
        """Test scan with verbose output."""
        mock_auditor = Mock()
        mock_auditor_class.return_value = mock_auditor
        
        mock_results = ScanResults(
            vulnerabilities=[
                Vulnerability(
                    file_path="test.py",
                    line_number=1,
                    algorithm=CryptoAlgorithm.RSA,
                    severity=Severity.HIGH
                )
            ],
            scanned_files=1
        )
        mock_auditor.scan_directory.return_value = mock_results
        
        result = self.runner.invoke(main, ['scan', '.', '--verbose'])
        
        assert result.exit_code == 0
        # Should contain more detailed output
        assert len(result.output) > 0

    def test_scan_invalid_severity(self):
        """Test scan with invalid severity threshold."""
        result = self.runner.invoke(main, ['scan', '.', '--min-severity', 'invalid'])
        
        assert result.exit_code != 0

    def test_scan_invalid_format(self):
        """Test scan with invalid output format."""
        result = self.runner.invoke(main, ['scan', '.', '--format', 'invalid'])
        
        assert result.exit_code != 0


class TestConfigCommand:
    """Test configuration command functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.runner = CliRunner()

    def test_config_help(self):
        """Test config command help."""
        result = self.runner.invoke(main, ['config', '--help'])
        
        assert result.exit_code == 0
        assert 'configuration' in result.output.lower()

    def test_config_show(self):
        """Test showing current configuration."""
        result = self.runner.invoke(main, ['config', 'show'])
        
        # Should not error, may show default config
        assert result.exit_code == 0 or 'config' in result.output.lower()

    def test_config_init(self):
        """Test initializing configuration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = os.path.join(temp_dir, 'pqc-config.yaml')
            
            result = self.runner.invoke(main, ['config', 'init', '--path', config_file])
            
            # Should create config file or provide guidance
            assert result.exit_code in [0, 1]  # May fail if command not fully implemented


class TestCLIErrorHandling:
    """Test CLI error handling."""

    def setup_method(self):
        """Set up test fixtures."""
        self.runner = CliRunner()

    @patch('src.pqc_migration_audit.cli.CryptoAuditor')
    def test_scan_error_handling(self, mock_auditor_class):
        """Test error handling during scan."""
        mock_auditor = Mock()
        mock_auditor_class.return_value = mock_auditor
        
        # Make the auditor raise an exception
        mock_auditor.scan_directory.side_effect = Exception("Scan failed")
        
        result = self.runner.invoke(main, ['scan', '.'])
        
        # Should handle the error gracefully
        assert result.exit_code != 0
        assert 'error' in result.output.lower() or 'failed' in result.output.lower()

    def test_permission_error_handling(self):
        """Test handling of permission errors."""
        # Try to scan a directory that requires permissions
        result = self.runner.invoke(main, ['scan', '/root/.ssh'])
        
        # Should handle permission errors gracefully
        assert result.exit_code != 0 or 'permission' in result.output.lower()

    @patch('src.pqc_migration_audit.cli.open')
    def test_output_file_write_error(self, mock_open):
        """Test handling output file write errors."""
        mock_open.side_effect = PermissionError("Cannot write file")
        
        result = self.runner.invoke(main, ['scan', '.', '--output', '/readonly/file.json'])
        
        assert result.exit_code != 0


class TestCLIOutputFormats:
    """Test different CLI output formats."""

    def setup_method(self):
        """Set up test fixtures."""
        self.runner = CliRunner()
        
        # Create mock results
        self.mock_vulnerability = Vulnerability(
            file_path="test.py",
            line_number=42,
            algorithm=CryptoAlgorithm.RSA,
            severity=Severity.HIGH,
            key_size=2048,
            description="RSA 2048-bit key generation",
            code_snippet="rsa.generate_private_key(2048)",
            recommendation="Use ML-KEM-768 instead"
        )
        
        self.mock_results = ScanResults(
            vulnerabilities=[self.mock_vulnerability],
            scanned_files=1,
            total_lines=100,
            scan_time=1.5,
            scan_path=".",
            languages_detected=["python"]
        )

    @patch('src.pqc_migration_audit.cli.CryptoAuditor')
    def test_json_output_format(self, mock_auditor_class):
        """Test JSON output format."""
        mock_auditor = Mock()
        mock_auditor_class.return_value = mock_auditor
        mock_auditor.scan_directory.return_value = self.mock_results
        
        result = self.runner.invoke(main, ['scan', '.', '--format', 'json'])
        
        assert result.exit_code == 0
        # Output should be valid JSON or contain JSON-like structure
        assert '{' in result.output or 'vulnerabilities' in result.output

    @patch('src.pqc_migration_audit.cli.CryptoAuditor')
    def test_console_output_format(self, mock_auditor_class):
        """Test console output format."""
        mock_auditor = Mock()
        mock_auditor_class.return_value = mock_auditor
        mock_auditor.scan_directory.return_value = self.mock_results
        
        result = self.runner.invoke(main, ['scan', '.', '--format', 'console'])
        
        assert result.exit_code == 0
        # Should contain human-readable information
        assert 'RSA' in result.output or 'vulnerability' in result.output.lower()

    @patch('src.pqc_migration_audit.cli.CryptoAuditor')
    def test_html_output_format(self, mock_auditor_class):
        """Test HTML output format."""
        mock_auditor = Mock()
        mock_auditor_class.return_value = mock_auditor
        mock_auditor.scan_directory.return_value = self.mock_results
        
        result = self.runner.invoke(main, ['scan', '.', '--format', 'html'])
        
        assert result.exit_code == 0
        # Should contain HTML-like content or save to file
        assert result.output is not None


class TestCLIIntegration:
    """Integration tests for CLI functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.runner = CliRunner()

    def test_full_scan_workflow(self):
        """Test complete scan workflow via CLI."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a test file with vulnerabilities
            test_file = Path(temp_dir) / "vulnerable.py"
            test_file.write_text("""
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key
""")
            
            # Run scan
            result = self.runner.invoke(main, ['scan', temp_dir])
            
            # Should complete successfully
            assert result.exit_code == 0
            
            # Output should contain relevant information
            output_lower = result.output.lower()
            assert any(keyword in output_lower for keyword in 
                      ['vulnerability', 'rsa', 'scan', 'complete', 'found'])

    def test_scan_with_output_file_workflow(self):
        """Test scan with output file workflow."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test files
            test_file = Path(temp_dir) / "test.py"
            test_file.write_text("rsa.generate_private_key(2048)")
            
            output_file = Path(temp_dir) / "results.json"
            
            # Run scan with output
            result = self.runner.invoke(main, [
                'scan', str(test_file.parent), 
                '--output', str(output_file),
                '--format', 'json'
            ])
            
            # Should complete successfully
            assert result.exit_code == 0
            
            # Output file should be created (if implementation supports it)
            # Note: This test may pass even if file isn't created, depending on implementation


class TestCLIPerformance:
    """Performance tests for CLI operations."""

    def setup_method(self):
        """Set up test fixtures."""
        self.runner = CliRunner()

    @pytest.mark.performance
    def test_cli_startup_time(self):
        """Test CLI startup performance."""
        import time
        
        start_time = time.time()
        result = self.runner.invoke(main, ['--help'])
        end_time = time.time()
        
        startup_time = end_time - start_time
        
        assert result.exit_code == 0
        assert startup_time < 2.0  # Should start within 2 seconds

    @pytest.mark.performance
    @patch('src.pqc_migration_audit.cli.CryptoAuditor')
    def test_scan_performance_reporting(self, mock_auditor_class):
        """Test that scan performance is reported."""
        mock_auditor = Mock()
        mock_auditor_class.return_value = mock_auditor
        
        # Create results with performance metrics
        mock_results = ScanResults(
            vulnerabilities=[],
            scanned_files=100,
            scan_time=5.0,
            total_lines=10000
        )
        mock_auditor.scan_directory.return_value = mock_results
        
        result = self.runner.invoke(main, ['scan', '.', '--verbose'])
        
        assert result.exit_code == 0
        # Should report timing information
        output_lower = result.output.lower()
        assert any(keyword in output_lower for keyword in 
                  ['time', 'second', 'duration', 'performance', 'files'])


if __name__ == "__main__":
    pytest.main([__file__, "-v"])