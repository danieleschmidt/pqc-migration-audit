"""Security-focused tests for the PQC Migration Audit tool."""

import pytest
import tempfile
import os
import subprocess
from pathlib import Path
from unittest.mock import patch, mock_open

from pqc_migration_audit.core import CryptoAuditor
from pqc_migration_audit.scanners import PythonScanner


class TestSecurityValidation:
    """Security validation tests for the audit tool itself."""

    @pytest.mark.security
    def test_path_traversal_protection(self, temp_repo):
        """Test protection against path traversal attacks."""
        auditor = CryptoAuditor()
        
        # Attempt path traversal attacks
        malicious_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/shadow",
            "C:\\Windows\\System32\\config\\SAM",
            "~/../../etc/passwd",
            "file:///etc/passwd",
        ]
        
        for malicious_path in malicious_paths:
            # Should handle gracefully without accessing unauthorized files
            try:
                results = auditor.scan_directory(malicious_path)
                # If it doesn't raise an exception, verify it didn't access the file
                assert results.scan_stats.files_processed == 0
            except (ValueError, FileNotFoundError, PermissionError) as e:
                # These exceptions are acceptable
                pass

    @pytest.mark.security
    def test_symlink_attack_protection(self, temp_repo):
        """Test protection against symlink attacks."""
        if os.name == 'nt':  # Skip on Windows
            pytest.skip("Symlink test not applicable on Windows")
        
        # Create a symlink pointing to sensitive file
        sensitive_file = "/etc/passwd"
        if Path(sensitive_file).exists():
            symlink_path = temp_repo / "malicious_link"
            try:
                os.symlink(sensitive_file, symlink_path)
                
                auditor = CryptoAuditor()
                results = auditor.scan_directory(temp_repo)
                
                # Should not follow symlink to sensitive file
                scanned_files = [str(f) for f in results.scan_stats.files_scanned]
                assert sensitive_file not in scanned_files
                
            except (OSError, PermissionError):
                # May not have permissions to create symlinks
                pytest.skip("Cannot create symlinks in test environment")

    @pytest.mark.security
    def test_large_file_dos_protection(self, temp_repo):
        """Test protection against DoS via extremely large files."""
        auditor = CryptoAuditor()
        
        # Create a very large file (but not so large it fills disk)
        large_file = temp_repo / "large_file.py"
        
        # Write 50MB of data
        chunk_size = 1024 * 1024  # 1MB chunks
        with open(large_file, 'w') as f:
            for i in range(50):  # 50MB total
                f.write("# " + "x" * (chunk_size - 2) + "\n")
        
        # Should handle large file gracefully
        results = auditor.scan_directory(temp_repo, max_file_size=10*1024*1024)  # 10MB limit
        
        # Large file should be skipped, not crash the scanner
        assert results.scan_stats.files_skipped >= 1

    @pytest.mark.security
    def test_memory_exhaustion_protection(self, temp_repo):
        """Test protection against memory exhaustion attacks."""
        auditor = CryptoAuditor()
        
        # Create many files to test memory usage
        for i in range(1000):
            file_path = temp_repo / f"file_{i}.py"
            file_path.write_text(f"# File {i}\n" + "x" * 1000)  # 1KB per file
        
        # Should handle many files without excessive memory usage
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        memory_before = process.memory_info().rss
        
        results = auditor.scan_directory(temp_repo)
        
        memory_after = process.memory_info().rss
        memory_increase = memory_after - memory_before
        
        # Memory increase should be reasonable (less than 500MB)
        assert memory_increase < 500 * 1024 * 1024
        assert results.scan_stats.files_processed == 1000

    @pytest.mark.security
    def test_code_injection_protection(self):
        """Test protection against code injection in scanned files."""
        scanner = PythonScanner()
        
        # Malicious code that shouldn't be executed
        malicious_code = '''
import os
os.system("rm -rf /")  # This should never execute
exec("__import__('os').system('touch /tmp/pwned')")
eval("1+1")  # Even benign eval should not execute
'''
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(malicious_code)
            f.flush()
            
            # Scanner should parse but not execute the code
            findings = scanner.scan_file(Path(f.name))
            
            # Verify malicious code was not executed
            assert not Path("/tmp/pwned").exists()
            
            # Should still detect patterns in the code
            assert isinstance(findings, list)
            
        # Clean up
        os.unlink(f.name)

    @pytest.mark.security
    def test_output_sanitization(self, temp_repo):
        """Test that output doesn't contain sensitive information."""
        # Create file with potentially sensitive content
        sensitive_file = temp_repo / "sensitive.py"
        sensitive_file.write_text('''
# This file contains sensitive information
API_KEY = "sk_live_abcdef123456789"
PASSWORD = "super_secret_password"
TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxx"

from cryptography.hazmat.primitives.asymmetric import rsa
def crypto_func():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)
''')
        
        auditor = CryptoAuditor()
        results = auditor.scan_directory(temp_repo)
        
        # Convert results to JSON to simulate output
        import json
        json_output = json.dumps(results.to_dict(), indent=2)
        
        # Verify sensitive data is not in output
        sensitive_strings = ["sk_live_", "super_secret_password", "ghp_"]
        for sensitive in sensitive_strings:
            assert sensitive not in json_output
        
        # But should still contain vulnerability information
        assert "RSA" in json_output
        assert "2048" in json_output

    @pytest.mark.security
    def test_privilege_escalation_protection(self, temp_repo):
        """Test that scanner doesn't escalate privileges."""
        auditor = CryptoAuditor()
        
        # Get current user ID
        import os
        current_uid = os.getuid() if hasattr(os, 'getuid') else None
        
        if current_uid is not None:
            # Scan should not change process privileges
            results = auditor.scan_directory(temp_repo)
            
            # Verify UID hasn't changed
            assert os.getuid() == current_uid

    @pytest.mark.security
    def test_temporary_file_security(self, temp_repo):
        """Test secure handling of temporary files."""
        auditor = CryptoAuditor()
        
        # Create files that might trigger temp file creation
        test_file = temp_repo / "test.py"
        test_file.write_text("from cryptography.hazmat.primitives.asymmetric import rsa")
        
        # Monitor temp directory before scan
        import tempfile
        temp_dir = Path(tempfile.gettempdir())
        temp_files_before = set(temp_dir.glob("*"))
        
        # Perform scan
        results = auditor.scan_directory(temp_repo)
        
        # Check temp directory after scan
        temp_files_after = set(temp_dir.glob("*"))
        new_temp_files = temp_files_after - temp_files_before
        
        # Should not leave temporary files behind
        pqc_temp_files = [f for f in new_temp_files if "pqc" in f.name.lower()]
        assert len(pqc_temp_files) == 0

    @pytest.mark.security
    def test_configuration_injection_protection(self, temp_repo):
        """Test protection against configuration injection attacks."""
        # Malicious configuration
        malicious_config = {
            "scanners": {
                "python": {
                    "command": "rm -rf /",  # Should not be executed
                    "patterns": ["__import__('os').system('rm -rf /')"]
                }
            },
            "output_file": "../../../etc/passwd",  # Path traversal attempt
            "custom_patterns": {
                "evil": {
                    "pattern": ".*",
                    "action": "exec('__import__(\"os\").system(\"touch /tmp/evil\")')"
                }
            }
        }
        
        auditor = CryptoAuditor(config=malicious_config)
        
        # Should handle malicious config safely
        try:
            results = auditor.scan_directory(temp_repo)
            # Verify malicious actions didn't execute
            assert not Path("/tmp/evil").exists()
        except (ValueError, SecurityError) as e:
            # Acceptable to reject malicious config
            pass

    @pytest.mark.security
    def test_regex_dos_protection(self):
        """Test protection against ReDoS (Regular Expression DoS) attacks."""
        scanner = PythonScanner()
        
        # Input designed to cause catastrophic backtracking
        redos_input = "a" * 10000 + "X"
        
        malicious_file_content = f'''
# File with content designed for ReDoS
some_variable = "{redos_input}"
from cryptography.hazmat.primitives.asymmetric import rsa
'''
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(malicious_file_content)
            f.flush()
            
            # Should complete in reasonable time
            import time
            start_time = time.time()
            
            findings = scanner.scan_file(Path(f.name))
            
            scan_time = time.time() - start_time
            
            # Should not take excessive time (> 5 seconds indicates ReDoS)
            assert scan_time < 5.0
            assert isinstance(findings, list)
            
        os.unlink(f.name)

    @pytest.mark.security
    def test_network_isolation(self, temp_repo):
        """Test that scanner doesn't make unauthorized network requests."""
        # Mock network to detect any outbound requests
        with patch('urllib.request.urlopen') as mock_urlopen, \
             patch('requests.get') as mock_requests_get, \
             patch('socket.socket') as mock_socket:
            
            auditor = CryptoAuditor()
            
            # Create file that might trigger network requests
            network_file = temp_repo / "network_test.py"
            network_file.write_text('''
import urllib.request
import requests
from cryptography.hazmat.primitives.asymmetric import rsa

def download_key():
    # This shouldn't actually execute during scanning
    urllib.request.urlopen("http://evil.com/key")
    requests.get("https://malicious.com/api")
''')
            
            results = auditor.scan_directory(temp_repo)
            
            # Verify no network calls were made
            mock_urlopen.assert_not_called()
            mock_requests_get.assert_not_called()
            mock_socket.assert_not_called()

    @pytest.mark.security
    def test_input_validation_fuzzing(self):
        """Test input validation with fuzzing-like inputs."""
        scanner = PythonScanner()
        
        # Various malformed/fuzzing inputs
        fuzzing_inputs = [
            b"\x00\x01\x02\x03",  # Binary data
            "å∫ç∂´ƒ©˙ˆ∆˚¬",      # Unicode characters
            "\x00" * 1000,        # Null bytes
            "\n" * 10000,         # Many newlines
            "\t" * 5000,          # Many tabs
            "'" * 1000,           # Many quotes
            '"' * 1000,           # Many double quotes
            "(" * 500 + ")" * 500, # Balanced parens
            "def " * 1000,        # Repeated keywords
            "\\" * 1000,          # Backslashes
        ]
        
        for fuzzing_input in fuzzing_inputs:
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.py', delete=False) as f:
                if isinstance(fuzzing_input, str):
                    f.write(fuzzing_input.encode('utf-8', errors='ignore'))
                else:
                    f.write(fuzzing_input)
                f.flush()
                
                # Should handle gracefully without crashing
                try:
                    findings = scanner.scan_file(Path(f.name))
                    assert isinstance(findings, list)
                except (UnicodeDecodeError, SyntaxError, ValueError) as e:
                    # These exceptions are acceptable for malformed input
                    pass
                
                os.unlink(f.name)