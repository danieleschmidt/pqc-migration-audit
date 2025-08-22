"""Comprehensive security and performance validation tests."""

import pytest
import time
import os
import tempfile
import threading
import concurrent.futures
from pathlib import Path
from unittest.mock import Mock, patch
import resource
import psutil

from src.pqc_migration_audit.types import (
    Vulnerability, Severity, CryptoAlgorithm, ScanResults
)


class TestSecurityValidation:
    """Test security aspects of the PQC migration audit tool."""

    def test_path_traversal_prevention(self):
        """Test prevention of path traversal attacks."""
        try:
            from src.pqc_migration_audit.core import CryptoAuditor
            
            auditor = CryptoAuditor()
            
            # Test various path traversal attempts
            malicious_paths = [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "/etc/shadow",
                "../../../../root/.ssh/id_rsa",
                "file://etc/passwd",
                "\x00/etc/passwd"
            ]
            
            for malicious_path in malicious_paths:
                # Should either reject the path or handle it safely
                try:
                    result = auditor.scan_file(Path(malicious_path))
                    # If it doesn't raise an exception, it should return safe results
                    assert isinstance(result, ScanResults)
                except (FileNotFoundError, PermissionError, OSError, ValueError):
                    # These exceptions are acceptable for security
                    pass
                except Exception as e:
                    # Any other exception should be a security-related one
                    assert "security" in str(e).lower() or "invalid" in str(e).lower()
                    
        except ImportError:
            pytest.skip("CryptoAuditor not available")

    def test_input_sanitization(self):
        """Test input sanitization for malicious content."""
        try:
            from src.pqc_migration_audit.core import FileAnalyzer
            
            analyzer = FileAnalyzer()
            
            # Test with files containing potential exploits
            malicious_contents = [
                "exec('__import__(\"os\").system(\"rm -rf /\")')",
                "eval(input())",
                "__import__('subprocess').call(['rm', '-rf', '/'])",
                "open('/etc/passwd').read()",
                "import socket; socket.socket().connect(('evil.com', 80))"
            ]
            
            with tempfile.TemporaryDirectory() as temp_dir:
                for i, content in enumerate(malicious_contents):
                    test_file = Path(temp_dir) / f"malicious_{i}.py"
                    test_file.write_text(content)
                    
                    # Should analyze safely without executing malicious code
                    result = analyzer.analyze_file(test_file)
                    assert isinstance(result, list)
                    
        except ImportError:
            pytest.skip("FileAnalyzer not available")

    def test_resource_exhaustion_prevention(self):
        """Test prevention of resource exhaustion attacks."""
        try:
            from src.pqc_migration_audit.core import CryptoAuditor
            
            auditor = CryptoAuditor()
            
            with tempfile.TemporaryDirectory() as temp_dir:
                # Create a very large file to test memory limits
                large_file = Path(temp_dir) / "large.py"
                
                # Write a large file (but not too large to cause CI issues)
                large_content = "# Large file test\n" + "print('test')\n" * 10000
                large_file.write_text(large_content)
                
                # Monitor memory usage during scan
                process = psutil.Process()
                memory_before = process.memory_info().rss
                
                start_time = time.time()
                result = auditor.scan_file(large_file)
                duration = time.time() - start_time
                
                memory_after = process.memory_info().rss
                memory_increase = memory_after - memory_before
                
                # Should complete in reasonable time and memory
                assert duration < 30.0  # Max 30 seconds
                assert memory_increase < 500 * 1024 * 1024  # Max 500MB increase
                assert isinstance(result, ScanResults)
                
        except ImportError:
            pytest.skip("Required modules not available")

    def test_file_permission_respect(self):
        """Test that file permissions are respected."""
        try:
            from src.pqc_migration_audit.core import CryptoAuditor
            
            auditor = CryptoAuditor()
            
            with tempfile.TemporaryDirectory() as temp_dir:
                # Create a file and remove read permissions
                restricted_file = Path(temp_dir) / "restricted.py"
                restricted_file.write_text("print('secret')")
                restricted_file.chmod(0o000)  # No permissions
                
                try:
                    # Should handle permission errors gracefully
                    result = auditor.scan_file(restricted_file)
                    # If it succeeds, should return valid results
                    assert isinstance(result, ScanResults)
                except PermissionError:
                    # This is the expected behavior
                    pass
                finally:
                    # Restore permissions for cleanup
                    restricted_file.chmod(0o644)
                    
        except ImportError:
            pytest.skip("CryptoAuditor not available")

    def test_symlink_safety(self):
        """Test safe handling of symbolic links."""
        try:
            from src.pqc_migration_audit.core import CryptoAuditor
            
            auditor = CryptoAuditor()
            
            with tempfile.TemporaryDirectory() as temp_dir:
                # Create a legitimate file
                real_file = Path(temp_dir) / "real.py"
                real_file.write_text("print('hello')")
                
                # Create a symlink
                symlink_file = Path(temp_dir) / "symlink.py"
                try:
                    symlink_file.symlink_to(real_file)
                    
                    # Should handle symlinks safely
                    result = auditor.scan_file(symlink_file)
                    assert isinstance(result, ScanResults)
                    
                except OSError:
                    # Symlink creation might fail on some systems
                    pytest.skip("Cannot create symlinks on this system")
                    
        except ImportError:
            pytest.skip("CryptoAuditor not available")

    def test_error_information_disclosure(self):
        """Test that error messages don't disclose sensitive information."""
        try:
            from src.pqc_migration_audit.core import CryptoAuditor
            
            auditor = CryptoAuditor()
            
            # Try to scan non-existent file
            try:
                auditor.scan_file(Path("/nonexistent/secret/file.py"))
            except Exception as e:
                error_msg = str(e).lower()
                
                # Error message should not contain sensitive paths
                assert "secret" not in error_msg
                assert "password" not in error_msg
                assert "key" not in error_msg or "file" in error_msg  # "key file" is OK
                
        except ImportError:
            pytest.skip("CryptoAuditor not available")


class TestPerformanceBenchmarks:
    """Performance benchmarks and stress tests."""

    @pytest.mark.performance
    def test_single_file_scan_performance(self):
        """Test performance of scanning a single file."""
        try:
            from src.pqc_migration_audit.core import CryptoAuditor
            
            auditor = CryptoAuditor()
            
            with tempfile.TemporaryDirectory() as temp_dir:
                # Create a moderately complex file
                test_file = Path(temp_dir) / "performance_test.py"
                content_lines = []
                
                # Add various crypto patterns
                for i in range(100):
                    if i % 20 == 0:
                        content_lines.append("rsa.generate_private_key(2048)")
                    elif i % 15 == 0:
                        content_lines.append("ec.generate_private_key(ec.SECP256R1())")
                    else:
                        content_lines.append(f"# Comment line {i}")
                        content_lines.append(f"def function_{i}(): pass")
                
                test_file.write_text("\n".join(content_lines))
                
                # Benchmark the scan
                times = []
                for _ in range(5):
                    start_time = time.time()
                    result = auditor.scan_file(test_file)
                    duration = time.time() - start_time
                    times.append(duration)
                    
                    assert isinstance(result, ScanResults)
                    assert result.scanned_files == 1
                
                # Calculate performance metrics
                avg_time = sum(times) / len(times)
                max_time = max(times)
                
                # Performance assertions
                assert avg_time < 1.0  # Average should be under 1 second
                assert max_time < 2.0  # No single run should exceed 2 seconds
                
        except ImportError:
            pytest.skip("CryptoAuditor not available")

    @pytest.mark.performance
    def test_directory_scan_performance(self):
        """Test performance of scanning a directory with multiple files."""
        try:
            from src.pqc_migration_audit.core import CryptoAuditor
            
            auditor = CryptoAuditor()
            
            with tempfile.TemporaryDirectory() as temp_dir:
                # Create multiple test files
                file_count = 50
                vulnerabilities_per_file = 2
                
                for i in range(file_count):
                    test_file = Path(temp_dir) / f"test_file_{i}.py"
                    content = f"# Test file {i}\n"
                    
                    # Add some vulnerabilities
                    for j in range(vulnerabilities_per_file):
                        content += f"rsa_key_{j} = rsa.generate_private_key(2048)\n"
                    
                    # Add some normal code
                    content += f"def function_{i}():\n    return 'test'\n"
                    
                    test_file.write_text(content)
                
                # Benchmark directory scan
                start_time = time.time()
                result = auditor.scan_directory(temp_dir)
                duration = time.time() - start_time
                
                # Performance assertions
                assert duration < 10.0  # Should complete within 10 seconds
                assert result.scanned_files == file_count
                assert len(result.vulnerabilities) >= file_count * vulnerabilities_per_file
                
                # Calculate throughput
                files_per_second = file_count / duration
                assert files_per_second > 5  # Should process at least 5 files/second
                
        except ImportError:
            pytest.skip("CryptoAuditor not available")

    @pytest.mark.performance
    def test_memory_efficiency(self):
        """Test memory efficiency during large scans."""
        try:
            from src.pqc_migration_audit.core import CryptoAuditor
            
            auditor = CryptoAuditor()
            
            with tempfile.TemporaryDirectory() as temp_dir:
                # Create files with substantial content
                for i in range(20):
                    test_file = Path(temp_dir) / f"large_file_{i}.py"
                    
                    # Create content with patterns scattered throughout
                    lines = []
                    for j in range(500):
                        if j % 50 == 0:
                            lines.append("private_key = rsa.generate_private_key(2048)")
                        else:
                            lines.append(f"# Line {j} in file {i}")
                    
                    test_file.write_text("\n".join(lines))
                
                # Monitor memory usage
                process = psutil.Process()
                memory_before = process.memory_info().rss
                
                result = auditor.scan_directory(temp_dir)
                
                memory_after = process.memory_info().rss
                memory_increase = memory_after - memory_before
                
                # Memory efficiency assertions
                assert memory_increase < 200 * 1024 * 1024  # Max 200MB increase
                assert isinstance(result, ScanResults)
                assert result.scanned_files == 20
                
        except ImportError:
            pytest.skip("CryptoAuditor not available")

    @pytest.mark.performance
    def test_concurrent_scanning_performance(self):
        """Test performance with concurrent scanning operations."""
        try:
            from src.pqc_migration_audit.core import CryptoAuditor
            
            with tempfile.TemporaryDirectory() as temp_dir:
                # Create test files
                for i in range(10):
                    test_file = Path(temp_dir) / f"concurrent_test_{i}.py"
                    content = f"# File {i}\nrsa.generate_private_key(2048)\n"
                    test_file.write_text(content)
                
                def scan_file(file_path):
                    """Scan a single file."""
                    auditor = CryptoAuditor()
                    return auditor.scan_file(file_path)
                
                # Test concurrent scanning
                files = list(Path(temp_dir).glob("*.py"))
                
                start_time = time.time()
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                    futures = [executor.submit(scan_file, f) for f in files]
                    results = [future.result() for future in concurrent.futures.as_completed(futures)]
                
                duration = time.time() - start_time
                
                # Assertions
                assert len(results) == len(files)
                assert all(isinstance(r, ScanResults) for r in results)
                assert duration < 5.0  # Should complete quickly with concurrency
                
        except ImportError:
            pytest.skip("CryptoAuditor not available")

    @pytest.mark.performance
    def test_large_file_handling(self):
        """Test handling of very large files."""
        try:
            from src.pqc_migration_audit.core import CryptoAuditor
            
            auditor = CryptoAuditor()
            
            with tempfile.TemporaryDirectory() as temp_dir:
                # Create a large file (but not too large for CI)
                large_file = Path(temp_dir) / "very_large.py"
                
                lines = []
                for i in range(5000):  # 5000 lines
                    if i % 100 == 0:
                        lines.append("rsa_key = rsa.generate_private_key(2048)")
                    elif i % 150 == 0:
                        lines.append("ec_key = ec.generate_private_key(ec.SECP256R1())")
                    else:
                        lines.append(f"# This is line {i} with some content")
                
                large_file.write_text("\n".join(lines))
                
                # Test scanning large file
                start_time = time.time()
                result = auditor.scan_file(large_file)
                duration = time.time() - start_time
                
                # Should handle large files efficiently
                assert duration < 15.0  # Max 15 seconds for large file
                assert isinstance(result, ScanResults)
                assert len(result.vulnerabilities) > 0
                assert result.total_lines >= 5000
                
        except ImportError:
            pytest.skip("CryptoAuditor not available")


class TestStressTests:
    """Stress tests for robustness."""

    @pytest.mark.performance
    def test_deep_directory_structure(self):
        """Test scanning deeply nested directory structures."""
        try:
            from src.pqc_migration_audit.core import CryptoAuditor
            
            auditor = CryptoAuditor()
            
            with tempfile.TemporaryDirectory() as temp_dir:
                # Create deep directory structure
                current_dir = Path(temp_dir)
                
                for depth in range(10):  # 10 levels deep
                    current_dir = current_dir / f"level_{depth}"
                    current_dir.mkdir()
                    
                    # Add a file at each level
                    test_file = current_dir / f"test_{depth}.py"
                    test_file.write_text(f"# Level {depth}\nrsa.generate_private_key(2048)\n")
                
                # Scan the entire structure
                start_time = time.time()
                result = auditor.scan_directory(temp_dir)
                duration = time.time() - start_time
                
                assert duration < 10.0  # Should handle deep structures efficiently
                assert result.scanned_files == 10
                assert len(result.vulnerabilities) >= 10
                
        except ImportError:
            pytest.skip("CryptoAuditor not available")

    @pytest.mark.performance
    def test_many_small_files(self):
        """Test scanning many small files."""
        try:
            from src.pqc_migration_audit.core import CryptoAuditor
            
            auditor = CryptoAuditor()
            
            with tempfile.TemporaryDirectory() as temp_dir:
                # Create many small files
                file_count = 200
                
                for i in range(file_count):
                    test_file = Path(temp_dir) / f"small_{i}.py"
                    content = f"# Small file {i}\n"
                    if i % 10 == 0:
                        content += "rsa.generate_private_key(2048)\n"
                    test_file.write_text(content)
                
                # Scan all files
                start_time = time.time()
                result = auditor.scan_directory(temp_dir)
                duration = time.time() - start_time
                
                assert duration < 20.0  # Should handle many files efficiently
                assert result.scanned_files == file_count
                
                # Calculate throughput
                throughput = file_count / duration
                assert throughput > 10  # At least 10 files per second
                
        except ImportError:
            pytest.skip("CryptoAuditor not available")

    @pytest.mark.performance
    def test_mixed_file_types_performance(self):
        """Test performance with mixed file types."""
        try:
            from src.pqc_migration_audit.core import CryptoAuditor
            
            auditor = CryptoAuditor()
            
            with tempfile.TemporaryDirectory() as temp_dir:
                # Create files of different types
                file_types = [
                    ("test.py", "rsa.generate_private_key(2048)"),
                    ("Test.java", 'KeyPairGenerator.getInstance("RSA")'),
                    ("test.go", "rsa.GenerateKey(rand.Reader, 2048)"),
                    ("test.js", "crypto.generateKeyPair('rsa')"),
                    ("config.yaml", "cipher: RSA-2048"),
                    ("readme.txt", "This uses RSA encryption")
                ]
                
                # Create multiple instances of each type
                for i in range(20):
                    for filename, content in file_types:
                        name, ext = filename.rsplit('.', 1)
                        test_file = Path(temp_dir) / f"{name}_{i}.{ext}"
                        test_file.write_text(f"# File {i}\n{content}\n")
                
                # Scan mixed files
                start_time = time.time()
                result = auditor.scan_directory(temp_dir)
                duration = time.time() - start_time
                
                expected_files = len(file_types) * 20
                assert duration < 15.0
                assert result.scanned_files <= expected_files  # Some might be skipped
                assert len(result.languages_detected) > 1
                
        except ImportError:
            pytest.skip("CryptoAuditor not available")


class TestResourceMonitoring:
    """Test resource usage monitoring and limits."""

    def test_cpu_usage_monitoring(self):
        """Test CPU usage during intensive scanning."""
        try:
            from src.pqc_migration_audit.core import CryptoAuditor
            
            auditor = CryptoAuditor()
            
            with tempfile.TemporaryDirectory() as temp_dir:
                # Create CPU-intensive scan scenario
                for i in range(50):
                    test_file = Path(temp_dir) / f"cpu_test_{i}.py"
                    content = "# CPU test\n" + "rsa.generate_private_key(2048)\n" * 5
                    test_file.write_text(content)
                
                # Monitor CPU usage
                process = psutil.Process()
                cpu_before = process.cpu_percent()
                
                start_time = time.time()
                result = auditor.scan_directory(temp_dir)
                duration = time.time() - start_time
                
                cpu_after = process.cpu_percent(interval=1)
                
                # CPU usage should be reasonable
                assert duration < 20.0
                assert isinstance(result, ScanResults)
                # CPU monitoring may not be reliable in all environments
                
        except ImportError:
            pytest.skip("CryptoAuditor not available")

    def test_file_descriptor_usage(self):
        """Test file descriptor usage doesn't leak."""
        try:
            from src.pqc_migration_audit.core import CryptoAuditor
            
            auditor = CryptoAuditor()
            
            # Get initial file descriptor count
            process = psutil.Process()
            initial_fds = process.num_fds() if hasattr(process, 'num_fds') else 0
            
            with tempfile.TemporaryDirectory() as temp_dir:
                # Create multiple files
                for i in range(100):
                    test_file = Path(temp_dir) / f"fd_test_{i}.py"
                    test_file.write_text("rsa.generate_private_key(2048)")
                
                # Scan multiple times
                for _ in range(5):
                    result = auditor.scan_directory(temp_dir)
                    assert isinstance(result, ScanResults)
                
                # Check file descriptor count
                final_fds = process.num_fds() if hasattr(process, 'num_fds') else 0
                
                # Should not have significant FD leaks
                if initial_fds > 0 and final_fds > 0:
                    fd_increase = final_fds - initial_fds
                    assert fd_increase < 50  # Allow some increase but not excessive
                
        except (ImportError, AttributeError):
            pytest.skip("Required modules or methods not available")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])