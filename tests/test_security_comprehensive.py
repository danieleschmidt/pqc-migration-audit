"""Comprehensive security tests for PQC Migration Audit."""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch, mock_open

from src.pqc_migration_audit.security import (
    AdvancedSecurityScanner, SecurityThreat, SecurityScanResults,
    SecureFileHandler, CryptoSecurityAnalyzer
)
from src.pqc_migration_audit.types import ScanResults, Vulnerability, Severity, CryptoAlgorithm
from src.pqc_migration_audit.exceptions import (
    SecurityException, PathTraversalException, ValidationException,
    FileSystemException
)


class TestAdvancedSecurityScanner:
    """Test advanced security scanning functionality."""
    
    def test_scanner_initialization(self):
        """Test security scanner initialization."""
        scanner = AdvancedSecurityScanner()
        
        assert scanner.malicious_patterns is not None
        assert 'code_injection' in scanner.malicious_patterns
        assert 'path_traversal' in scanner.malicious_patterns
        assert scanner.entropy_threshold == 7.5
    
    def test_malicious_pattern_detection(self):
        """Test detection of malicious code patterns."""
        scanner = AdvancedSecurityScanner()
        
        # Test code injection patterns
        test_content = """
import subprocess
result = subprocess.call('rm -rf /')
eval('malicious_code')
exec('dangerous_operation')
os.system('harmful_command')
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(test_content)
            temp_path = Path(f.name)
        
        try:
            threats = scanner.scan_file_security(temp_path)
            
            # Should detect multiple threats
            assert len(threats) > 0
            
            # Check for code injection threats
            code_injection_threats = [t for t in threats if t.threat_type == 'code_injection']
            assert len(code_injection_threats) > 0
            
            # Verify threat properties
            for threat in code_injection_threats:
                assert threat.severity in ['critical', 'high', 'medium']
                assert threat.file_path == str(temp_path)
                assert threat.line_number > 0
                assert threat.description is not None
                assert threat.mitigation is not None
        
        finally:
            temp_path.unlink()
    
    def test_path_traversal_detection(self):
        """Test path traversal vulnerability detection."""
        scanner = AdvancedSecurityScanner()
        
        test_content = """
file_path = '../../../etc/passwd'
with open('../../sensitive_file.txt') as f:
    data = f.read()
url = 'http://example.com/path?file=..%2F..%2Fetc%2Fpasswd'
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(test_content)
            temp_path = Path(f.name)
        
        try:
            threats = scanner.scan_file_security(temp_path)
            
            # Should detect path traversal threats
            traversal_threats = [t for t in threats if t.threat_type == 'path_traversal']
            assert len(traversal_threats) > 0
            
            for threat in traversal_threats:
                assert '..' in threat.pattern_matched
                assert threat.severity == 'high'
        
        finally:
            temp_path.unlink()
    
    def test_hardcoded_secrets_detection(self):
        """Test hardcoded secrets detection."""
        scanner = AdvancedSecurityScanner()
        
        test_content = """
password = "super_secret_password123"
api_key = "ak_1234567890abcdef1234567890abcdef"
aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
private_key = "-----BEGIN RSA PRIVATE KEY-----"
token = "ghp_1234567890abcdef1234567890abcdef123456"
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(test_content)
            temp_path = Path(f.name)
        
        try:
            threats = scanner.scan_file_security(temp_path)
            
            # Should detect hardcoded secrets
            secret_threats = [t for t in threats if t.threat_type == 'hardcoded_secrets']
            assert len(secret_threats) > 0
            
            for threat in secret_threats:
                assert threat.severity == 'high'
                assert any(keyword in threat.description.lower() 
                          for keyword in ['password', 'key', 'secret', 'token'])
        
        finally:
            temp_path.unlink()
    
    def test_crypto_weakness_detection(self):
        """Test cryptographic weakness detection."""
        scanner = AdvancedSecurityScanner()
        
        test_content = """
import hashlib
import random
import math

# Weak hash functions
md5_hash = hashlib.md5()
sha1_hash = hashlib.sha1()

# Weak random number generation
weak_random = random.randint(1, 100)
js_random = Math.random()

# Weak key sizes
key_size = 512
rsa_key = generate_key(key_size=1024)
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(test_content)
            temp_path = Path(f.name)
        
        try:
            threats = scanner.scan_file_security(temp_path)
            
            # Should detect crypto weaknesses
            crypto_threats = [t for t in threats if t.threat_type == 'crypto_weaknesses']
            assert len(crypto_threats) > 0
            
            for threat in crypto_threats:
                assert threat.severity in ['medium', 'high']
        
        finally:
            temp_path.unlink()
    
    def test_file_permissions_check(self):
        """Test file permission security checks."""
        scanner = AdvancedSecurityScanner()
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = Path(f.name)
        
        try:
            # Make file world-writable
            os.chmod(temp_path, 0o666)
            
            threats = scanner._check_file_permissions(temp_path)
            
            # Should detect world-writable file
            perm_threats = [t for t in threats if t.threat_type == 'permissions']
            assert len(perm_threats) > 0
            
            world_writable = [t for t in perm_threats if 'world-writable' in t.description]
            assert len(world_writable) > 0
        
        finally:
            temp_path.unlink()
    
    def test_file_signature_detection(self):
        """Test file signature vs extension detection."""
        scanner = AdvancedSecurityScanner()
        
        # Create file with PE signature but .txt extension
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b'\x4D\x5A')  # PE signature
            f.write(b'\x00' * 100)  # Padding
            temp_path = Path(f.name)
        
        try:
            threats = scanner._check_file_signature(temp_path)
            
            # Should detect file masquerading
            masq_threats = [t for t in threats if t.threat_type == 'file_masquerading']
            assert len(masq_threats) > 0
            
            for threat in masq_threats:
                assert 'PE executable' in threat.description
                assert threat.severity == 'high'
        
        finally:
            temp_path.unlink()
    
    def test_entropy_calculation(self):
        """Test entropy calculation for packed content detection."""
        scanner = AdvancedSecurityScanner()
        
        # High entropy data (random-like)
        high_entropy_data = os.urandom(1000)
        entropy = scanner._calculate_shannon_entropy(high_entropy_data)
        assert entropy > scanner.entropy_threshold
        
        # Low entropy data (repetitive)
        low_entropy_data = b'A' * 1000
        entropy = scanner._calculate_shannon_entropy(low_entropy_data)
        assert entropy < scanner.entropy_threshold
    
    def test_directory_scanning(self):
        """Test comprehensive directory scanning."""
        scanner = AdvancedSecurityScanner()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create test files with different threats
            (temp_path / 'malicious.py').write_text('eval("dangerous_code")')
            (temp_path / 'secrets.py').write_text('password = "secret123"')
            (temp_path / 'normal.py').write_text('print("hello world")')
            
            results = scanner.scan_directory_security(temp_path)
            
            assert isinstance(results, SecurityScanResults)
            assert results.files_scanned == 3
            assert len(results.threats) > 0
            assert results.overall_risk_score > 0
            
            # Check threat summary
            assert len(results.threat_summary) > 0
    
    def test_confidence_scoring(self):
        """Test threat confidence scoring."""
        scanner = AdvancedSecurityScanner()
        
        # Test different contexts
        high_confidence = scanner._calculate_confidence(
            'code_injection', 
            'eval(user_input)', 
            'eval'
        )
        
        low_confidence = scanner._calculate_confidence(
            'code_injection',
            '# This is just a comment about eval()',
            'eval'
        )
        
        assert high_confidence > low_confidence
        assert 0.1 <= high_confidence <= 1.0
        assert 0.1 <= low_confidence <= 1.0


class TestSecureFileHandler:
    """Test secure file handling functionality."""
    
    def test_path_validation(self):
        """Test path validation security."""
        handler = SecureFileHandler()
        
        # Valid paths should pass
        handler.validate_path('/home/user/file.txt')
        handler.validate_path('relative/path/file.txt')
        
        # Path traversal should fail
        with pytest.raises(PathTraversalException):
            handler.validate_path('../../../etc/passwd')
        
        with pytest.raises(PathTraversalException):
            handler.validate_path('/home/user/../../etc/shadow')
    
    def test_secure_write(self):
        """Test secure file writing."""
        handler = SecureFileHandler()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / 'secure_file.txt'
            content = 'This is secure content'
            
            handler.secure_write(file_path, content, mode=0o600)
            
            # File should exist and be readable
            assert file_path.exists()
            assert file_path.read_text() == content
            
            # Check permissions (on Unix systems)
            if os.name == 'posix':
                stat = file_path.stat()
                assert stat.st_mode & 0o777 == 0o600
    
    def test_secure_read(self):
        """Test secure file reading."""
        handler = SecureFileHandler()
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            test_content = 'Test file content'
            f.write(test_content)
            file_path = Path(f.name)
        
        try:
            content = handler.secure_read(file_path)
            assert content == test_content
        finally:
            file_path.unlink()
    
    def test_secure_read_size_limit(self):
        """Test secure read with size limits."""
        handler = SecureFileHandler()
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            # Write large content
            large_content = 'A' * (2 * 1024 * 1024)  # 2MB
            f.write(large_content)
            file_path = Path(f.name)
        
        try:
            # Should fail with size limit
            with pytest.raises(ValidationException):
                handler.secure_read(file_path, max_size=1024*1024)  # 1MB limit
        finally:
            file_path.unlink()
    
    def test_checksum_calculation(self):
        """Test secure checksum calculation."""
        handler = SecureFileHandler()
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            content = 'Test content for checksum'
            f.write(content)
            file_path = Path(f.name)
        
        try:
            checksum = handler.calculate_checksum(file_path)
            assert len(checksum) == 64  # SHA-256 hex digest
            assert all(c in '0123456789abcdef' for c in checksum)
            
            # Same content should produce same checksum
            checksum2 = handler.calculate_checksum(file_path)
            assert checksum == checksum2
        finally:
            file_path.unlink()


class TestCryptoSecurityAnalyzer:
    """Test cryptographic security analysis."""
    
    def test_quantum_readiness_assessment(self):
        """Test quantum readiness assessment."""
        analyzer = CryptoSecurityAnalyzer()
        
        # Create mock scan results with various vulnerabilities
        vulnerabilities = [
            Vulnerability(
                file_path='test1.py',
                line_number=10,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.CRITICAL,
                description='RSA vulnerability'
            ),
            Vulnerability(
                file_path='test2.py',
                line_number=20,
                algorithm=CryptoAlgorithm.ECC,
                severity=Severity.HIGH,
                description='ECC vulnerability'
            ),
            Vulnerability(
                file_path='test3.py',
                line_number=30,
                algorithm=CryptoAlgorithm.DSA,
                severity=Severity.MEDIUM,
                description='DSA vulnerability'
            )
        ]
        
        scan_results = ScanResults(
            scan_path='/test/path',
            vulnerabilities=vulnerabilities
        )
        
        assessment = analyzer.assess_quantum_readiness(scan_results)
        
        assert 'overall_readiness' in assessment
        assert 'readiness_score' in assessment
        assert 'critical_vulnerabilities' in assessment
        assert 'high_vulnerabilities' in assessment
        assert 'estimated_migration_time' in assessment
        assert 'recommendations' in assessment
        assert 'algorithm_breakdown' in assessment
        
        # Check algorithm breakdown
        assert 'RSA' in assessment['algorithm_breakdown']
        assert 'ECC' in assessment['algorithm_breakdown']
        assert 'DSA' in assessment['algorithm_breakdown']
        
        # Should have critical vulnerabilities
        assert assessment['critical_vulnerabilities'] == 1
        assert assessment['high_vulnerabilities'] == 1
        
        # Should not be quantum ready with these vulnerabilities
        assert assessment['overall_readiness'] != 'Quantum Ready'
        assert assessment['readiness_score'] < 90
    
    def test_migration_time_estimation(self):
        """Test migration time estimation."""
        analyzer = CryptoSecurityAnalyzer()
        
        # Test with different severity levels
        vulnerabilities = [
            # Critical vulnerabilities take more time
            *[Vulnerability(
                file_path='critical.py',
                line_number=i,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.CRITICAL,
                description='Critical RSA'
            ) for i in range(2)],
            
            # High severity
            *[Vulnerability(
                file_path='high.py',
                line_number=i,
                algorithm=CryptoAlgorithm.ECC,
                severity=Severity.HIGH,
                description='High ECC'
            ) for i in range(3)],
            
            # Medium severity
            *[Vulnerability(
                file_path='medium.py',
                line_number=i,
                algorithm=CryptoAlgorithm.DSA,
                severity=Severity.MEDIUM,
                description='Medium DSA'
            ) for i in range(5)]
        ]
        
        scan_results = ScanResults(
            scan_path='/test/path',
            vulnerabilities=vulnerabilities
        )
        
        estimated_time = analyzer._estimate_migration_time(scan_results)
        
        # Should be reasonable time estimate
        assert estimated_time > 0
        assert estimated_time < 100  # Less than 100 weeks
        
        # More severe vulnerabilities should take longer
        critical_only = ScanResults(
            scan_path='/test/path',
            vulnerabilities=vulnerabilities[:2]  # Only critical
        )
        
        medium_only = ScanResults(
            scan_path='/test/path',
            vulnerabilities=vulnerabilities[-5:]  # Only medium
        )
        
        critical_time = analyzer._estimate_migration_time(critical_only)
        medium_time = analyzer._estimate_migration_time(medium_only)
        
        # Critical should take longer per vulnerability
        assert critical_time > medium_time
    
    def test_quantum_recommendations(self):
        """Test quantum security recommendations generation."""
        analyzer = CryptoSecurityAnalyzer()
        
        # Test high-risk scenario
        high_risk_assessment = {
            'readiness_score': 30,
            'algorithm_breakdown': {
                'RSA': {'count': 10, 'risk_info': {'quantum_vulnerable': True}},
                'ECC': {'count': 5, 'risk_info': {'quantum_vulnerable': True}}
            }
        }
        
        recommendations = analyzer._generate_quantum_recommendations(high_risk_assessment)
        
        assert len(recommendations) > 0
        assert any('URGENT' in rec for rec in recommendations)
        assert any('ML-KEM' in rec for rec in recommendations)
        assert any('ML-DSA' in rec for rec in recommendations)
        
        # Test low-risk scenario
        low_risk_assessment = {
            'readiness_score': 95,
            'algorithm_breakdown': {}
        }
        
        low_risk_recommendations = analyzer._generate_quantum_recommendations(low_risk_assessment)
        
        assert any('quantum-ready' in rec.lower() for rec in low_risk_recommendations)
        assert not any('URGENT' in rec for rec in low_risk_recommendations)


class TestSecurityIntegration:
    """Integration tests for security components."""
    
    def test_comprehensive_security_scan(self):
        """Test comprehensive security scanning workflow."""
        scanner = AdvancedSecurityScanner()
        analyzer = CryptoSecurityAnalyzer()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create files with various security issues
            (temp_path / 'crypto_weak.py').write_text("""
import hashlib
password = "hardcoded_secret_123"
md5_hash = hashlib.md5()
key = rsa.generate_private_key(key_size=1024)
""")
            
            (temp_path / 'injection.py').write_text("""
import subprocess
user_input = request.get('input')
subprocess.call(user_input)
eval(dangerous_code)
""")
            
            (temp_path / 'clean.py').write_text("""
import hashlib
secure_hash = hashlib.sha256()
print("This is a clean file")
""")
            
            # Run security scan
            security_results = scanner.scan_directory_security(temp_path)
            
            assert security_results.files_scanned == 3
            assert len(security_results.threats) > 0
            assert security_results.overall_risk_score > 0
            
            # Convert to scan results format for quantum analysis
            vulnerabilities = []
            for threat in security_results.threats:
                if 'crypto' in threat.threat_type or 'weak' in threat.description.lower():
                    vuln = Vulnerability(
                        file_path=threat.file_path,
                        line_number=threat.line_number,
                        algorithm=CryptoAlgorithm.RSA,  # Simplified for test
                        severity=Severity.HIGH if threat.severity == 'high' else Severity.MEDIUM,
                        description=threat.description
                    )
                    vulnerabilities.append(vuln)
            
            scan_results = ScanResults(
                scan_path=str(temp_path),
                vulnerabilities=vulnerabilities
            )
            
            # Run quantum analysis
            quantum_assessment = analyzer.assess_quantum_readiness(scan_results)
            
            assert 'overall_readiness' in quantum_assessment
            assert len(quantum_assessment['recommendations']) > 0
    
    def test_secure_file_operations_integration(self):
        """Test secure file operations in scanning workflow."""
        handler = SecureFileHandler()
        scanner = AdvancedSecurityScanner()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create test content
            test_content = """
# Test file with potential issues
password = "secret123"
eval("dangerous_code")
import subprocess
subprocess.call("rm -rf /")
"""
            
            # Write file securely
            test_file = temp_path / 'test_security.py'
            handler.secure_write(test_file, test_content, mode=0o600)
            
            # Verify file was written securely
            assert test_file.exists()
            if os.name == 'posix':
                stat = test_file.stat()
                assert stat.st_mode & 0o777 == 0o600
            
            # Calculate checksum
            original_checksum = handler.calculate_checksum(test_file)
            
            # Scan for security threats
            threats = scanner.scan_file_security(test_file)
            
            assert len(threats) > 0
            
            # Verify file integrity after scan
            post_scan_checksum = handler.calculate_checksum(test_file)
            assert original_checksum == post_scan_checksum
            
            # Test secure reading
            read_content = handler.secure_read(test_file)
            assert read_content == test_content


@pytest.mark.slow
class TestSecurityPerformance:
    """Performance tests for security scanning."""
    
    def test_large_file_security_scan(self):
        """Test security scanning performance on large files."""
        scanner = AdvancedSecurityScanner()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            # Create large file with mixed content
            for i in range(1000):
                f.write(f'# Line {i}\n')
                f.write(f'normal_variable_{i} = "value"\n')
                
                # Inject some threats occasionally
                if i % 100 == 0:
                    f.write('eval("potential_threat")\n')
                if i % 150 == 0:
                    f.write('password = "hardcoded_secret"\n')
            
            large_file = Path(f.name)
        
        try:
            import time
            start_time = time.time()
            
            threats = scanner.scan_file_security(large_file)
            
            scan_time = time.time() - start_time
            
            # Should complete in reasonable time (less than 5 seconds for this test)
            assert scan_time < 5.0
            
            # Should find threats
            assert len(threats) > 0
            
            # Should find multiple threat types
            threat_types = set(t.threat_type for t in threats)
            assert len(threat_types) > 1
            
        finally:
            large_file.unlink()
    
    def test_concurrent_security_scanning(self):
        """Test concurrent security scanning doesn't cause race conditions."""
        import threading
        import time
        
        scanner = AdvancedSecurityScanner()
        results = []
        errors = []
        
        def scan_worker(worker_id):
            try:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                    f.write(f"""
# Worker {worker_id} test file
password_{worker_id} = "secret_{worker_id}"
eval("code_{worker_id}")
subprocess.call("command_{worker_id}")
""")
                    temp_file = Path(f.name)
                
                threats = scanner.scan_file_security(temp_file)
                results.append((worker_id, len(threats)))
                
                temp_file.unlink()
                
            except Exception as e:
                errors.append((worker_id, str(e)))
        
        # Start multiple scanning threads
        threads = []
        for i in range(10):
            thread = threading.Thread(target=scan_worker, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=10)
        
        # Check results
        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert len(results) == 10
        
        # All workers should find similar number of threats
        threat_counts = [count for _, count in results]
        assert all(count > 0 for count in threat_counts)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])