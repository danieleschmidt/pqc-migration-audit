"""Basic import and functionality tests to validate test infrastructure."""

import pytest
import re
from pathlib import Path


class TestBasicImports:
    """Test that core modules can be imported and basic functionality works."""

    def test_types_import(self):
        """Test that types module imports correctly."""
        from src.pqc_migration_audit.types import (
            Severity, CryptoAlgorithm, Vulnerability, ScanResults, ScanStats
        )
        
        # Test enum values
        assert Severity.HIGH.value == "high"
        assert CryptoAlgorithm.RSA.value == "rsa"
        
        # Test creating basic instances
        vuln = Vulnerability(
            file_path="test.py",
            line_number=1,
            algorithm=CryptoAlgorithm.RSA,
            severity=Severity.HIGH
        )
        assert vuln.file_path == "test.py"
        assert vuln.algorithm == CryptoAlgorithm.RSA

    def test_exceptions_import(self):
        """Test that exceptions module imports correctly."""
        from src.pqc_migration_audit.exceptions import (
            ScanException, ValidationException, FileSystemException
        )
        
        # Test that exceptions can be raised
        try:
            raise ScanException("Test error")
        except ScanException as e:
            assert str(e) == "Test error"

    def test_core_patterns_available(self):
        """Test that crypto patterns are available."""
        from src.pqc_migration_audit.core import CryptoPatterns
        
        # Test that patterns exist
        assert hasattr(CryptoPatterns, 'PYTHON_PATTERNS')
        assert 'rsa_generation' in CryptoPatterns.PYTHON_PATTERNS
        
        # Test pattern matching
        patterns = CryptoPatterns.PYTHON_PATTERNS['rsa_generation']
        test_code = "rsa.generate_private_key(2048)"
        
        found_match = any(re.search(pattern, test_code) for pattern in patterns)
        assert found_match

    def test_basic_file_analyzer(self):
        """Test basic file analyzer functionality."""
        try:
            from src.pqc_migration_audit.core import FileAnalyzer
            
            analyzer = FileAnalyzer()
            assert analyzer is not None
            
            # Test with simple content
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write("rsa.generate_private_key(2048)")
                f.flush()
                
                temp_path = Path(f.name)
                try:
                    results = analyzer.analyze_file(temp_path)
                    assert isinstance(results, list)
                finally:
                    temp_path.unlink()
                    
        except ImportError:
            pytest.skip("FileAnalyzer not available")

    def test_basic_crypto_auditor(self):
        """Test basic crypto auditor functionality."""
        try:
            from src.pqc_migration_audit.core import CryptoAuditor
            from src.pqc_migration_audit.types import ScanResults
            
            auditor = CryptoAuditor()
            assert auditor is not None
            
            # Test with empty directory
            import tempfile
            with tempfile.TemporaryDirectory() as temp_dir:
                results = auditor.scan_directory(Path(temp_dir))
                assert isinstance(results, ScanResults)
                assert results.scanned_files == 0
                
        except ImportError:
            pytest.skip("CryptoAuditor not available")

    def test_pattern_regex_compilation(self):
        """Test that all regex patterns compile correctly."""
        from src.pqc_migration_audit.core import CryptoPatterns
        
        # Test Python patterns
        for category, patterns in CryptoPatterns.PYTHON_PATTERNS.items():
            for pattern in patterns:
                try:
                    compiled = re.compile(pattern)
                    assert compiled is not None
                except re.error as e:
                    pytest.fail(f"Invalid regex in {category}: {pattern} - {e}")
        
        # Test Java patterns if available
        if hasattr(CryptoPatterns, 'JAVA_PATTERNS'):
            for category, patterns in CryptoPatterns.JAVA_PATTERNS.items():
                for pattern in patterns:
                    try:
                        compiled = re.compile(pattern)
                        assert compiled is not None
                    except re.error as e:
                        pytest.fail(f"Invalid Java regex in {category}: {pattern} - {e}")

    def test_vulnerability_creation_variations(self):
        """Test different ways of creating vulnerabilities."""
        from src.pqc_migration_audit.types import Vulnerability, Severity, CryptoAlgorithm
        
        # Minimal vulnerability
        vuln1 = Vulnerability(
            file_path="/test.py",
            line_number=1,
            algorithm=CryptoAlgorithm.RSA,
            severity=Severity.HIGH
        )
        assert vuln1.key_size is None
        assert vuln1.description == ""
        
        # Full vulnerability
        vuln2 = Vulnerability(
            file_path="/test.py",
            line_number=42,
            algorithm=CryptoAlgorithm.ECC,
            severity=Severity.MEDIUM,
            key_size=256,
            description="ECC vulnerability",
            code_snippet="ec.generate_private_key()",
            recommendation="Use ML-KEM",
            cwe_id="CWE-326"
        )
        assert vuln2.key_size == 256
        assert vuln2.description == "ECC vulnerability"
        assert vuln2.cwe_id == "CWE-326"

    def test_scan_results_basic_functionality(self):
        """Test basic scan results functionality."""
        from src.pqc_migration_audit.types import (
            ScanResults, Vulnerability, Severity, CryptoAlgorithm, ScanStats
        )
        
        # Create sample vulnerabilities
        vulns = [
            Vulnerability(
                file_path="test1.py",
                line_number=1,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.HIGH
            ),
            Vulnerability(
                file_path="test2.py",
                line_number=1,
                algorithm=CryptoAlgorithm.ECC,
                severity=Severity.MEDIUM
            )
        ]
        
        # Create scan results
        results = ScanResults(
            vulnerabilities=vulns,
            scanned_files=2,
            total_lines=100,
            scan_time=1.5,
            scan_path="/test",
            languages_detected=["python"]
        )
        
        assert len(results.vulnerabilities) == 2
        assert results.scanned_files == 2
        assert results.scan_time == 1.5
        assert "python" in results.languages_detected


if __name__ == "__main__":
    pytest.main([__file__, "-v"])