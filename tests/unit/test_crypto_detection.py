"""Unit tests for cryptographic vulnerability detection."""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch

from pqc_migration_audit.core import CryptoAuditor
from pqc_migration_audit.scanners import PythonScanner
from pqc_migration_audit.analyzers import RSAAnalyzer, ECCAnalyzer
from pqc_migration_audit.types import Severity


class TestCryptoDetection:
    """Test suite for cryptographic vulnerability detection."""

    @pytest.fixture
    def crypto_auditor(self):
        """Create a CryptoAuditor instance for testing."""
        return CryptoAuditor()

    @pytest.fixture
    def python_scanner(self):
        """Create a PythonScanner instance for testing."""
        return PythonScanner()

    @pytest.fixture
    def rsa_analyzer(self):
        """Create an RSAAnalyzer instance for testing."""
        return RSAAnalyzer()

    @pytest.fixture
    def ecc_analyzer(self):
        """Create an ECCAnalyzer instance for testing."""
        return ECCAnalyzer()

    @pytest.mark.unit
    def test_rsa_key_generation_detection(self, python_scanner, sample_vulnerable_code):
        """Test detection of RSA key generation patterns."""
        code = sample_vulnerable_code["rsa_key_gen.py"]
        
        # Create a temporary file
        with pytest.helpers.temp_python_file(code) as temp_file:
            findings = python_scanner.scan_file(temp_file)
            
            # Verify RSA pattern is detected
            assert len(findings) > 0
            rsa_findings = [f for f in findings if 'rsa' in f.pattern.lower()]
            assert len(rsa_findings) > 0
            
            # Verify key size is detected
            key_size_findings = [f for f in rsa_findings if '2048' in f.context]
            assert len(key_size_findings) > 0

    @pytest.mark.unit
    def test_ecdsa_signature_detection(self, python_scanner, sample_vulnerable_code):
        """Test detection of ECDSA signature patterns."""
        code = sample_vulnerable_code["ecdsa_signing.py"]
        
        with pytest.helpers.temp_python_file(code) as temp_file:
            findings = python_scanner.scan_file(temp_file)
            
            # Verify ECDSA pattern is detected
            assert len(findings) > 0
            ecc_findings = [f for f in findings if 'ec' in f.pattern.lower()]
            assert len(ecc_findings) > 0
            
            # Verify curve is detected
            curve_findings = [f for f in ecc_findings if 'SECP256R1' in f.context]
            assert len(curve_findings) > 0

    @pytest.mark.unit
    def test_pqc_secure_code_no_detection(self, python_scanner, sample_secure_code):
        """Test that PQC-secure code doesn't trigger false positives."""
        code = sample_secure_code["kyber_kem.py"]
        
        with pytest.helpers.temp_python_file(code) as temp_file:
            findings = python_scanner.scan_file(temp_file)
            
            # Should not detect quantum-vulnerable patterns
            vulnerable_findings = [
                f for f in findings 
                if any(pattern in f.pattern.lower() for pattern in ['rsa', 'ec', 'dsa'])
            ]
            assert len(vulnerable_findings) == 0

    @pytest.mark.unit
    @pytest.mark.parametrize("key_size,expected_severity", [
        (1024, Severity.CRITICAL),
        (2048, Severity.HIGH),
        (3072, Severity.MEDIUM),
        (4096, Severity.LOW),
    ])
    def test_rsa_key_size_risk_assessment(self, rsa_analyzer, key_size, expected_severity):
        """Test RSA key size risk assessment."""
        # Mock finding with different key sizes
        finding = Mock()
        finding.algorithm = "RSA"
        finding.key_size = key_size
        finding.context = f"key_size={key_size}"
        
        vulnerabilities = rsa_analyzer.analyze([finding])
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].severity == expected_severity

    @pytest.mark.unit
    @pytest.mark.parametrize("curve,expected_vulnerable", [
        ("SECP256R1", True),
        ("SECP384R1", True),
        ("SECP521R1", True),
        ("ED25519", False),  # Not quantum-vulnerable in same way
    ])
    def test_ecc_curve_vulnerability_assessment(self, ecc_analyzer, curve, expected_vulnerable):
        """Test ECC curve vulnerability assessment."""
        finding = Mock()
        finding.algorithm = "ECC"
        finding.curve = curve
        finding.context = f"curve={curve}"
        
        vulnerabilities = ecc_analyzer.analyze([finding])
        
        if expected_vulnerable:
            assert len(vulnerabilities) > 0
        else:
            assert len(vulnerabilities) == 0

    @pytest.mark.unit
    def test_multiple_language_support(self, crypto_auditor, temp_repo):
        """Test scanning repositories with multiple programming languages."""
        # Create sample files in different languages
        python_file = temp_repo / "crypto.py"
        java_file = temp_repo / "Crypto.java"
        go_file = temp_repo / "crypto.go"
        js_file = temp_repo / "crypto.js"
        
        python_file.write_text("""
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
""")
        
        java_file.write_text("""
import java.security.KeyPairGenerator;
KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
keyGen.initialize(2048);
""")
        
        go_file.write_text("""
package main
import "crypto/rsa"
func main() {
    rsa.GenerateKey(rand.Reader, 2048)
}
""")
        
        js_file.write_text("""
const crypto = require('crypto');
const { generateKeyPairSync } = crypto;
generateKeyPairSync('rsa', { modulusLength: 2048 });
""")
        
        # Scan the repository
        results = crypto_auditor.scan_directory(temp_repo)
        
        # Verify vulnerabilities found in all languages
        assert len(results.vulnerabilities) >= 4  # At least one per language
        
        # Verify language detection
        languages = {Path(v.file_path).suffix for v in results.vulnerabilities}
        expected_languages = {'.py', '.java', '.go', '.js'}
        assert expected_languages.issubset(languages)

    @pytest.mark.unit
    def test_configuration_file_scanning(self, crypto_auditor, temp_repo):
        """Test scanning of configuration files for cryptographic settings."""
        # Create SSL configuration file
        ssl_config = temp_repo / "ssl.conf"
        ssl_config.write_text("""
[ssl_settings]
SSLCipherSuite = HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA
SSLProtocol = TLSv1.2
SSLCertificateFile = /path/to/rsa-2048.crt
SSLCertificateKeyFile = /path/to/rsa-2048.key
""")
        
        # Create certificate file
        cert_file = temp_repo / "server.crt"
        cert_file.write_text("""
-----BEGIN CERTIFICATE-----
MIIEpDCCAowCCQC... (RSA 2048-bit certificate)
-----END CERTIFICATE-----
""")
        
        results = crypto_auditor.scan_directory(temp_repo)
        
        # Verify configuration vulnerabilities are detected
        config_vulns = [v for v in results.vulnerabilities if v.file_type == "config"]
        assert len(config_vulns) > 0

    @pytest.mark.unit
    @pytest.mark.security
    def test_malicious_input_handling(self, python_scanner):
        """Test scanner behavior with malicious or malformed input."""
        malicious_inputs = [
            # Extremely large file
            "x" * (10 * 1024 * 1024),  # 10MB of 'x'
            # Malformed Python syntax
            "def invalid_syntax(:\n    pass",
            # Binary data
            b"\x00\x01\x02\x03\x04\x05",
            # Unicode edge cases
            "def test():\n    # 🔐💀\n    pass",
        ]
        
        for malicious_input in malicious_inputs:
            with pytest.helpers.temp_python_file(malicious_input) as temp_file:
                # Should handle gracefully without crashing
                try:
                    findings = python_scanner.scan_file(temp_file)
                    # Should return empty list or valid findings, not crash
                    assert isinstance(findings, list)
                except Exception as e:
                    # If exception occurs, it should be a known, handled exception
                    assert isinstance(e, (ValueError, SyntaxError, UnicodeDecodeError))

    @pytest.mark.unit
    @pytest.mark.performance
    def test_large_repository_performance(self, crypto_auditor, temp_repo):
        """Test performance with large repositories."""
        import time
        
        # Create many files with crypto patterns
        for i in range(100):
            file_path = temp_repo / f"crypto_{i}.py"
            file_path.write_text(f"""
# File {i}
from cryptography.hazmat.primitives.asymmetric import rsa
def generate_key_{i}():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)
""")
        
        # Measure scan time
        start_time = time.time()
        results = crypto_auditor.scan_directory(temp_repo)
        scan_time = time.time() - start_time
        
        # Performance assertions
        assert len(results.vulnerabilities) >= 100  # Should find vulnerabilities
        assert scan_time < 60  # Should complete within reasonable time
        assert results.scan_stats.files_processed == 100

    @pytest.mark.unit
    def test_incremental_scanning(self, crypto_auditor, temp_repo):
        """Test incremental scanning capabilities."""
        # Initial scan
        file1 = temp_repo / "crypto1.py"
        file1.write_text("from cryptography.hazmat.primitives.asymmetric import rsa")
        
        results1 = crypto_auditor.scan_directory(temp_repo, incremental=True)
        
        # Add another file
        file2 = temp_repo / "crypto2.py"
        file2.write_text("from cryptography.hazmat.primitives.asymmetric import ec")
        
        # Incremental scan should only process new file
        results2 = crypto_auditor.scan_directory(temp_repo, incremental=True)
        
        assert results2.scan_stats.files_processed == 1  # Only new file
        assert len(results2.vulnerabilities) >= len(results1.vulnerabilities)

    @pytest.mark.unit
    def test_custom_pattern_support(self, crypto_auditor, temp_repo):
        """Test support for custom vulnerability patterns."""
        # Create custom pattern configuration
        custom_patterns = {
            "custom_crypto_lib": {
                "pattern": r"from custom_crypto import .*",
                "severity": "HIGH",
                "description": "Usage of deprecated custom crypto library"
            }
        }
        
        # Create file with custom pattern
        test_file = temp_repo / "custom.py"
        test_file.write_text("from custom_crypto import encrypt_data")
        
        # Scan with custom patterns
        results = crypto_auditor.scan_directory(
            temp_repo, 
            custom_patterns=custom_patterns
        )
        
        # Verify custom pattern is detected
        custom_vulns = [v for v in results.vulnerabilities if "custom_crypto" in v.description]
        assert len(custom_vulns) > 0
        assert custom_vulns[0].severity == Severity.HIGH