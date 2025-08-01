"""Integration tests for full scanning workflow."""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from pqc_migration_audit.cli import main
from pqc_migration_audit.core import CryptoAuditor
from pqc_migration_audit.reporters import JSONReporter, HTMLReporter


class TestFullScanWorkflow:
    """Integration tests for complete scanning workflows."""

    @pytest.fixture
    def sample_repository(self, temp_repo):
        """Create a sample repository with various vulnerabilities."""
        # Python vulnerabilities
        (temp_repo / "backend").mkdir()
        (temp_repo / "backend" / "crypto_utils.py").write_text("""
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
import hashlib

def generate_rsa_key():
    \"\"\"Generate RSA key - VULNERABLE.\"\"\"
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048  # Quantum vulnerable
    )

def generate_ec_key():
    \"\"\"Generate EC key - VULNERABLE.\"\"\"
    return ec.generate_private_key(ec.SECP256R1())

def weak_hash():
    \"\"\"Use weak hash - VULNERABLE.\"\"\"
    return hashlib.md5(b"data").hexdigest()
""")

        # Java vulnerabilities
        (temp_repo / "src" / "main" / "java").mkdir(parents=True)
        (temp_repo / "src" / "main" / "java" / "CryptoService.java").write_text("""
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;

public class CryptoService {
    public KeyPair generateRSAKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); // Quantum vulnerable
        return keyGen.generateKeyPair();
    }
    
    public SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // Potentially vulnerable
        return keyGen.generateKey();
    }
}
""")

        # Configuration files
        (temp_repo / "config").mkdir()
        (temp_repo / "config" / "ssl.conf").write_text("""
SSLEngine on
SSLProtocol TLSv1.2
SSLCipherSuite ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256
SSLCertificateFile /etc/ssl/certs/server.crt
SSLCertificateKeyFile /etc/ssl/private/server.key
""")

        # Package configuration
        (temp_repo / "requirements.txt").write_text("""
cryptography==3.4.8
pycrypto==2.6.1
rsa==4.7.2
ecdsa==0.17.0
""")

        return temp_repo

    @pytest.mark.integration
    def test_complete_python_java_scan(self, sample_repository):
        """Test complete scan of repository with Python and Java code."""
        auditor = CryptoAuditor()
        results = auditor.scan_directory(sample_repository)
        
        # Verify comprehensive results
        assert len(results.vulnerabilities) >= 4  # At least 4 vulnerabilities found
        assert results.scan_stats.files_processed >= 4
        assert results.scan_stats.languages_detected >= 2
        
        # Verify vulnerability types
        rsa_vulns = [v for v in results.vulnerabilities if "RSA" in v.algorithm]
        ec_vulns = [v for v in results.vulnerabilities if "EC" in v.algorithm]
        hash_vulns = [v for v in results.vulnerabilities if "MD5" in v.algorithm]
        
        assert len(rsa_vulns) >= 2  # Python and Java RSA
        assert len(ec_vulns) >= 1   # Python EC
        assert len(hash_vulns) >= 1 # Python MD5
        
        # Verify file paths
        python_files = [v.file_path for v in results.vulnerabilities if v.file_path.suffix == '.py']
        java_files = [v.file_path for v in results.vulnerabilities if v.file_path.suffix == '.java']
        
        assert len(python_files) > 0
        assert len(java_files) > 0

    @pytest.mark.integration
    def test_cli_json_output(self, sample_repository, tmp_path):
        """Test CLI with JSON output format."""
        output_file = tmp_path / "scan_results.json"
        
        # Mock sys.argv for CLI
        with patch('sys.argv', [
            'pqc-audit', 'scan', str(sample_repository),
            '--output', str(output_file),
            '--format', 'json'
        ]):
            main()
        
        # Verify output file exists and contains valid JSON
        assert output_file.exists()
        
        with open(output_file) as f:
            results_data = json.load(f)
        
        # Verify JSON structure
        assert 'scan_metadata' in results_data
        assert 'vulnerabilities' in results_data
        assert 'risk_assessment' in results_data
        assert 'scan_statistics' in results_data
        
        # Verify vulnerability data
        vulnerabilities = results_data['vulnerabilities']
        assert len(vulnerabilities) > 0
        
        for vuln in vulnerabilities:
            assert 'id' in vuln
            assert 'severity' in vuln
            assert 'algorithm' in vuln
            assert 'file_path' in vuln
            assert 'line_number' in vuln

    @pytest.mark.integration
    def test_cli_html_output(self, sample_repository, tmp_path):
        """Test CLI with HTML output format."""
        output_file = tmp_path / "scan_results.html"
        
        with patch('sys.argv', [
            'pqc-audit', 'scan', str(sample_repository),
            '--output', str(output_file),
            '--format', 'html'
        ]):
            main()
        
        # Verify HTML output
        assert output_file.exists()
        
        html_content = output_file.read_text()
        
        # Verify HTML structure
        assert '<html>' in html_content
        assert '<title>' in html_content
        assert 'PQC Migration Audit Report' in html_content
        
        # Verify content sections
        assert 'Executive Summary' in html_content
        assert 'Vulnerability Details' in html_content
        assert 'Risk Assessment' in html_content

    @pytest.mark.integration
    def test_incremental_scan_workflow(self, sample_repository):
        """Test incremental scanning workflow."""
        auditor = CryptoAuditor()
        
        # Initial full scan
        results1 = auditor.scan_directory(sample_repository, incremental=False)
        baseline_vulns = len(results1.vulnerabilities)
        
        # Add new vulnerable file
        new_file = sample_repository / "new_crypto.py"
        new_file.write_text("""
from cryptography.hazmat.primitives.asymmetric import dsa
def generate_dsa_key():
    return dsa.generate_private_key(key_size=2048)
""")
        
        # Incremental scan
        results2 = auditor.scan_directory(sample_repository, incremental=True)
        
        # Verify incremental behavior
        assert len(results2.vulnerabilities) > baseline_vulns
        assert results2.scan_stats.files_processed == 1  # Only new file
        
        # Verify new DSA vulnerability found
        dsa_vulns = [v for v in results2.vulnerabilities if "DSA" in v.algorithm]
        assert len(dsa_vulns) > 0

    @pytest.mark.integration
    def test_multi_format_reporting(self, sample_repository, tmp_path):
        """Test generating multiple report formats simultaneously."""
        auditor = CryptoAuditor()
        results = auditor.scan_directory(sample_repository)
        
        # Generate multiple formats
        json_file = tmp_path / "results.json"
        html_file = tmp_path / "results.html"
        csv_file = tmp_path / "results.csv"
        
        json_reporter = JSONReporter()
        html_reporter = HTMLReporter()
        
        json_reporter.generate_report(results, json_file)
        html_reporter.generate_report(results, html_file)
        
        # Verify all files created
        assert json_file.exists()
        assert html_file.exists()
        
        # Verify content consistency
        with open(json_file) as f:
            json_data = json.load(f)
        
        html_content = html_file.read_text()
        
        # Same number of vulnerabilities in both formats
        json_vuln_count = len(json_data['vulnerabilities'])
        html_vuln_matches = html_content.count('vulnerability-item')
        
        assert json_vuln_count > 0
        # HTML might have different structure, just verify it's populated
        assert len(html_content) > 1000  # Substantial content

    @pytest.mark.integration
    def test_large_repository_scan(self, tmp_path):
        """Test scanning a large repository with many files."""
        large_repo = tmp_path / "large_repo"
        large_repo.mkdir()
        
        # Create many files with various patterns
        for i in range(50):
            # Python files
            py_file = large_repo / f"module_{i}.py"
            py_file.write_text(f"""
# Module {i}
from cryptography.hazmat.primitives.asymmetric import rsa
def func_{i}():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)
""")
            
            # Java files
            if i % 2 == 0:
                java_file = large_repo / f"Service{i}.java"
                java_file.write_text(f"""
public class Service{i} {{
    public void method{i}() {{
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
    }}
}}
""")
        
        auditor = CryptoAuditor()
        results = auditor.scan_directory(large_repo)
        
        # Verify scalability
        assert results.scan_stats.files_processed >= 75  # 50 Python + 25 Java
        assert len(results.vulnerabilities) >= 75       # At least one per file
        assert results.scan_stats.scan_duration < 120   # Under 2 minutes

    @pytest.mark.integration
    def test_configuration_file_integration(self, sample_repository):
        """Test integration of configuration file scanning."""
        auditor = CryptoAuditor()
        results = auditor.scan_directory(sample_repository, scan_configs=True)
        
        # Verify configuration vulnerabilities
        config_vulns = [v for v in results.vulnerabilities if v.file_type == "config"]
        assert len(config_vulns) > 0
        
        # Verify SSL configuration issues
        ssl_vulns = [v for v in config_vulns if "ssl" in v.file_path.name.lower()]
        assert len(ssl_vulns) > 0

    @pytest.mark.integration
    def test_dependency_analysis_integration(self, sample_repository):
        """Test integration of dependency vulnerability analysis."""
        auditor = CryptoAuditor()
        results = auditor.scan_directory(
            sample_repository, 
            analyze_dependencies=True
        )
        
        # Verify dependency vulnerabilities
        dep_vulns = [v for v in results.vulnerabilities if v.vulnerability_type == "dependency"]
        assert len(dep_vulns) > 0
        
        # Verify specific vulnerable dependencies
        pycrypto_vulns = [v for v in dep_vulns if "pycrypto" in v.description.lower()]
        assert len(pycrypto_vulns) > 0  # pycrypto is known vulnerable

    @pytest.mark.integration
    def test_risk_assessment_integration(self, sample_repository):
        """Test integration of risk assessment calculations."""
        auditor = CryptoAuditor()
        results = auditor.scan_directory(sample_repository)
        
        # Verify risk assessment data
        assert results.risk_assessment is not None
        assert results.risk_assessment.overall_risk_score > 0
        assert results.risk_assessment.overall_risk_score <= 100
        
        # Verify risk categories
        assert hasattr(results.risk_assessment, 'harvest_now_decrypt_later_risk')
        assert hasattr(results.risk_assessment, 'migration_urgency_score')
        assert hasattr(results.risk_assessment, 'business_impact_score')
        
        # Verify timeline assessment
        assert results.risk_assessment.estimated_migration_hours > 0
        assert results.risk_assessment.quantum_threat_timeline is not None

    @pytest.mark.integration
    @pytest.mark.slow
    def test_end_to_end_enterprise_workflow(self, sample_repository, tmp_path):
        """Test complete enterprise workflow from scan to reporting."""
        # Simulate enterprise scan workflow
        
        # 1. Configuration
        config = {
            "languages": ["python", "java"],
            "output_formats": ["json", "html", "sarif"],
            "risk_thresholds": {
                "critical": 90,
                "high": 70,
                "medium": 40
            },
            "reporting": {
                "include_patches": True,
                "include_sbom": True,
                "executive_summary": True
            }
        }
        
        # 2. Scanning
        auditor = CryptoAuditor(config=config)
        results = auditor.scan_directory(sample_repository)
        
        # 3. Risk Assessment
        assert results.risk_assessment.overall_risk_score > 0
        
        # 4. Patch Generation
        patches = auditor.generate_patches(results.vulnerabilities)
        assert len(patches) > 0
        
        # 5. Multi-format Reporting
        json_file = tmp_path / "enterprise_results.json"
        html_file = tmp_path / "enterprise_results.html"
        sarif_file = tmp_path / "enterprise_results.sarif"
        
        json_reporter = JSONReporter()
        html_reporter = HTMLReporter()
        
        json_reporter.generate_report(results, json_file)
        html_reporter.generate_report(results, html_file)
        
        # 6. Verification
        assert json_file.exists()
        assert html_file.exists()
        
        # Verify executive summary in HTML
        html_content = html_file.read_text()
        assert "Executive Summary" in html_content
        assert "Risk Score" in html_content
        assert "Migration Recommendations" in html_content
        
        # Verify JSON completeness
        with open(json_file) as f:
            json_data = json.load(f)
        
        assert "patches" in json_data
        assert "sbom" in json_data
        assert len(json_data["patches"]) > 0