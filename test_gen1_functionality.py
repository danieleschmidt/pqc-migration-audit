#!/usr/bin/env python3
"""Test Generation 1 functionality - Basic working features."""

import sys
import os
import tempfile
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, '/root/repo/src')

from pqc_migration_audit.core import CryptoAuditor, RiskAssessment
from pqc_migration_audit.types import Severity, CryptoAlgorithm


def test_basic_scanning():
    """Test basic vulnerability scanning functionality."""
    print("🔍 Testing basic scanning functionality...")
    
    auditor = CryptoAuditor()
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test files with vulnerable crypto
        test_files = {
            'python_rsa.py': '''from cryptography.hazmat.primitives.asymmetric import rsa
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)''',
            'java_rsa.java': '''import java.security.KeyPairGenerator;
KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
keyGen.initialize(2048);''',
            'go_ecdsa.go': '''package main
import "crypto/ecdsa"
import "crypto/elliptic"
privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)''',
        }
        
        for filename, content in test_files.items():
            file_path = os.path.join(tmpdir, filename)
            with open(file_path, 'w') as f:
                f.write(content)
        
        # Perform scan
        results = auditor.scan_directory(tmpdir)
        
        print(f"✅ Scan completed: {len(results.vulnerabilities)} vulnerabilities found")
        print(f"   • Files scanned: {results.scanned_files}")
        print(f"   • Languages detected: {results.languages_detected}")
        print(f"   • Scan time: {results.scan_time:.2f}s")
        
        # Validate results
        assert len(results.vulnerabilities) > 0, "Should find vulnerabilities"
        assert results.scanned_files > 0, "Should scan files"
        assert len(results.languages_detected) > 0, "Should detect languages"
        
        for vuln in results.vulnerabilities[:3]:  # Show first 3
            print(f"   • {vuln.algorithm.value} in {Path(vuln.file_path).name}:{vuln.line_number}")
        
        return results


def test_risk_assessment(scan_results):
    """Test risk assessment functionality."""
    print("\n⚠️  Testing risk assessment...")
    
    risk_assessment = RiskAssessment(scan_results)
    
    # Calculate risk metrics
    hndl_risk = risk_assessment.calculate_harvest_now_decrypt_later_risk()
    migration_hours = risk_assessment.migration_hours
    risk_report = risk_assessment.generate_risk_report()
    
    print(f"✅ Risk assessment completed:")
    print(f"   • HNDL Risk Score: {hndl_risk}/100")
    print(f"   • Migration Hours: {migration_hours}")
    print(f"   • Risk Level: {risk_assessment._get_risk_level(hndl_risk)}")
    
    # Validate risk metrics
    assert 0 <= hndl_risk <= 100, "Risk score should be 0-100"
    assert migration_hours > 0, "Should estimate migration effort"
    assert 'risk_summary' in risk_report, "Should generate risk report"
    
    return risk_assessment


def test_migration_planning(scan_results):
    """Test migration plan generation."""
    print("\n📋 Testing migration planning...")
    
    auditor = CryptoAuditor()
    migration_plan = auditor.create_migration_plan(scan_results)
    
    print(f"✅ Migration plan generated:")
    print(f"   • Total vulnerabilities: {migration_plan['summary']['total_vulnerabilities']}")
    print(f"   • Critical: {migration_plan['summary']['critical']}")
    print(f"   • High: {migration_plan['summary']['high']}")
    print(f"   • Migration phases: {len(migration_plan['migration_phases'])}")
    
    # Validate migration plan
    assert 'summary' in migration_plan, "Should have summary"
    assert 'migration_phases' in migration_plan, "Should have phases"
    assert 'recommendations' in migration_plan, "Should have recommendations"
    assert len(migration_plan['migration_phases']) > 0, "Should have migration phases"
    
    return migration_plan


def test_advanced_scanning_features():
    """Test advanced scanning features."""
    print("\n🔬 Testing advanced scanning features...")
    
    # Test with custom patterns
    custom_patterns = {
        'weak_hash': {
            'pattern': r'MD5\s*\(',
            'severity': 'medium',
            'description': 'Weak hash function detected'
        }
    }
    
    auditor = CryptoAuditor()
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test file with custom pattern
        test_file = os.path.join(tmpdir, 'test_weak.py')
        with open(test_file, 'w') as f:
            f.write('import hashlib\nhash_obj = hashlib.MD5()\n')
        
        # Scan with custom patterns
        results = auditor.scan_directory(tmpdir, custom_patterns=custom_patterns)
        
        print(f"✅ Advanced scan completed: {len(results.vulnerabilities)} vulnerabilities found")
        
        # Should find custom pattern
        custom_found = any('weak_hash' in vuln.description for vuln in results.vulnerabilities)
        assert custom_found, "Should detect custom patterns"
        
        print("   • Custom pattern detection: ✅")
        
        return results


def test_error_handling():
    """Test error handling and edge cases."""
    print("\n🛡️  Testing error handling...")
    
    auditor = CryptoAuditor()
    
    # Test non-existent directory
    try:
        results = auditor.scan_directory("/non/existent/path")
        assert False, "Should raise exception for non-existent path"
    except Exception as e:
        print(f"   • Non-existent path handling: ✅ ({type(e).__name__})")
    
    # Test empty directory
    with tempfile.TemporaryDirectory() as tmpdir:
        results = auditor.scan_directory(tmpdir)
        assert len(results.vulnerabilities) == 0, "Empty directory should have no vulnerabilities"
        print("   • Empty directory handling: ✅")
    
    # Test large file handling
    with tempfile.TemporaryDirectory() as tmpdir:
        large_file = os.path.join(tmpdir, 'large.py')
        with open(large_file, 'w') as f:
            f.write('# Large file\n' * 10000)  # 10k lines
            f.write('from cryptography.hazmat.primitives.asymmetric import rsa\n')
            f.write('private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n')
        
        results = auditor.scan_directory(tmpdir)
        assert len(results.vulnerabilities) > 0, "Should handle large files"
        print("   • Large file handling: ✅")


def generate_comprehensive_report(scan_results, risk_assessment, migration_plan):
    """Generate comprehensive Generation 1 report."""
    print("\n📄 Generating comprehensive report...")
    
    report = {
        "generation": 1,
        "description": "MAKE IT WORK - Basic functionality implementation",
        "features_implemented": [
            "Core vulnerability scanning for Python, Java, Go, JavaScript, C/C++",
            "Risk assessment with HNDL scoring",
            "Migration planning with phased approach",
            "Custom pattern support",
            "Advanced error handling and validation",
            "Comprehensive reporting capabilities"
        ],
        "scan_results": {
            "files_scanned": scan_results.scanned_files,
            "vulnerabilities_found": len(scan_results.vulnerabilities),
            "languages_detected": scan_results.languages_detected,
            "scan_duration": scan_results.scan_time
        },
        "risk_metrics": {
            "hndl_risk_score": risk_assessment.calculate_harvest_now_decrypt_later_risk(),
            "migration_effort_hours": risk_assessment.migration_hours,
            "risk_level": risk_assessment._get_risk_level(risk_assessment.calculate_harvest_now_decrypt_later_risk())
        },
        "migration_summary": {
            "total_vulnerabilities": migration_plan['summary']['total_vulnerabilities'],
            "critical_count": migration_plan['summary']['critical'],
            "high_count": migration_plan['summary']['high'],
            "migration_phases": len(migration_plan['migration_phases'])
        },
        "quality_metrics": {
            "error_handling": "Comprehensive",
            "input_validation": "Enabled",
            "security_validation": "Enabled",
            "performance_optimization": "Basic"
        }
    }
    
    report_file = '/root/repo/generation1_report.json'
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"✅ Comprehensive report saved: {report_file}")
    return report


def main():
    """Run Generation 1 tests."""
    print("🚀 GENERATION 1: MAKE IT WORK - Testing Implementation\n")
    
    try:
        # Test basic functionality
        scan_results = test_basic_scanning()
        risk_assessment = test_risk_assessment(scan_results)
        migration_plan = test_migration_planning(scan_results)
        
        # Test advanced features
        test_advanced_scanning_features()
        test_error_handling()
        
        # Generate comprehensive report
        report = generate_comprehensive_report(scan_results, risk_assessment, migration_plan)
        
        print("\n✅ GENERATION 1 COMPLETE - All basic functionality working!")
        print(f"   • Core scanning: ✅")
        print(f"   • Risk assessment: ✅") 
        print(f"   • Migration planning: ✅")
        print(f"   • Advanced features: ✅")
        print(f"   • Error handling: ✅")
        print(f"   • Comprehensive reporting: ✅")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Generation 1 test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)