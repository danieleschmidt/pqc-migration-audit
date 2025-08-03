#!/usr/bin/env python3
"""Minimal test script for the PQC scanner core functionality."""

import sys
import os
sys.path.insert(0, 'src')

# Import core directly to avoid CLI dependencies
import pqc_migration_audit.core as core

def test_minimal():
    """Test the minimal PQC scanner functionality."""
    print("🔍 Testing PQC Migration Audit Core")
    print("=" * 50)
    
    # Initialize auditor
    auditor = core.CryptoAuditor()
    
    # Scan the examples directory
    try:
        results = auditor.scan_directory("examples")
        
        print(f"📊 Scan Results:")
        print(f"   Path: {results.scan_path}")
        print(f"   Files scanned: {results.scanned_files}")
        print(f"   Total lines: {results.total_lines}")
        print(f"   Scan time: {results.scan_time:.2f}s")
        print(f"   Languages: {', '.join(results.languages_detected)}")
        print(f"   Vulnerabilities found: {len(results.vulnerabilities)}")
        
        if results.vulnerabilities:
            print(f"\n🚨 Vulnerabilities Found:")
            print("-" * 40)
            
            for i, vuln in enumerate(results.vulnerabilities, 1):
                print(f"{i}. {vuln.file_path}:{vuln.line_number}")
                print(f"   Algorithm: {vuln.algorithm.value}")
                print(f"   Severity: {vuln.severity.value.upper()}")
                if vuln.key_size:
                    print(f"   Key Size: {vuln.key_size}")
                print(f"   Description: {vuln.description}")
                print(f"   Recommendation: {vuln.recommendation}")
                print()
        
        # Risk assessment
        risk_assessment = core.RiskAssessment(results)
        risk_score = risk_assessment.calculate_harvest_now_decrypt_later_risk()
        migration_hours = risk_assessment.migration_hours
        
        print(f"⚠️  Risk Assessment:")
        print(f"   HNDL Risk Score: {risk_score}/100")
        risk_level = "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60 else "MEDIUM" if risk_score >= 40 else "LOW"
        print(f"   Risk Level: {risk_level}")
        print(f"   Migration Effort: {migration_hours} hours")
        
        # Generate migration plan
        migration_plan = auditor.create_migration_plan(results)
        print(f"\n📋 Migration Plan:")
        print(f"   Total vulnerabilities: {migration_plan['summary']['total_vulnerabilities']}")
        print(f"   Critical: {migration_plan['summary']['critical']}")
        print(f"   High: {migration_plan['summary']['high']}")
        print(f"   Medium: {migration_plan['summary']['medium']}")
        print(f"   Low: {migration_plan['summary']['low']}")
        
        print(f"\n📈 Migration Phases:")
        for phase in migration_plan['migration_phases']:
            print(f"   Phase {phase['phase']}: {phase['name']}")
            print(f"      Items: {len(phase['vulnerabilities'])}")
            print(f"      Effort: {phase['estimated_effort']}")
        
        print(f"\n💡 Recommendations:")
        for rec in migration_plan['recommendations']['immediate_actions'][:3]:
            print(f"   • {rec}")
        
        print(f"\n✅ Core functionality test completed successfully!")
        print(f"🔐 Found {len(results.vulnerabilities)} quantum-vulnerable implementations")
        print(f"⏱️  Estimated {migration_hours} hours of migration effort needed")
        
        return True
        
    except Exception as e:
        print(f"❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_minimal()
    sys.exit(0 if success else 1)