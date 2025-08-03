#!/usr/bin/env python3
"""Simple test script for the PQC scanner core functionality."""

import sys
import os
sys.path.insert(0, 'src')

# Import only core functionality to avoid CLI dependencies
from pqc_migration_audit.core import CryptoAuditor, RiskAssessment

def test_core_functionality():
    """Test the core PQC scanner functionality."""
    print("🔍 Testing PQC Migration Audit Core")
    print("=" * 50)
    
    # Initialize auditor
    auditor = CryptoAuditor()
    
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
        risk_assessment = RiskAssessment(results)
        risk_score = risk_assessment.calculate_harvest_now_decrypt_later_risk()
        migration_hours = risk_assessment.migration_hours
        
        print(f"⚠️  Risk Assessment:")
        print(f"   HNDL Risk Score: {risk_score}/100")
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
        
        # Test services
        print(f"\n🔧 Testing Services:")
        
        # Migration service
        from pqc_migration_audit.services.migration_service import MigrationService
        migration_service = MigrationService()
        roadmap = migration_service.create_migration_roadmap(results)
        print(f"   Migration Service: Generated roadmap with {len(roadmap['recommendations'])} recommendations")
        
        # Inventory service
        from pqc_migration_audit.services.inventory_service import CryptoInventoryService
        inventory_service = CryptoInventoryService()
        inventory = inventory_service.generate_crypto_inventory(results)
        print(f"   Inventory Service: Found {inventory['summary']['total_crypto_implementations']} implementations")
        
        # Compliance service
        from pqc_migration_audit.services.compliance_service import ComplianceService
        compliance_service = ComplianceService()
        compliance_report = compliance_service.generate_compliance_report(results)
        print(f"   Compliance Service: Assessed {len(compliance_report['framework_assessments'])} frameworks")
        
        print(f"\n✅ All tests completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_core_functionality()
    sys.exit(0 if success else 1)