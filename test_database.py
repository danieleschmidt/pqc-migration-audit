#!/usr/bin/env python3
"""Test script for database layer functionality."""

import sys
import os
sys.path.insert(0, 'src')

import sqlite3
from datetime import datetime

# Import database components
import pqc_migration_audit.database.connection as db_conn
from pqc_migration_audit.database.repository import (
    ScanResultRepository, VulnerabilityRepository, 
    RiskAssessmentRepository
)
from pqc_migration_audit.database.models import (
    ScanResultModel, VulnerabilityModel, RiskAssessmentModel
)

def test_database_layer():
    """Test the database layer functionality."""
    print("🗄️  Testing PQC Migration Audit Database Layer")
    print("=" * 60)
    
    try:
        # Initialize database connection (in-memory for testing)
        db = db_conn.DatabaseConnection(":memory:")
        print("✅ Database connection initialized")
        
        # Test repositories
        scan_repo = ScanResultRepository(db)
        vuln_repo = VulnerabilityRepository(db)
        risk_repo = RiskAssessmentRepository(db)
        print("✅ Repositories initialized")
        
        # Create sample scan result
        scan_model = ScanResultModel(
            scan_path="/test/example",
            timestamp=datetime.now().isoformat(),
            scan_time=1.23,
            scanned_files=5,
            total_lines=500,
            languages_detected=["python", "java"],
            created_at=datetime.now()
        )
        
        scan_id = scan_repo.create(scan_model)
        print(f"✅ Created scan result with ID: {scan_id}")
        
        # Create sample vulnerabilities
        vulnerabilities = [
            VulnerabilityModel(
                scan_result_id=scan_id,
                file_path="/test/crypto.py",
                line_number=10,
                algorithm="RSA",
                severity="high",
                key_size=2048,
                description="RSA key generation detected",
                code_snippet="rsa.generate_private_key(key_size=2048)",
                recommendation="Replace with ML-KEM (Kyber)",
                cwe_id="CWE-327",
                created_at=datetime.now()
            ),
            VulnerabilityModel(
                scan_result_id=scan_id,
                file_path="/test/ecc.py", 
                line_number=25,
                algorithm="ECC",
                severity="high",
                description="ECC key generation detected",
                code_snippet="ec.generate_private_key(ec.SECP256R1())",
                recommendation="Replace with ML-DSA (Dilithium)",
                cwe_id="CWE-327",
                created_at=datetime.now()
            )
        ]
        
        vuln_ids = []
        for vuln in vulnerabilities:
            vuln_id = vuln_repo.create(vuln)
            vuln_ids.append(vuln_id)
        
        print(f"✅ Created {len(vuln_ids)} vulnerabilities")
        
        # Create risk assessment
        risk_model = RiskAssessmentModel(
            scan_result_id=scan_id,
            hndl_risk_score=85,
            migration_hours=24,
            risk_level="HIGH",
            assessment_data={
                "algorithm_breakdown": {"RSA": 1, "ECC": 1},
                "severity_breakdown": {"high": 2}
            },
            created_at=datetime.now()
        )
        
        risk_id = risk_repo.create(risk_model)
        print(f"✅ Created risk assessment with ID: {risk_id}")
        
        # Test retrieval operations
        print("\n📊 Testing retrieval operations:")
        
        # Get scan result
        retrieved_scan = scan_repo.get_by_id(scan_id)
        if retrieved_scan:
            print(f"   Scan path: {retrieved_scan.scan_path}")
            print(f"   Files scanned: {retrieved_scan.scanned_files}")
            print(f"   Languages: {', '.join(retrieved_scan.languages_detected)}")
        
        # Get vulnerabilities for scan
        scan_vulns = vuln_repo.get_by_scan_result(scan_id)
        print(f"   Vulnerabilities: {len(scan_vulns)}")
        for vuln in scan_vulns:
            print(f"     - {vuln.algorithm} in {vuln.file_path}:{vuln.line_number} ({vuln.severity})")
        
        # Get risk assessment
        risk_assessment = risk_repo.get_by_scan_result(scan_id)
        if risk_assessment:
            print(f"   Risk score: {risk_assessment.hndl_risk_score}/100")
            print(f"   Risk level: {risk_assessment.risk_level}")
            print(f"   Migration effort: {risk_assessment.migration_hours} hours")
        
        # Test statistics
        print("\n📈 Testing statistics:")
        vuln_stats = vuln_repo.get_statistics()
        print(f"   Total vulnerabilities: {vuln_stats['total_vulnerabilities']}")
        print(f"   By severity: {vuln_stats['by_severity']}")
        print(f"   By algorithm: {vuln_stats['by_algorithm']}")
        
        # Test cache functionality
        print("\n💾 Testing cache functionality:")
        cache = db_conn.CacheManager(".test-cache")
        
        # Cache some data
        test_data = {"scan_results": "cached_value", "timestamp": datetime.now().isoformat()}
        cache.set("test_key", test_data)
        print("   ✅ Data cached")
        
        # Retrieve from cache
        cached_data = cache.get("test_key")
        if cached_data:
            print(f"   ✅ Retrieved from cache: {cached_data['scan_results']}")
        
        # Test update operations
        print("\n🔄 Testing update operations:")
        
        # Update scan result
        retrieved_scan.total_lines = 600
        update_success = scan_repo.update(retrieved_scan)
        print(f"   Scan update: {'✅ Success' if update_success else '❌ Failed'}")
        
        # Verify update
        updated_scan = scan_repo.get_by_id(scan_id)
        if updated_scan and updated_scan.total_lines == 600:
            print("   ✅ Update verified")
        
        # Test count operations
        print("\n🔢 Testing count operations:")
        scan_count = scan_repo.count()
        vuln_count = vuln_repo.count()
        print(f"   Total scans: {scan_count}")
        print(f"   Total vulnerabilities: {vuln_count}")
        
        # Clean up test cache
        cache.clear()
        print("   ✅ Cache cleared")
        
        # Close database
        db.close()
        print("\n✅ Database layer test completed successfully!")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Database layer test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_database_layer()
    sys.exit(0 if success else 1)