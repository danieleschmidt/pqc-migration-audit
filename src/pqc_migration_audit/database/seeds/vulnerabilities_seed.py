"""Seed data for vulnerability examples and test data."""

import json
from datetime import datetime, timedelta
from typing import List, Dict, Any

from ..connection import get_database
from ..models import ScanResultModel, VulnerabilityModel


def create_sample_scan_results() -> List[Dict[str, Any]]:
    """Create sample scan result data for testing."""
    
    base_time = datetime.now() - timedelta(days=30)
    
    sample_scans = [
        {
            "scan_path": "/example/project/web-app",
            "timestamp": (base_time + timedelta(days=1)).isoformat(),
            "scan_time": 2.45,
            "scanned_files": 156,
            "total_lines": 12450,
            "languages_detected": ["python", "javascript", "java"]
        },
        {
            "scan_path": "/example/project/mobile-app", 
            "timestamp": (base_time + timedelta(days=7)).isoformat(),
            "scan_time": 1.32,
            "scanned_files": 89,
            "total_lines": 8900,
            "languages_detected": ["java", "javascript"]
        },
        {
            "scan_path": "/example/project/api-service",
            "timestamp": (base_time + timedelta(days=14)).isoformat(),
            "scan_time": 0.89,
            "scanned_files": 45,
            "total_lines": 5600,
            "languages_detected": ["python", "go"]
        },
        {
            "scan_path": "/example/project/legacy-system",
            "timestamp": (base_time + timedelta(days=21)).isoformat(),
            "scan_time": 4.12,
            "scanned_files": 234,
            "total_lines": 23400,
            "languages_detected": ["java", "c", "cpp"]
        }
    ]
    
    return sample_scans


def create_sample_vulnerabilities() -> List[Dict[str, Any]]:
    """Create sample vulnerability data for different scenarios."""
    
    vulnerabilities = [
        # Critical RSA vulnerabilities with weak key sizes
        {
            "file_path": "/src/auth/crypto.py",
            "line_number": 15,
            "algorithm": "RSA",
            "severity": "critical",
            "key_size": 1024,
            "description": "RSA key generation with 1024-bit key size (quantum-vulnerable and weak)",
            "code_snippet": "private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)",
            "recommendation": "Replace with ML-KEM-768 (Kyber) for key exchange or increase to 4096-bit RSA as interim measure",
            "cwe_id": "CWE-327"
        },
        {
            "file_path": "/src/payment/encryption.java",
            "line_number": 42,
            "algorithm": "RSA", 
            "severity": "critical",
            "key_size": 512,
            "description": "RSA key generation with extremely weak 512-bit key size",
            "code_snippet": "KeyPairGenerator keyGen = KeyPairGenerator.getInstance(\"RSA\"); keyGen.initialize(512);",
            "recommendation": "URGENT: Replace with ML-KEM-768 (Kyber) immediately",
            "cwe_id": "CWE-327"
        },
        
        # High severity standard RSA/ECC vulnerabilities
        {
            "file_path": "/src/tls/handshake.py",
            "line_number": 78,
            "algorithm": "RSA",
            "severity": "high", 
            "key_size": 2048,
            "description": "RSA key generation detected (quantum-vulnerable)",
            "code_snippet": "private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)",
            "recommendation": "Replace with ML-KEM-768 (Kyber) for key exchange or ML-DSA-65 (Dilithium) for signatures",
            "cwe_id": "CWE-327"
        },
        {
            "file_path": "/src/certificates/ca.py",
            "line_number": 125,
            "algorithm": "ECC",
            "severity": "high",
            "key_size": None,
            "description": "ECC key generation detected (quantum-vulnerable)",
            "code_snippet": "private_key = ec.generate_private_key(ec.SECP256R1())",
            "recommendation": "Replace with ML-DSA-65 (Dilithium) for digital signatures",
            "cwe_id": "CWE-327"
        },
        {
            "file_path": "/mobile/crypto/KeyManager.java",
            "line_number": 67,
            "algorithm": "ECC",
            "severity": "high",
            "key_size": None,
            "description": "ECC KeyPairGenerator detected (quantum-vulnerable)",
            "code_snippet": "KeyPairGenerator keyGen = KeyPairGenerator.getInstance(\"EC\");",
            "recommendation": "Migrate to post-quantum signatures using ML-DSA-65 (Dilithium)",
            "cwe_id": "CWE-327"
        },
        
        # Medium severity DSA vulnerabilities
        {
            "file_path": "/legacy/signing/dsa_signer.py",
            "line_number": 34,
            "algorithm": "DSA",
            "severity": "high",
            "key_size": 2048,
            "description": "DSA key generation detected (quantum-vulnerable)",
            "code_snippet": "private_key = dsa.generate_private_key(key_size=2048)",
            "recommendation": "Replace with ML-DSA-44 (Dilithium) for digital signatures",
            "cwe_id": "CWE-327"
        },
        
        # Go language vulnerabilities
        {
            "file_path": "/api/crypto/keygen.go",
            "line_number": 23,
            "algorithm": "RSA",
            "severity": "high",
            "key_size": 2048,
            "description": "RSA key generation detected (quantum-vulnerable)",
            "code_snippet": "privateKey, err := rsa.GenerateKey(rand.Reader, 2048)",
            "recommendation": "Replace with post-quantum cryptography using liboqs Go bindings",
            "cwe_id": "CWE-327"
        },
        {
            "file_path": "/api/tls/ecdsa.go",
            "line_number": 56,
            "algorithm": "ECDSA",
            "severity": "high",
            "key_size": None,
            "description": "ECDSA key generation detected (quantum-vulnerable)",
            "code_snippet": "privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)",
            "recommendation": "Replace with ML-DSA-65 (Dilithium) for digital signatures",
            "cwe_id": "CWE-327"
        },
        
        # C/C++ vulnerabilities (legacy systems)
        {
            "file_path": "/legacy/crypto/rsa_impl.c",
            "line_number": 145,
            "algorithm": "RSA",
            "severity": "critical",
            "key_size": 1024,
            "description": "Legacy RSA implementation with weak key size",
            "code_snippet": "RSA_generate_key_ex(rsa, 1024, e, NULL)",
            "recommendation": "Modernize to use ML-KEM-768 (Kyber) with liboqs library",
            "cwe_id": "CWE-327"
        },
        {
            "file_path": "/legacy/crypto/ecdsa_verify.cpp",
            "line_number": 89,
            "algorithm": "ECDSA",
            "severity": "high",
            "key_size": None,
            "description": "ECDSA verification in legacy C++ code (quantum-vulnerable)",
            "code_snippet": "EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);",
            "recommendation": "Migrate to ML-DSA-65 (Dilithium) using liboqs C++ bindings",
            "cwe_id": "CWE-327"
        }
    ]
    
    return vulnerabilities


def seed_database():
    """Seed database with sample data for testing and demonstrations."""
    
    db = get_database()
    
    # Create sample scan results
    scan_data = create_sample_scan_results()
    vuln_data = create_sample_vulnerabilities()
    
    scan_ids = []
    
    # Insert scan results
    for scan in scan_data:
        query = """
            INSERT INTO scan_results 
            (scan_path, timestamp, scan_time, scanned_files, total_lines, languages_detected, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        
        scan_id = db.execute_insert(query, (
            scan["scan_path"],
            scan["timestamp"], 
            scan["scan_time"],
            scan["scanned_files"],
            scan["total_lines"],
            json.dumps(scan["languages_detected"]),
            datetime.now().isoformat()
        ))
        
        scan_ids.append(scan_id)
    
    # Insert vulnerabilities - distribute across scan results
    vuln_per_scan = len(vuln_data) // len(scan_ids)
    
    for i, vuln in enumerate(vuln_data):
        scan_id = scan_ids[i // vuln_per_scan] if i // vuln_per_scan < len(scan_ids) else scan_ids[-1]
        
        query = """
            INSERT INTO vulnerabilities 
            (scan_result_id, file_path, line_number, algorithm, severity, key_size, 
             description, code_snippet, recommendation, cwe_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        
        db.execute_insert(query, (
            scan_id,
            vuln["file_path"],
            vuln["line_number"],
            vuln["algorithm"],
            vuln["severity"],
            vuln["key_size"],
            vuln["description"],
            vuln["code_snippet"],
            vuln["recommendation"],
            vuln["cwe_id"],
            datetime.now().isoformat()
        ))
    
    # Create sample risk assessments
    for scan_id in scan_ids:
        # Count vulnerabilities for this scan
        vuln_query = "SELECT COUNT(*) as count, severity FROM vulnerabilities WHERE scan_result_id = ? GROUP BY severity"
        vuln_counts = db.execute_query(vuln_query, (scan_id,))
        
        # Calculate risk score based on vulnerabilities
        risk_score = 0
        total_vulns = 0
        migration_hours = 0
        
        for row in vuln_counts:
            count = row['count']
            severity = row['severity']
            total_vulns += count
            
            if severity == 'critical':
                risk_score += count * 25
                migration_hours += count * 16
            elif severity == 'high':
                risk_score += count * 15
                migration_hours += count * 8
            elif severity == 'medium':
                risk_score += count * 10
                migration_hours += count * 4
            else:
                risk_score += count * 5
                migration_hours += count * 2
        
        risk_score = min(risk_score, 100)
        
        if risk_score >= 80:
            risk_level = "CRITICAL"
        elif risk_score >= 60:
            risk_level = "HIGH"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        assessment_data = {
            "total_vulnerabilities": total_vulns,
            "risk_factors": ["Quantum computing threat timeline", "Algorithm deprecation"],
            "timeline_urgency": "2027 compliance deadline"
        }
        
        risk_query = """
            INSERT INTO risk_assessments 
            (scan_result_id, hndl_risk_score, migration_hours, risk_level, assessment_data, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """
        
        db.execute_insert(risk_query, (
            scan_id,
            risk_score,
            migration_hours,
            risk_level,
            json.dumps(assessment_data),
            datetime.now().isoformat()
        ))
    
    print(f"Database seeded with {len(scan_data)} scan results and {len(vuln_data)} vulnerabilities")
    return len(scan_data), len(vuln_data)


if __name__ == "__main__":
    # Run seeding when script is executed directly
    scans, vulns = seed_database()
    print(f"Seeding complete: {scans} scans, {vulns} vulnerabilities")