"""
Simple Scanner for Generation 1: Make It Work
Basic functionality without advanced features for quick setup and testing.
"""

import os
import re
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from .types import Vulnerability, Severity, CryptoAlgorithm, ScanResults, ScanStats


@dataclass
class SimpleScanResult:
    """Simple scan result for basic functionality."""
    vulnerabilities: List[Vulnerability]
    files_scanned: int
    total_time: float
    summary: Dict[str, int]


class SimpleScanner:
    """
    Simplified scanner for basic functionality testing.
    No advanced features, just core vulnerability detection.
    """
    
    def __init__(self):
        """Initialize simple scanner."""
        self.supported_extensions = {'.py', '.java', '.go', '.js', '.ts', '.c', '.cpp'}
        
        # Basic patterns for common vulnerabilities
        self.patterns = {
            'python': {
                'rsa': [r'rsa\.generate_private_key', r'RSA\.generate'],
                'ecc': [r'ec\.generate_private_key', r'SECP\d+R1'],
                'imports': [r'from\s+cryptography.*import.*rsa', r'from\s+cryptography.*import.*ec']
            },
            'java': {
                'rsa': [r'KeyPairGenerator\.getInstance.*RSA', r'RSAKeyGenParameterSpec'],
                'ecc': [r'KeyPairGenerator\.getInstance.*EC', r'ECGenParameterSpec']
            },
            'go': {
                'rsa': [r'rsa\.GenerateKey', r'crypto/rsa'],
                'ecc': [r'ecdsa\.GenerateKey', r'crypto/ecdsa']
            },
            'javascript': {
                'rsa': [r'generateKeyPair.*rsa', r'node-rsa'],
                'ecc': [r'generateKeyPair.*ec', r'elliptic']
            }
        }
    
    def scan_simple(self, target_path: str) -> SimpleScanResult:
        """
        Perform basic vulnerability scan.
        
        Args:
            target_path: Path to scan (file or directory)
            
        Returns:
            SimpleScanResult with basic vulnerability information
        """
        start_time = time.time()
        vulnerabilities = []
        files_scanned = 0
        
        # Convert to Path object
        path = Path(target_path)
        
        if not path.exists():
            return SimpleScanResult([], 0, 0.0, {'error': 'Path does not exist'})
        
        # Collect files to scan
        files_to_scan = []
        if path.is_file():
            if self._should_scan_file(path):
                files_to_scan.append(path)
        else:
            files_to_scan = self._find_source_files(path)
        
        # Scan each file
        for file_path in files_to_scan:
            try:
                file_vulnerabilities = self._scan_file_simple(file_path)
                vulnerabilities.extend(file_vulnerabilities)
                files_scanned += 1
            except Exception as e:
                print(f"Warning: Could not scan {file_path}: {e}")
        
        total_time = time.time() - start_time
        
        # Create summary
        summary = {
            'total': len(vulnerabilities),
            'critical': len([v for v in vulnerabilities if v.severity == Severity.CRITICAL]),
            'high': len([v for v in vulnerabilities if v.severity == Severity.HIGH]),
            'medium': len([v for v in vulnerabilities if v.severity == Severity.MEDIUM]),
            'low': len([v for v in vulnerabilities if v.severity == Severity.LOW])
        }
        
        return SimpleScanResult(
            vulnerabilities=vulnerabilities,
            files_scanned=files_scanned,
            total_time=total_time,
            summary=summary
        )
    
    def _should_scan_file(self, file_path: Path) -> bool:
        """Check if file should be scanned."""
        return file_path.suffix in self.supported_extensions
    
    def _find_source_files(self, directory: Path) -> List[Path]:
        """Find source files in directory."""
        files = []
        try:
            for item in directory.rglob('*'):
                if item.is_file() and self._should_scan_file(item):
                    # Skip common directories
                    if any(part in item.parts for part in ['node_modules', 'venv', '.git', '__pycache__']):
                        continue
                    files.append(item)
        except Exception as e:
            print(f"Warning: Error scanning directory {directory}: {e}")
        return files[:1000]  # Limit to prevent excessive scanning
    
    def _scan_file_simple(self, file_path: Path) -> List[Vulnerability]:
        """Scan a single file for vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            # Detect language
            language = self._detect_language(file_path)
            if not language:
                return vulnerabilities
            
            # Get patterns for this language
            lang_patterns = self.patterns.get(language, {})
            
            # Check RSA patterns
            for pattern in lang_patterns.get('rsa', []):
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    line_num = content[:match.start()].count('\n') + 1
                    
                    vulnerabilities.append(Vulnerability(
                        file_path=str(file_path),
                        line_number=line_num,
                        algorithm=CryptoAlgorithm.RSA,
                        severity=Severity.HIGH,
                        description=f"RSA cryptography detected in {language} (quantum-vulnerable)",
                        code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                        recommendation="Replace with ML-KEM (Kyber) for key exchange",
                        cwe_id="CWE-327"
                    ))
            
            # Check ECC patterns
            for pattern in lang_patterns.get('ecc', []):
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    line_num = content[:match.start()].count('\n') + 1
                    
                    vulnerabilities.append(Vulnerability(
                        file_path=str(file_path),
                        line_number=line_num,
                        algorithm=CryptoAlgorithm.ECC,
                        severity=Severity.HIGH,
                        description=f"ECC cryptography detected in {language} (quantum-vulnerable)",
                        code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                        recommendation="Replace with ML-DSA (Dilithium) for signatures",
                        cwe_id="CWE-327"
                    ))
            
            # Check import patterns
            for pattern in lang_patterns.get('imports', []):
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    line_num = content[:match.start()].count('\n') + 1
                    
                    vulnerabilities.append(Vulnerability(
                        file_path=str(file_path),
                        line_number=line_num,
                        algorithm=CryptoAlgorithm.RSA,  # Generic
                        severity=Severity.MEDIUM,
                        description=f"Quantum-vulnerable crypto import detected in {language}",
                        code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                        recommendation="Review imported cryptographic functions",
                        cwe_id="CWE-327"
                    ))
                        
        except Exception as e:
            print(f"Warning: Error scanning file {file_path}: {e}")
        
        return vulnerabilities
    
    def _detect_language(self, file_path: Path) -> Optional[str]:
        """Detect programming language from file extension."""
        ext_to_lang = {
            '.py': 'python',
            '.java': 'java', 
            '.go': 'go',
            '.js': 'javascript',
            '.ts': 'javascript',
            '.c': 'c',
            '.cpp': 'c'
        }
        return ext_to_lang.get(file_path.suffix)
    
    def print_simple_results(self, result: SimpleScanResult) -> None:
        """Print scan results in simple format."""
        print(f"\n📊 Simple PQC Scan Results")
        print(f"Files scanned: {result.files_scanned}")
        print(f"Scan time: {result.total_time:.2f}s")
        print(f"Total vulnerabilities: {result.summary['total']}")
        
        if result.summary['total'] > 0:
            print(f"\nSeverity breakdown:")
            for severity, count in result.summary.items():
                if severity != 'total' and count > 0:
                    print(f"  {severity.title()}: {count}")
            
            print(f"\n🚨 Found vulnerabilities:")
            for i, vuln in enumerate(result.vulnerabilities[:10], 1):  # Show first 10
                print(f"{i}. {Path(vuln.file_path).name}:{vuln.line_number} - {vuln.description}")
            
            if len(result.vulnerabilities) > 10:
                print(f"  ... and {len(result.vulnerabilities) - 10} more")
        else:
            print("✅ No quantum-vulnerable cryptography detected!")


def main():
    """Simple CLI for basic testing."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python simple_scanner.py <path_to_scan>")
        sys.exit(1)
    
    scanner = SimpleScanner()
    result = scanner.scan_simple(sys.argv[1])
    scanner.print_simple_results(result)


if __name__ == "__main__":
    main()