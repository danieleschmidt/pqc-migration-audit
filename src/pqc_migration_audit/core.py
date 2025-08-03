"""Core functionality for cryptographic auditing."""

import os
import re
import ast
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, NamedTuple
from dataclasses import dataclass, field
from enum import Enum
import json


class Severity(Enum):
    """Vulnerability severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CryptoAlgorithm(Enum):
    """Quantum-vulnerable cryptographic algorithms."""
    RSA = "RSA"
    ECC = "ECC"
    DSA = "DSA"
    DH = "Diffie-Hellman"
    ECDSA = "ECDSA"
    ECDH = "ECDH"


@dataclass
class Vulnerability:
    """Represents a quantum-vulnerable cryptographic finding."""
    file_path: str
    line_number: int
    algorithm: CryptoAlgorithm
    severity: Severity
    key_size: Optional[int] = None
    description: str = ""
    code_snippet: str = ""
    recommendation: str = ""
    cwe_id: Optional[str] = None


@dataclass
class ScanResults:
    """Results from a cryptographic audit scan."""
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scanned_files: int = 0
    total_lines: int = 0
    scan_time: float = 0.0
    scan_path: str = ""
    timestamp: str = ""
    languages_detected: List[str] = field(default_factory=list)


class CryptoPatterns:
    """Cryptographic vulnerability patterns for different languages."""
    
    PYTHON_PATTERNS = {
        'rsa_generation': [
            r'rsa\.generate_private_key\s*\(',
            r'RSA\.generate\s*\(',
            r'Crypto\.PublicKey\.RSA\.generate\s*\(',
        ],
        'ecc_generation': [
            r'ec\.generate_private_key\s*\(',
            r'ECC\.generate\s*\(',
            r'ecdsa\.SigningKey\.generate\s*\(',
        ],
        'dsa_generation': [
            r'dsa\.generate_private_key\s*\(',
            r'DSA\.generate\s*\(',
        ],
        'diffie_hellman': [
            r'dh\.generate_private_key\s*\(',
            r'DiffieHellman\s*\(',
        ],
        'weak_key_sizes': [
            r'key_size\s*=\s*(512|1024)\b',
            r'bits\s*=\s*(512|1024)\b',
        ]
    }
    
    JAVA_PATTERNS = {
        'rsa_generation': [
            r'KeyPairGenerator\.getInstance\s*\(\s*["\']RSA["\']',
            r'RSAKeyGenParameterSpec\s*\(',
        ],
        'ecc_generation': [
            r'KeyPairGenerator\.getInstance\s*\(\s*["\']EC["\']',
            r'ECGenParameterSpec\s*\(',
        ],
        'dsa_generation': [
            r'KeyPairGenerator\.getInstance\s*\(\s*["\']DSA["\']',
        ]
    }
    
    GO_PATTERNS = {
        'rsa_generation': [
            r'rsa\.GenerateKey\s*\(',
            r'rsa\.GenerateMultiPrimeKey\s*\(',
        ],
        'ecdsa_generation': [
            r'ecdsa\.GenerateKey\s*\(',
        ]
    }


class CryptoAuditor:
    """Main auditor class for scanning cryptographic vulnerabilities."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the crypto auditor.
        
        Args:
            config: Configuration options for the auditor
        """
        self.config = config or {}
        self.supported_extensions = {
            '.py': 'python',
            '.java': 'java',
            '.go': 'go',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.c': 'c',
            '.cpp': 'cpp',
            '.h': 'c',
            '.hpp': 'cpp'
        }
        self.patterns = CryptoPatterns()

    def scan_directory(self, path: str, **kwargs) -> ScanResults:
        """Scan a directory for quantum-vulnerable cryptography.
        
        Args:
            path: Directory path to scan
            **kwargs: Additional scanning options
            
        Returns:
            ScanResults containing vulnerabilities and metadata
        """
        start_time = time.time()
        results = ScanResults(
            scan_path=path,
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
        )
        
        path_obj = Path(path)
        if not path_obj.exists():
            raise FileNotFoundError(f"Path does not exist: {path}")
        
        exclude_patterns = kwargs.get('exclude_patterns', [
            '*/node_modules/*', '*/venv/*', '*/build/*', '*/dist/*',
            '*/.git/*', '*/tests/*', '*/test/*'
        ])
        
        languages_found = set()
        
        for file_path in self._find_source_files(path_obj, exclude_patterns):
            language = self._detect_language(file_path)
            if language:
                languages_found.add(language)
                file_vulnerabilities = self._scan_file(file_path, language)
                results.vulnerabilities.extend(file_vulnerabilities)
                results.scanned_files += 1
                
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    results.total_lines += len(f.readlines())
        
        results.languages_detected = list(languages_found)
        results.scan_time = time.time() - start_time
        
        return results

    def _find_source_files(self, path: Path, exclude_patterns: List[str]) -> List[Path]:
        """Find source code files to scan.
        
        Args:
            path: Directory path to search
            exclude_patterns: Patterns to exclude from scanning
            
        Returns:
            List of source file paths
        """
        files = []
        
        if path.is_file():
            if self._should_scan_file(path, exclude_patterns):
                files.append(path)
        else:
            for file_path in path.rglob('*'):
                if file_path.is_file() and self._should_scan_file(file_path, exclude_patterns):
                    files.append(file_path)
        
        return files

    def _should_scan_file(self, file_path: Path, exclude_patterns: List[str]) -> bool:
        """Check if a file should be scanned.
        
        Args:
            file_path: Path to the file
            exclude_patterns: Patterns to exclude
            
        Returns:
            True if file should be scanned
        """
        if file_path.suffix not in self.supported_extensions:
            return False
            
        file_str = str(file_path)
        for pattern in exclude_patterns:
            pattern_regex = pattern.replace('*', '.*')
            if re.search(pattern_regex, file_str):
                return False
                
        return True

    def _detect_language(self, file_path: Path) -> Optional[str]:
        """Detect programming language from file extension.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Language name or None if not supported
        """
        return self.supported_extensions.get(file_path.suffix)

    def _scan_file(self, file_path: Path, language: str) -> List[Vulnerability]:
        """Scan a single file for cryptographic vulnerabilities.
        
        Args:
            file_path: Path to the file to scan
            language: Programming language of the file
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            if language == 'python':
                vulnerabilities.extend(self._scan_python_file(file_path, content, lines))
            elif language == 'java':
                vulnerabilities.extend(self._scan_java_file(file_path, content, lines))
            elif language == 'go':
                vulnerabilities.extend(self._scan_go_file(file_path, content, lines))
            
        except Exception as e:
            # Log error but continue scanning
            pass
            
        return vulnerabilities

    def _scan_python_file(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        """Scan Python file for cryptographic vulnerabilities."""
        vulnerabilities = []
        
        # RSA vulnerabilities
        for pattern in self.patterns.PYTHON_PATTERNS['rsa_generation']:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                severity, key_size = self._analyze_rsa_usage(lines[line_num - 1] if line_num <= len(lines) else "")
                
                vulnerabilities.append(Vulnerability(
                    file_path=str(file_path),
                    line_number=line_num,
                    algorithm=CryptoAlgorithm.RSA,
                    severity=severity,
                    key_size=key_size,
                    description=f"RSA key generation detected (quantum-vulnerable)",
                    code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    recommendation="Replace with ML-KEM (Kyber) for key exchange or ML-DSA (Dilithium) for signatures",
                    cwe_id="CWE-327"
                ))
        
        # ECC vulnerabilities
        for pattern in self.patterns.PYTHON_PATTERNS['ecc_generation']:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(Vulnerability(
                    file_path=str(file_path),
                    line_number=line_num,
                    algorithm=CryptoAlgorithm.ECC,
                    severity=Severity.HIGH,
                    description="ECC key generation detected (quantum-vulnerable)",
                    code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    recommendation="Replace with ML-DSA (Dilithium) for signatures or ML-KEM (Kyber) for key exchange",
                    cwe_id="CWE-327"
                ))
        
        # DSA vulnerabilities
        for pattern in self.patterns.PYTHON_PATTERNS['dsa_generation']:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(Vulnerability(
                    file_path=str(file_path),
                    line_number=line_num,
                    algorithm=CryptoAlgorithm.DSA,
                    severity=Severity.HIGH,
                    description="DSA key generation detected (quantum-vulnerable)",
                    code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    recommendation="Replace with ML-DSA (Dilithium) for digital signatures",
                    cwe_id="CWE-327"
                ))
        
        return vulnerabilities

    def _scan_java_file(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        """Scan Java file for cryptographic vulnerabilities."""
        vulnerabilities = []
        
        for pattern in self.patterns.JAVA_PATTERNS['rsa_generation']:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(Vulnerability(
                    file_path=str(file_path),
                    line_number=line_num,
                    algorithm=CryptoAlgorithm.RSA,
                    severity=Severity.HIGH,
                    description="RSA KeyPairGenerator detected (quantum-vulnerable)",
                    code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    recommendation="Migrate to post-quantum key exchange using ML-KEM (Kyber)",
                    cwe_id="CWE-327"
                ))
        
        return vulnerabilities

    def _scan_go_file(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        """Scan Go file for cryptographic vulnerabilities."""
        vulnerabilities = []
        
        for pattern in self.patterns.GO_PATTERNS['rsa_generation']:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(Vulnerability(
                    file_path=str(file_path),
                    line_number=line_num,
                    algorithm=CryptoAlgorithm.RSA,
                    severity=Severity.HIGH,
                    description="RSA key generation detected (quantum-vulnerable)",
                    code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    recommendation="Replace with post-quantum cryptography using liboqs Go bindings",
                    cwe_id="CWE-327"
                ))
        
        return vulnerabilities

    def _analyze_rsa_usage(self, code_line: str) -> Tuple[Severity, Optional[int]]:
        """Analyze RSA usage to determine severity and key size.
        
        Args:
            code_line: Line of code containing RSA usage
            
        Returns:
            Tuple of (severity, key_size)
        """
        # Look for key_size parameter
        key_size_match = re.search(r'key_size\s*=\s*(\d+)', code_line)
        if key_size_match:
            key_size = int(key_size_match.group(1))
            if key_size < 2048:
                return Severity.CRITICAL, key_size
            elif key_size < 4096:
                return Severity.HIGH, key_size
            else:
                return Severity.MEDIUM, key_size
        
        return Severity.HIGH, None

    def create_migration_plan(self, results: ScanResults) -> Dict[str, Any]:
        """Create a migration plan based on scan results.
        
        Args:
            results: Scan results containing vulnerabilities
            
        Returns:
            Migration plan with prioritized recommendations
        """
        plan = {
            "summary": {
                "total_vulnerabilities": len(results.vulnerabilities),
                "critical": len([v for v in results.vulnerabilities if v.severity == Severity.CRITICAL]),
                "high": len([v for v in results.vulnerabilities if v.severity == Severity.HIGH]),
                "medium": len([v for v in results.vulnerabilities if v.severity == Severity.MEDIUM]),
                "low": len([v for v in results.vulnerabilities if v.severity == Severity.LOW]),
            },
            "migration_phases": [
                {
                    "phase": 1,
                    "name": "Critical Vulnerabilities",
                    "description": "Address all critical and high-severity vulnerabilities",
                    "vulnerabilities": [v for v in results.vulnerabilities if v.severity in [Severity.CRITICAL, Severity.HIGH]],
                    "estimated_effort": "2-4 weeks"
                },
                {
                    "phase": 2,
                    "name": "Medium Priority Items",
                    "description": "Address medium-severity vulnerabilities",
                    "vulnerabilities": [v for v in results.vulnerabilities if v.severity == Severity.MEDIUM],
                    "estimated_effort": "1-2 weeks"
                },
                {
                    "phase": 3,
                    "name": "Cleanup and Optimization",
                    "description": "Address remaining low-severity items and optimize",
                    "vulnerabilities": [v for v in results.vulnerabilities if v.severity == Severity.LOW],
                    "estimated_effort": "1 week"
                }
            ],
            "recommendations": {
                "immediate_actions": [
                    "Inventory all cryptographic implementations",
                    "Prioritize customer-facing and critical system components",
                    "Begin testing PQC alternatives in development environment"
                ],
                "pqc_algorithms": {
                    "key_exchange": "ML-KEM (Kyber) - NIST standardized",
                    "digital_signatures": "ML-DSA (Dilithium) - NIST standardized",
                    "alternative_signatures": "SLH-DSA (SPHINCS+) - Hash-based signatures"
                },
                "migration_strategy": "Hybrid approach during transition period (2025-2027)"
            }
        }
        
        return plan


class RiskAssessment:
    """Risk assessment for quantum-vulnerable cryptography."""

    def __init__(self, scan_results: ScanResults):
        """Initialize risk assessment with scan results.
        
        Args:
            scan_results: Results from CryptoAuditor scan
        """
        self.results = scan_results

    def calculate_harvest_now_decrypt_later_risk(self) -> int:
        """Calculate HNDL (Harvest Now, Decrypt Later) risk score.
        
        Returns:
            Risk score from 0-100
        """
        if not self.results.vulnerabilities:
            return 0
        
        # Risk factors
        vulnerability_count = len(self.results.vulnerabilities)
        critical_count = len([v for v in self.results.vulnerabilities if v.severity == Severity.CRITICAL])
        high_count = len([v for v in self.results.vulnerabilities if v.severity == Severity.HIGH])
        
        # Algorithm-specific risk weights
        algorithm_weights = {
            CryptoAlgorithm.RSA: 0.8,  # High risk for RSA
            CryptoAlgorithm.ECC: 0.9,  # Higher risk for ECC (easier to break)
            CryptoAlgorithm.DSA: 0.7,
            CryptoAlgorithm.DH: 0.8,
            CryptoAlgorithm.ECDSA: 0.9,
            CryptoAlgorithm.ECDH: 0.9
        }
        
        # Calculate weighted algorithm risk
        algorithm_risk = 0
        for vuln in self.results.vulnerabilities:
            weight = algorithm_weights.get(vuln.algorithm, 0.5)
            if vuln.severity == Severity.CRITICAL:
                algorithm_risk += weight * 25
            elif vuln.severity == Severity.HIGH:
                algorithm_risk += weight * 15
            elif vuln.severity == Severity.MEDIUM:
                algorithm_risk += weight * 10
            else:
                algorithm_risk += weight * 5
        
        # Normalize to 0-100 scale
        base_risk = min(algorithm_risk, 100)
        
        # Apply time pressure factor (quantum threat timeline)
        # Assuming current year is 2025, with quantum threat by 2030
        timeline_factor = 1.2  # Increasing urgency
        
        final_risk = min(int(base_risk * timeline_factor), 100)
        
        return final_risk

    @property
    def migration_hours(self) -> int:
        """Estimate migration effort in hours.
        
        Returns:
            Estimated hours needed for migration
        """
        if not self.results.vulnerabilities:
            return 0
        
        # Base effort estimates per vulnerability type
        effort_map = {
            Severity.CRITICAL: 16,  # 2 days per critical
            Severity.HIGH: 8,       # 1 day per high
            Severity.MEDIUM: 4,     # Half day per medium
            Severity.LOW: 2         # Quarter day per low
        }
        
        total_hours = 0
        for vuln in self.results.vulnerabilities:
            total_hours += effort_map.get(vuln.severity, 2)
        
        # Add overhead for testing and integration (25%)
        total_hours = int(total_hours * 1.25)
        
        return total_hours

    def generate_risk_report(self) -> Dict[str, Any]:
        """Generate comprehensive risk assessment report.
        
        Returns:
            Risk assessment report
        """
        hndl_risk = self.calculate_harvest_now_decrypt_later_risk()
        
        report = {
            "risk_summary": {
                "hndl_risk_score": hndl_risk,
                "risk_level": self._get_risk_level(hndl_risk),
                "total_vulnerabilities": len(self.results.vulnerabilities),
                "migration_effort_hours": self.migration_hours,
                "scan_metadata": {
                    "files_scanned": self.results.scanned_files,
                    "lines_analyzed": self.results.total_lines,
                    "scan_duration": f"{self.results.scan_time:.2f}s",
                    "languages_detected": self.results.languages_detected
                }
            },
            "vulnerability_breakdown": {
                "by_severity": self._get_severity_breakdown(),
                "by_algorithm": self._get_algorithm_breakdown(),
                "by_file": self._get_file_breakdown()
            },
            "recommendations": self._generate_recommendations(hndl_risk)
        }
        
        return report

    def _get_risk_level(self, risk_score: int) -> str:
        """Convert numeric risk score to risk level."""
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 60:
            return "HIGH"
        elif risk_score >= 40:
            return "MEDIUM"
        elif risk_score >= 20:
            return "LOW"
        else:
            return "MINIMAL"

    def _get_severity_breakdown(self) -> Dict[str, int]:
        """Get vulnerability count by severity."""
        breakdown = {severity.value: 0 for severity in Severity}
        for vuln in self.results.vulnerabilities:
            breakdown[vuln.severity.value] += 1
        return breakdown

    def _get_algorithm_breakdown(self) -> Dict[str, int]:
        """Get vulnerability count by algorithm."""
        breakdown = {}
        for vuln in self.results.vulnerabilities:
            algo = vuln.algorithm.value
            breakdown[algo] = breakdown.get(algo, 0) + 1
        return breakdown

    def _get_file_breakdown(self) -> Dict[str, int]:
        """Get vulnerability count by file."""
        breakdown = {}
        for vuln in self.results.vulnerabilities:
            file_path = vuln.file_path
            breakdown[file_path] = breakdown.get(file_path, 0) + 1
        return breakdown

    def _generate_recommendations(self, risk_score: int) -> List[str]:
        """Generate recommendations based on risk score."""
        recommendations = [
            "Begin immediate inventory of all cryptographic implementations",
            "Establish PQC migration timeline with 2027 deadline",
            "Test ML-KEM (Kyber) and ML-DSA (Dilithium) in development environment"
        ]
        
        if risk_score >= 80:
            recommendations.extend([
                "URGENT: Address critical vulnerabilities within 30 days",
                "Implement crypto-agility framework immediately",
                "Consider hybrid classical+PQC approach for critical systems"
            ])
        elif risk_score >= 60:
            recommendations.extend([
                "Prioritize high-risk components for immediate attention",
                "Begin pilot PQC implementation in non-critical systems",
                "Establish regular security scanning in CI/CD pipeline"
            ])
        
        return recommendations