"""Vulnerability analyzers for different cryptographic algorithms."""

from typing import List
from dataclasses import dataclass

from .types import Vulnerability, CryptoAlgorithm, Severity


@dataclass
class AnalyzerResult:
    """Result from vulnerability analysis."""
    vulnerabilities: List[Vulnerability]
    metadata: dict


class BaseAnalyzer:
    """Base class for crypto vulnerability analyzers."""
    
    def analyze(self, findings: List) -> List[Vulnerability]:
        """Analyze findings and return vulnerabilities."""
        raise NotImplementedError


class RSAAnalyzer(BaseAnalyzer):
    """Analyzer for RSA-related vulnerabilities."""
    
    def analyze(self, findings: List) -> List[Vulnerability]:
        """Analyze RSA findings for vulnerabilities."""
        vulnerabilities = []
        
        for finding in findings:
            if hasattr(finding, 'algorithm') and finding.algorithm == "RSA":
                # Determine severity based on key size if available
                severity = self._assess_rsa_severity(finding)
                
                vulnerability = Vulnerability(
                    file_path=finding.file_path,
                    line_number=finding.line_number,
                    algorithm=CryptoAlgorithm.RSA,
                    severity=severity,
                    description="RSA cryptography detected (quantum-vulnerable)",
                    code_snippet=getattr(finding, 'context', ''),
                    recommendation="Replace with ML-KEM (Kyber) for key exchange or ML-DSA (Dilithium) for signatures",
                    cwe_id="CWE-327"
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _assess_rsa_severity(self, finding) -> Severity:
        """Assess RSA vulnerability severity based on key size."""
        if hasattr(finding, 'key_size'):
            key_size = finding.key_size
            if key_size < 2048:
                return Severity.CRITICAL
            elif key_size < 3072:
                return Severity.HIGH
            elif key_size < 4096:
                return Severity.MEDIUM
            else:
                return Severity.LOW
        
        # Check context for key size
        if hasattr(finding, 'context'):
            context = finding.context.lower()
            if '1024' in context:
                return Severity.CRITICAL
            elif '2048' in context:
                return Severity.HIGH
            elif '3072' in context:
                return Severity.MEDIUM
            elif '4096' in context:
                return Severity.LOW
        
        return Severity.HIGH  # Default for RSA


class ECCAnalyzer(BaseAnalyzer):
    """Analyzer for ECC-related vulnerabilities."""
    
    def analyze(self, findings: List) -> List[Vulnerability]:
        """Analyze ECC findings for vulnerabilities."""
        vulnerabilities = []
        
        for finding in findings:
            if hasattr(finding, 'algorithm') and finding.algorithm == "ECC":
                # Check if this is a quantum-vulnerable curve
                if self._is_vulnerable_curve(finding):
                    vulnerability = Vulnerability(
                        file_path=finding.file_path,
                        line_number=finding.line_number,
                        algorithm=CryptoAlgorithm.ECC,
                        severity=Severity.HIGH,
                        description="ECC cryptography detected (quantum-vulnerable)",
                        code_snippet=getattr(finding, 'context', ''),
                        recommendation="Replace with ML-DSA (Dilithium) for signatures or ML-KEM (Kyber) for key exchange",
                        cwe_id="CWE-327"
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _is_vulnerable_curve(self, finding) -> bool:
        """Check if ECC curve is quantum-vulnerable."""
        vulnerable_curves = ['SECP256R1', 'SECP384R1', 'SECP521R1', 'P-256', 'P-384', 'P-521']
        
        if hasattr(finding, 'curve'):
            return finding.curve in vulnerable_curves
        
        if hasattr(finding, 'context'):
            context = finding.context.upper()
            return any(curve in context for curve in vulnerable_curves)
        
        # Default to vulnerable for ECC patterns
        return True