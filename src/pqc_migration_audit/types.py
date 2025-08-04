"""Shared types and data structures for PQC Migration Audit."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


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