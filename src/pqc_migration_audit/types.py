"""Shared types and data structures for PQC Migration Audit."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any


class Severity(Enum):
    """Vulnerability severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CryptoAlgorithm(Enum):
    """Quantum-vulnerable cryptographic algorithms."""
    RSA = "rsa"
    ECC = "ecc"
    DSA = "dsa"
    DH = "dh"
    ECDSA = "ecdsa"
    ECDH = "ecdh"


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
class ScanStats:
    """Statistics from scan execution."""
    files_processed: int = 0
    files_skipped: int = 0
    errors_encountered: int = 0
    vulnerabilities_found: int = 0
    scan_start_time: Optional[float] = None
    performance_metrics: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ValidationResult:
    """Result of validation operations."""
    is_valid: bool = True
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)


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
    metadata: Dict[str, Any] = field(default_factory=dict)
    scan_stats: Optional['ScanStats'] = None