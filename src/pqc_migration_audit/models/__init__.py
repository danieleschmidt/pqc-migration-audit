"""Data models for PQC Migration Audit."""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum
import json


class MigrationStrategy(Enum):
    """Migration strategies for PQC transition."""
    IMMEDIATE = "immediate"
    HYBRID = "hybrid" 
    GRADUAL = "gradual"
    CUSTOM = "custom"


class PQCAlgorithm(Enum):
    """Post-quantum cryptographic algorithms."""
    ML_KEM_512 = "ML-KEM-512"  # Kyber-512
    ML_KEM_768 = "ML-KEM-768"  # Kyber-768  
    ML_KEM_1024 = "ML-KEM-1024"  # Kyber-1024
    ML_DSA_44 = "ML-DSA-44"    # Dilithium2
    ML_DSA_65 = "ML-DSA-65"    # Dilithium3
    ML_DSA_87 = "ML-DSA-87"    # Dilithium5
    SLH_DSA_128S = "SLH-DSA-128s"  # SPHINCS+-128s-simple
    SLH_DSA_128F = "SLH-DSA-128f"  # SPHINCS+-128f-simple
    SLH_DSA_192S = "SLH-DSA-192s"  # SPHINCS+-192s-simple
    SLH_DSA_192F = "SLH-DSA-192f"  # SPHINCS+-192f-simple
    SLH_DSA_256S = "SLH-DSA-256s"  # SPHINCS+-256s-simple
    SLH_DSA_256F = "SLH-DSA-256f"  # SPHINCS+-256f-simple


@dataclass
class MigrationRecommendation:
    """Recommendation for migrating a specific vulnerability."""
    vulnerability_id: str
    current_algorithm: str
    recommended_algorithm: PQCAlgorithm
    strategy: MigrationStrategy
    priority: int  # 1-10, 10 being highest
    estimated_effort_hours: int
    dependencies: List[str] = field(default_factory=list)
    notes: str = ""
    code_example: str = ""


@dataclass
class CryptoInventoryItem:
    """Item in cryptographic inventory."""
    name: str
    version: str
    location: str
    algorithms: List[str]
    key_sizes: List[int]
    usage_context: str
    pqc_ready: bool = False
    migration_priority: str = "medium"
    last_updated: str = ""


@dataclass
class SBOMCryptoComponent:
    """Cryptographic component in Software Bill of Materials."""
    component_name: str
    version: str
    supplier: str
    algorithms_used: List[str]
    quantum_vulnerable: bool
    pqc_alternatives: List[str] = field(default_factory=list)
    license: str = ""
    vulnerabilities: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "component_name": self.component_name,
            "version": self.version,
            "supplier": self.supplier,
            "algorithms_used": self.algorithms_used,
            "quantum_vulnerable": self.quantum_vulnerable,
            "pqc_alternatives": self.pqc_alternatives,
            "license": self.license,
            "vulnerabilities": self.vulnerabilities
        }


@dataclass
class ComplianceMetrics:
    """Compliance metrics for regulatory frameworks."""
    framework: str  # e.g., "NIST", "BSI", "ANSSI"
    compliance_percentage: float
    requirements_met: List[str]
    requirements_pending: List[str]
    deadline: str
    risk_level: str


@dataclass
class PerformanceMetrics:
    """Performance metrics for PQC implementations."""
    algorithm: str
    key_generation_time_ms: float
    encryption_time_ms: float
    decryption_time_ms: float
    signature_time_ms: Optional[float] = None
    verification_time_ms: Optional[float] = None
    public_key_size_bytes: int = 0
    private_key_size_bytes: int = 0
    signature_size_bytes: Optional[int] = None
    ciphertext_overhead_factor: float = 1.0


__all__ = [
    "MigrationStrategy",
    "PQCAlgorithm", 
    "MigrationRecommendation",
    "CryptoInventoryItem",
    "SBOMCryptoComponent",
    "ComplianceMetrics",
    "PerformanceMetrics"
]