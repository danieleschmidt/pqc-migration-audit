"""PQC Migration Audit - Post-Quantum Cryptography Migration Tool."""

__version__ = "0.1.0"
__author__ = "Daniel Schmidt"
__email__ = "daniel@terragonlabs.com"

# Public API
from .core import CryptoAuditor, RiskAssessment, ScanResults, Vulnerability, Severity, CryptoAlgorithm
# CLI import commented out to avoid dependency issues during testing
# from .cli import main
try:
    from .services import MigrationService, CryptoInventoryService, ComplianceService
    from .reporters import JSONReporter, HTMLReporter, SARIFReporter, ConsoleReporter
except ImportError:
    # Some optional dependencies may not be available
    pass

__all__ = [
    "CryptoAuditor", 
    "RiskAssessment", 
    "ScanResults",
    "Vulnerability",
    "Severity",
    "CryptoAlgorithm",
    "main",
    "MigrationService",
    "CryptoInventoryService", 
    "ComplianceService",
    "JSONReporter",
    "HTMLReporter", 
    "SARIFReporter",
    "ConsoleReporter"
]