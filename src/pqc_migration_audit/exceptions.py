"""Custom exceptions for PQC Migration Audit."""

from typing import Optional, List, Any


class PQCAuditException(Exception):
    """Base exception for PQC audit errors."""
    
    def __init__(self, message: str, error_code: Optional[str] = None, 
                 details: Optional[dict] = None):
        """Initialize exception with message and optional details.
        
        Args:
            message: Error message
            error_code: Optional error code for categorization
            details: Optional dictionary with additional error details
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}


class ScanException(PQCAuditException):
    """Exception raised during scanning operations."""
    pass


class ValidationException(PQCAuditException):
    """Exception raised during validation operations."""
    pass


class SecurityException(PQCAuditException):
    """Exception raised for security-related issues."""
    pass


class FileSystemException(PQCAuditException):
    """Exception raised for file system related errors."""
    pass


class ConfigurationException(PQCAuditException):
    """Exception raised for configuration errors."""
    pass


class PatchGenerationException(PQCAuditException):
    """Exception raised during patch generation."""
    pass


class ReportGenerationException(PQCAuditException):
    """Exception raised during report generation."""
    pass


class DatabaseException(PQCAuditException):
    """Exception raised for database operations."""
    pass


class ComplianceException(PQCAuditException):
    """Exception raised for compliance validation errors."""
    pass


class DashboardException(PQCAuditException):
    """Exception raised during dashboard generation."""
    pass


# Specific error types for better handling

class PathTraversalException(SecurityException):
    """Exception for path traversal attempts."""
    
    def __init__(self, path: str):
        super().__init__(
            f"Path traversal attempt detected: {path}",
            error_code="PATH_TRAVERSAL",
            details={"attempted_path": path}
        )


class UnsupportedFileTypeException(ValidationException):
    """Exception for unsupported file types."""
    
    def __init__(self, file_path: str, file_extension: str):
        super().__init__(
            f"Unsupported file type: {file_extension} in {file_path}",
            error_code="UNSUPPORTED_FILE_TYPE",
            details={"file_path": file_path, "extension": file_extension}
        )


class FileTooLargeException(ValidationException):
    """Exception for files that are too large to process."""
    
    def __init__(self, file_path: str, file_size: int, max_size: int):
        super().__init__(
            f"File too large: {file_path} ({file_size} bytes > {max_size} bytes)",
            error_code="FILE_TOO_LARGE",
            details={"file_path": file_path, "size": file_size, "max_size": max_size}
        )


class InsufficientPermissionsException(FileSystemException):
    """Exception for insufficient file system permissions."""
    
    def __init__(self, path: str, operation: str):
        super().__init__(
            f"Insufficient permissions for {operation} on: {path}",
            error_code="INSUFFICIENT_PERMISSIONS",
            details={"path": path, "operation": operation}
        )


class MaliciousContentException(SecurityException):
    """Exception for detected malicious content."""
    
    def __init__(self, file_path: str, pattern: str):
        super().__init__(
            f"Malicious content pattern detected in: {file_path}",
            error_code="MALICIOUS_CONTENT",
            details={"file_path": file_path, "pattern": pattern}
        )


class ScanTimeoutException(ScanException):
    """Exception for scan operations that timeout."""
    
    def __init__(self, timeout_seconds: int, files_processed: int):
        super().__init__(
            f"Scan timed out after {timeout_seconds} seconds (processed {files_processed} files)",
            error_code="SCAN_TIMEOUT",
            details={"timeout": timeout_seconds, "files_processed": files_processed}
        )


class CorruptedDataException(ValidationException):
    """Exception for corrupted or invalid data."""
    
    def __init__(self, data_type: str, validation_error: str):
        super().__init__(
            f"Corrupted {data_type}: {validation_error}",
            error_code="CORRUPTED_DATA",
            details={"data_type": data_type, "validation_error": validation_error}
        )


class NetworkException(PQCAuditException):
    """Exception for network-related errors."""
    
    def __init__(self, operation: str, endpoint: Optional[str] = None, 
                 status_code: Optional[int] = None):
        message = f"Network error during {operation}"
        if endpoint:
            message += f" to {endpoint}"
        if status_code:
            message += f" (HTTP {status_code})"
            
        super().__init__(
            message,
            error_code="NETWORK_ERROR",
            details={"operation": operation, "endpoint": endpoint, "status_code": status_code}
        )


class ResourceExhaustedException(PQCAuditException):
    """Exception for resource exhaustion."""
    
    def __init__(self, resource_type: str, limit: Any, current: Any):
        super().__init__(
            f"{resource_type} limit exceeded: {current} > {limit}",
            error_code="RESOURCE_EXHAUSTED",
            details={"resource_type": resource_type, "limit": limit, "current": current}
        )


class CriticalVulnerabilityException(ScanException):
    """Exception for critical vulnerabilities that require immediate attention."""
    
    def __init__(self, vulnerability_count: int, critical_files: List[str]):
        super().__init__(
            f"Critical vulnerabilities detected: {vulnerability_count} vulnerabilities in {len(critical_files)} files",
            error_code="CRITICAL_VULNERABILITIES",
            details={"count": vulnerability_count, "files": critical_files}
        )


class PQCLibraryException(PQCAuditException):
    """Exception for PQC library related errors."""
    
    def __init__(self, library_name: str, operation: str, error_details: str):
        super().__init__(
            f"PQC library error in {library_name} during {operation}: {error_details}",
            error_code="PQC_LIBRARY_ERROR",
            details={"library": library_name, "operation": operation, "error": error_details}
        )


class HashMismatchException(ValidationException):
    """Exception for file hash mismatches indicating potential tampering."""
    
    def __init__(self, file_path: str, expected_hash: str, actual_hash: str):
        super().__init__(
            f"File hash mismatch for {file_path}: expected {expected_hash[:16]}..., got {actual_hash[:16]}...",
            error_code="HASH_MISMATCH",
            details={"file_path": file_path, "expected": expected_hash, "actual": actual_hash}
        )


class ComplianceViolationException(ComplianceException):
    """Exception for compliance framework violations."""
    
    def __init__(self, framework: str, violation_type: str, requirements: List[str]):
        super().__init__(
            f"{framework} compliance violation: {violation_type}",
            error_code="COMPLIANCE_VIOLATION",
            details={"framework": framework, "violation": violation_type, "requirements": requirements}
        )


class QuantumThreatException(PQCAuditException):
    """Exception for quantum threat related issues."""
    
    def __init__(self, threat_level: str, affected_algorithms: List[str], 
                 estimated_years_remaining: Optional[int] = None):
        message = f"Quantum threat level {threat_level} detected for algorithms: {', '.join(affected_algorithms)}"
        if estimated_years_remaining:
            message += f" (estimated {estimated_years_remaining} years until quantum threat)"
            
        super().__init__(
            message,
            error_code="QUANTUM_THREAT",
            details={
                "threat_level": threat_level,
                "algorithms": affected_algorithms,
                "years_remaining": estimated_years_remaining
            }
        )


class PerformanceException(PQCAuditException):
    """Exception for performance-related issues."""
    pass


# Exception handler utility class

class ExceptionHandler:
    """Utility class for handling and logging exceptions."""
    
    @staticmethod
    def handle_scan_exception(func):
        """Decorator for handling scan exceptions."""
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if isinstance(e, PQCAuditException):
                    raise
                else:
                    raise ScanException(
                        f"Unexpected error in {func.__name__}: {str(e)}",
                        error_code="UNEXPECTED_SCAN_ERROR",
                        details={"function": func.__name__, "original_error": str(e)}
                    )
        return wrapper
    
    @staticmethod
    def handle_validation_exception(func):
        """Decorator for handling validation exceptions."""
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if isinstance(e, PQCAuditException):
                    raise
                else:
                    raise ValidationException(
                        f"Validation error in {func.__name__}: {str(e)}",
                        error_code="VALIDATION_ERROR",
                        details={"function": func.__name__, "original_error": str(e)}
                    )
        return wrapper
    
    @staticmethod
    def handle_security_exception(func):
        """Decorator for handling security exceptions."""
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if isinstance(e, SecurityException):
                    raise
                else:
                    raise SecurityException(
                        f"Security error in {func.__name__}: {str(e)}",
                        error_code="SECURITY_ERROR",
                        details={"function": func.__name__, "original_error": str(e)}
                    )
        return wrapper
    
    @staticmethod
    def create_error_context(exception: PQCAuditException) -> dict:
        """Create error context for logging and reporting.
        
        Args:
            exception: PQC audit exception
            
        Returns:
            Dictionary with error context information
        """
        return {
            "error_type": type(exception).__name__,
            "error_code": exception.error_code,
            "message": exception.message,
            "details": exception.details,
            "severity": ExceptionHandler._get_severity(exception)
        }
    
    @staticmethod
    def _get_severity(exception: PQCAuditException) -> str:
        """Get severity level for exception type."""
        severity_map = {
            SecurityException: "CRITICAL",
            PathTraversalException: "CRITICAL",
            MaliciousContentException: "CRITICAL",
            CriticalVulnerabilityException: "HIGH",
            QuantumThreatException: "HIGH",
            ComplianceViolationException: "MEDIUM",
            ValidationException: "MEDIUM",
            ScanException: "LOW",
            ConfigurationException: "LOW"
        }
        
        for exception_type, severity in severity_map.items():
            if isinstance(exception, exception_type):
                return severity
        
        return "MEDIUM"  # Default severity