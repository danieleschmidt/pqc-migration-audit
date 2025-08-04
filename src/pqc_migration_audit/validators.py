"""Input validation and security validation for PQC Migration Audit."""

import re
import os
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass
import hashlib
import tempfile
import subprocess
import json

from .types import ScanResults, Vulnerability, Severity


@dataclass
class ValidationResult:
    """Result of validation check."""
    is_valid: bool
    error_message: Optional[str] = None
    warnings: List[str] = None
    
    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []


class InputValidator:
    """Validates user inputs for security and correctness."""
    
    def __init__(self):
        """Initialize validator with security patterns."""
        self.dangerous_patterns = [
            r'[;&|`$()]',  # Shell injection patterns
            r'\.\./',       # Directory traversal
            r'\\\\',        # Windows path traversal
            r'<script',     # XSS patterns
            r'javascript:',  # JavaScript injection
            r'data:',       # Data URI
            r'file:',       # File URI
        ]
        
        self.max_path_length = 4096
        self.max_file_size = 100 * 1024 * 1024  # 100MB
        self.allowed_extensions = {
            '.py', '.java', '.go', '.js', '.ts', '.c', '.cpp', '.h', '.hpp',
            '.cs', '.php', '.rb', '.rs', '.kt', '.swift', '.jsx', '.tsx'
        }
    
    def validate_scan_path(self, path: Union[str, Path]) -> ValidationResult:
        """Validate scan path for security and existence.
        
        Args:
            path: Path to validate
            
        Returns:
            ValidationResult with validation status
        """
        try:
            path_str = str(path)
            
            # Check for dangerous patterns
            for pattern in self.dangerous_patterns:
                if re.search(pattern, path_str, re.IGNORECASE):
                    return ValidationResult(
                        is_valid=False,
                        error_message=f"Path contains potentially dangerous pattern: {pattern}"
                    )
            
            # Check path length
            if len(path_str) > self.max_path_length:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Path too long: {len(path_str)} > {self.max_path_length}"
                )
            
            # Convert to Path object for validation
            path_obj = Path(path_str).resolve()
            
            # Check if path exists
            if not path_obj.exists():
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Path does not exist: {path_obj}"
                )
            
            # Check if path is readable
            if not os.access(path_obj, os.R_OK):
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Path is not readable: {path_obj}"
                )
            
            # Check for suspicious paths
            warnings = []
            suspicious_dirs = ['system32', 'etc', 'boot', 'proc', 'sys']
            if any(suspect in path_str.lower() for suspect in suspicious_dirs):
                warnings.append(f"Scanning system directory: {path_obj}")
            
            return ValidationResult(
                is_valid=True,
                warnings=warnings
            )
            
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                error_message=f"Path validation error: {str(e)}"
            )
    
    def validate_file_for_scanning(self, file_path: Path) -> ValidationResult:
        """Validate individual file for safe scanning.
        
        Args:
            file_path: File to validate
            
        Returns:
            ValidationResult with validation status
        """
        try:
            # Check file existence and readability
            if not file_path.exists():
                return ValidationResult(
                    is_valid=False,
                    error_message=f"File does not exist: {file_path}"
                )
            
            if not file_path.is_file():
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Path is not a file: {file_path}"
                )
            
            if not os.access(file_path, os.R_OK):
                return ValidationResult(
                    is_valid=False,
                    error_message=f"File is not readable: {file_path}"
                )
            
            # Check file size
            file_size = file_path.stat().st_size
            if file_size > self.max_file_size:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"File too large: {file_size} > {self.max_file_size}"
                )
            
            # Check file extension
            if file_path.suffix.lower() not in self.allowed_extensions:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Unsupported file extension: {file_path.suffix}"
                )
            
            # Check for binary files (basic check)
            warnings = []
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    # Read first 1KB to check for binary content
                    sample = f.read(1024)
                    if '\x00' in sample:  # Null bytes indicate binary
                        warnings.append(f"File may be binary: {file_path}")
            except Exception:
                warnings.append(f"Could not read file for binary check: {file_path}")
            
            return ValidationResult(
                is_valid=True,
                warnings=warnings
            )
            
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                error_message=f"File validation error: {str(e)}"
            )
    
    def validate_output_path(self, output_path: Union[str, Path]) -> ValidationResult:
        """Validate output path for safe writing.
        
        Args:
            output_path: Output path to validate
            
        Returns:
            ValidationResult with validation status
        """
        try:
            path_obj = Path(output_path).resolve()
            
            # Check for dangerous patterns in path
            path_str = str(path_obj)
            for pattern in self.dangerous_patterns:
                if re.search(pattern, path_str, re.IGNORECASE):
                    return ValidationResult(
                        is_valid=False,
                        error_message=f"Output path contains dangerous pattern: {pattern}"
                    )
            
            # Check parent directory exists and is writable
            parent_dir = path_obj.parent
            if not parent_dir.exists():
                try:
                    parent_dir.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    return ValidationResult(
                        is_valid=False,
                        error_message=f"Cannot create parent directory: {str(e)}"
                    )
            
            if not os.access(parent_dir, os.W_OK):
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Parent directory not writable: {parent_dir}"
                )
            
            # Check if file already exists
            warnings = []
            if path_obj.exists():
                warnings.append(f"Output file will be overwritten: {path_obj}")
            
            return ValidationResult(
                is_valid=True,
                warnings=warnings
            )
            
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                error_message=f"Output path validation error: {str(e)}"
            )
    
    def validate_config_data(self, config_data: Dict[str, Any]) -> ValidationResult:
        """Validate configuration data for security.
        
        Args:
            config_data: Configuration dictionary
            
        Returns:
            ValidationResult with validation status
        """
        try:
            # Check for dangerous keys or values
            dangerous_keys = ['exec', 'eval', 'system', 'shell', 'command']
            
            def check_dict_recursive(data, path=""):
                warnings = []
                for key, value in data.items():
                    current_path = f"{path}.{key}" if path else key
                    
                    # Check for dangerous keys
                    if key.lower() in dangerous_keys:
                        warnings.append(f"Potentially dangerous config key: {current_path}")
                    
                    # Check string values for dangerous patterns
                    if isinstance(value, str):
                        for pattern in self.dangerous_patterns:
                            if re.search(pattern, value, re.IGNORECASE):
                                warnings.append(f"Dangerous pattern in config value: {current_path}")
                    
                    # Recursively check nested dictionaries
                    elif isinstance(value, dict):
                        warnings.extend(check_dict_recursive(value, current_path))
                
                return warnings
            
            warnings = check_dict_recursive(config_data)
            
            return ValidationResult(
                is_valid=True,
                warnings=warnings
            )
            
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                error_message=f"Config validation error: {str(e)}"
            )


class SecurityValidator:
    """Validates scan results and outputs for security issues."""
    
    def __init__(self):
        """Initialize security validator."""
        self.sensitive_patterns = [
            r'password\s*[=:]\s*["\']?[\w\-\.]+["\']?',
            r'api[_\-]?key\s*[=:]\s*["\']?[\w\-\.]+["\']?',
            r'secret\s*[=:]\s*["\']?[\w\-\.]+["\']?',
            r'token\s*[=:]\s*["\']?[\w\-\.]+["\']?',
            r'private[_\-]?key\s*[=:]\s*["\']?[\w\-\.]+["\']?',
        ]
    
    def validate_scan_results(self, results: ScanResults) -> ValidationResult:
        """Validate scan results for security issues.
        
        Args:
            results: Scan results to validate
            
        Returns:
            ValidationResult with validation status
        """
        try:
            warnings = []
            
            # Check for potential false positives
            if len(results.vulnerabilities) == 0:
                warnings.append("No vulnerabilities found - ensure scan patterns are comprehensive")
            
            # Check for suspicious file paths in results
            for vuln in results.vulnerabilities:
                if any(sensitive in vuln.file_path.lower() for sensitive in ['test', 'example', 'demo']):
                    warnings.append(f"Vulnerability found in test file: {vuln.file_path}")
                
                # Check code snippets for sensitive data
                for pattern in self.sensitive_patterns:
                    if re.search(pattern, vuln.code_snippet, re.IGNORECASE):
                        warnings.append(f"Code snippet may contain sensitive data: {vuln.file_path}:{vuln.line_number}")
            
            # Validate vulnerability data integrity
            for i, vuln in enumerate(results.vulnerabilities):
                if not vuln.file_path or not vuln.description:
                    return ValidationResult(
                        is_valid=False,
                        error_message=f"Incomplete vulnerability data at index {i}"
                    )
                
                if vuln.line_number < 1:
                    warnings.append(f"Invalid line number in vulnerability: {vuln.file_path}")
            
            return ValidationResult(
                is_valid=True,
                warnings=warnings
            )
            
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                error_message=f"Scan results validation error: {str(e)}"
            )
    
    def sanitize_output_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize output data to prevent information disclosure.
        
        Args:
            data: Data to sanitize
            
        Returns:
            Sanitized data dictionary
        """
        try:
            def sanitize_recursive(obj):
                if isinstance(obj, dict):
                    sanitized = {}
                    for key, value in obj.items():
                        # Remove or mask sensitive keys
                        if any(sensitive in key.lower() for sensitive in ['password', 'secret', 'key', 'token']):
                            sanitized[key] = "***REDACTED***"
                        else:
                            sanitized[key] = sanitize_recursive(value)
                    return sanitized
                elif isinstance(obj, list):
                    return [sanitize_recursive(item) for item in obj]
                elif isinstance(obj, str):
                    # Sanitize potential sensitive data in strings
                    sanitized_str = obj
                    for pattern in self.sensitive_patterns:
                        sanitized_str = re.sub(pattern, "[SENSITIVE_DATA_REDACTED]", sanitized_str, flags=re.IGNORECASE)
                    return sanitized_str
                else:
                    return obj
            
            return sanitize_recursive(data)
            
        except Exception:
            # If sanitization fails, return empty dict for safety
            return {"error": "Data sanitization failed"}
    
    def validate_patch_content(self, patch_content: str) -> ValidationResult:
        """Validate patch content for security issues.
        
        Args:
            patch_content: Patch content to validate
            
        Returns:
            ValidationResult with validation status
        """
        try:
            warnings = []
            
            # Check for dangerous code patterns in patches
            dangerous_patch_patterns = [
                r'eval\s*\(',
                r'exec\s*\(',
                r'system\s*\(',
                r'shell_exec\s*\(',
                r'passthru\s*\(',
                r'__import__\s*\(',
                r'subprocess\.',
                r'os\.system',
            ]
            
            for pattern in dangerous_patch_patterns:
                if re.search(pattern, patch_content, re.IGNORECASE):
                    warnings.append(f"Patch contains potentially dangerous code: {pattern}")
            
            # Check for hardcoded credentials
            for pattern in self.sensitive_patterns:
                if re.search(pattern, patch_content, re.IGNORECASE):
                    return ValidationResult(
                        is_valid=False,
                        error_message="Patch contains hardcoded sensitive data"
                    )
            
            # Check patch structure
            if len(patch_content.strip()) == 0:
                return ValidationResult(
                    is_valid=False,
                    error_message="Patch content is empty"
                )
            
            return ValidationResult(
                is_valid=True,
                warnings=warnings
            )
            
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                error_message=f"Patch validation error: {str(e)}"
            )


class FileIntegrityValidator:
    """Validates file integrity and detects tampering."""
    
    def __init__(self):
        """Initialize file integrity validator."""
        self.hash_algorithm = hashlib.sha256
    
    def calculate_file_hash(self, file_path: Path) -> str:
        """Calculate hash of file for integrity checking.
        
        Args:
            file_path: Path to file
            
        Returns:
            Hex digest of file hash
        """
        try:
            hasher = self.hash_algorithm()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return ""
    
    def validate_scan_integrity(self, scan_results: ScanResults,
                               expected_file_hashes: Optional[Dict[str, str]] = None) -> ValidationResult:
        """Validate integrity of scanned files.
        
        Args:
            scan_results: Results from scan
            expected_file_hashes: Expected file hashes if available
            
        Returns:
            ValidationResult with integrity status
        """
        try:
            warnings = []
            
            # Check if files still exist and are readable
            for vuln in scan_results.vulnerabilities:
                file_path = Path(vuln.file_path)
                if not file_path.exists():
                    warnings.append(f"Scanned file no longer exists: {file_path}")
                    continue
                
                # Check file hash if expected hashes provided
                if expected_file_hashes and str(file_path) in expected_file_hashes:
                    current_hash = self.calculate_file_hash(file_path)
                    expected_hash = expected_file_hashes[str(file_path)]
                    
                    if current_hash != expected_hash:
                        warnings.append(f"File modified since scan: {file_path}")
            
            return ValidationResult(
                is_valid=True,
                warnings=warnings
            )
            
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                error_message=f"Integrity validation error: {str(e)}"
            )
    
    def create_scan_manifest(self, scan_results: ScanResults) -> Dict[str, Any]:
        """Create manifest of scanned files with hashes.
        
        Args:
            scan_results: Results from scan
            
        Returns:
            Manifest dictionary with file hashes and metadata
        """
        try:
            manifest = {
                "scan_timestamp": scan_results.timestamp,
                "scan_path": scan_results.scan_path,
                "files": {}
            }
            
            # Get unique file paths from vulnerabilities
            file_paths = set(vuln.file_path for vuln in scan_results.vulnerabilities)
            
            for file_path_str in file_paths:
                file_path = Path(file_path_str)
                if file_path.exists():
                    manifest["files"][file_path_str] = {
                        "hash": self.calculate_file_hash(file_path),
                        "size": file_path.stat().st_size,
                        "modified_time": file_path.stat().st_mtime
                    }
            
            return manifest
            
        except Exception:
            return {"error": "Failed to create scan manifest"}


class ComplianceValidator:
    """Validates compliance with security standards and regulations."""
    
    def __init__(self):
        """Initialize compliance validator."""
        self.compliance_frameworks = {
            "NIST": self._validate_nist_compliance,
            "ISO27001": self._validate_iso27001_compliance,
            "SOC2": self._validate_soc2_compliance,
            "GDPR": self._validate_gdpr_compliance
        }
    
    def validate_compliance(self, scan_results: ScanResults, 
                          framework: str = "NIST") -> ValidationResult:
        """Validate compliance with specified framework.
        
        Args:
            scan_results: Scan results to validate
            framework: Compliance framework to validate against
            
        Returns:
            ValidationResult with compliance status
        """
        try:
            if framework not in self.compliance_frameworks:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Unknown compliance framework: {framework}"
                )
            
            validator = self.compliance_frameworks[framework]
            return validator(scan_results)
            
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                error_message=f"Compliance validation error: {str(e)}"
            )
    
    def _validate_nist_compliance(self, scan_results: ScanResults) -> ValidationResult:
        """Validate NIST Cybersecurity Framework compliance."""
        warnings = []
        
        # Check for quantum-readiness per NIST guidelines
        critical_vulns = [v for v in scan_results.vulnerabilities if v.severity.value == 'critical']
        if critical_vulns:
            warnings.append(f"NIST: {len(critical_vulns)} critical quantum vulnerabilities require immediate attention")
        
        # Check for crypto inventory completeness
        if len(scan_results.vulnerabilities) == 0:
            warnings.append("NIST: Cryptographic inventory may be incomplete")
        
        return ValidationResult(is_valid=True, warnings=warnings)
    
    def _validate_iso27001_compliance(self, scan_results: ScanResults) -> ValidationResult:
        """Validate ISO 27001 compliance."""
        warnings = []
        
        # ISO 27001 requires risk assessment and management
        high_risk_vulns = [v for v in scan_results.vulnerabilities 
                          if v.severity.value in ['critical', 'high']]
        if high_risk_vulns:
            warnings.append(f"ISO27001: {len(high_risk_vulns)} high-risk vulnerabilities need risk treatment")
        
        return ValidationResult(is_valid=True, warnings=warnings)
    
    def _validate_soc2_compliance(self, scan_results: ScanResults) -> ValidationResult:
        """Validate SOC 2 compliance."""
        warnings = []
        
        # SOC 2 requires security monitoring and controls
        if len(scan_results.vulnerabilities) > 0:
            warnings.append("SOC2: Security vulnerabilities detected - ensure monitoring controls are in place")
        
        return ValidationResult(is_valid=True, warnings=warnings)
    
    def _validate_gdpr_compliance(self, scan_results: ScanResults) -> ValidationResult:
        """Validate GDPR compliance."""
        warnings = []
        
        # GDPR requires protection of personal data
        crypto_vulns = len(scan_results.vulnerabilities)
        if crypto_vulns > 0:
            warnings.append(f"GDPR: {crypto_vulns} cryptographic vulnerabilities may impact data protection")
        
        return ValidationResult(is_valid=True, warnings=warnings)