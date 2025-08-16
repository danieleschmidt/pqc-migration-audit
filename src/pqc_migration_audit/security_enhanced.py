"""Enhanced security features for PQC Migration Audit."""

import hashlib
import hmac
import os
import json
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
from contextlib import contextmanager

from .exceptions import SecurityException, ValidationException
from .logging_config import get_logger


class SecurityLevel(Enum):
    """Security validation levels."""
    BASIC = "basic"
    ENHANCED = "enhanced"
    PARANOID = "paranoid"


class ThreatLevel(Enum):
    """Threat assessment levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityEvent:
    """Security event record."""
    event_type: str
    threat_level: ThreatLevel
    timestamp: float
    details: Dict[str, Any] = field(default_factory=dict)
    source: str = ""
    remediation: str = ""


class SecurityMonitor:
    """Real-time security monitoring for scan operations."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize security monitor.
        
        Args:
            config: Security configuration
        """
        self.config = config or {}
        self.logger = get_logger('pqc_audit.security')
        self.security_level = SecurityLevel(self.config.get('security_level', 'enhanced'))
        self.enable_threat_detection = self.config.get('enable_threat_detection', True)
        self.enable_integrity_checks = self.config.get('enable_integrity_checks', True)
        self.enable_anomaly_detection = self.config.get('enable_anomaly_detection', False)
        
        # Security state
        self.security_events: List[SecurityEvent] = []
        self.scan_checksums: Dict[str, str] = {}
        self.suspicious_patterns: List[str] = []
        self.baseline_metrics: Dict[str, float] = {}
        
        self._initialize_security_patterns()
    
    def _initialize_security_patterns(self):
        """Initialize security threat patterns."""
        self.suspicious_patterns = [
            # Potential malicious code patterns
            r'exec\s*\(',
            r'eval\s*\(',
            r'__import__\s*\(',
            r'subprocess\.',
            r'os\.system',
            r'pickle\.loads',
            
            # Potential data exfiltration
            r'requests\.post.*data',
            r'urllib.*data',
            r'socket\.send',
            r'base64\.b64encode',
            
            # Potential credential harvesting
            r'input.*password',
            r'getpass\.',
            r'keyring\.',
            
            # Suspicious file operations
            r'os\.remove.*\*',
            r'shutil\.rmtree',
            r'open.*\/etc\/passwd',
            r'open.*\/etc\/shadow',
        ]
    
    @contextmanager
    def secure_scan_context(self, scan_path: str):
        """Secure context manager for scan operations.
        
        Args:
            scan_path: Path being scanned
        """
        # Pre-scan security checks
        self._validate_scan_path(scan_path)
        self._calculate_baseline_checksum(scan_path)
        
        start_time = time.time()
        scan_id = self._generate_scan_id(scan_path)
        
        self.logger.log_security_event('scan_start', {
            'scan_id': scan_id,
            'scan_path': scan_path,
            'security_level': self.security_level.value,
            'timestamp': start_time
        })
        
        try:
            yield scan_id
            
            # Post-scan security validation
            self._validate_scan_integrity(scan_path)
            self._detect_anomalies(scan_path, time.time() - start_time)
            
            self.logger.log_security_event('scan_complete', {
                'scan_id': scan_id,
                'scan_path': scan_path,
                'duration': time.time() - start_time,
                'status': 'success'
            })
            
        except Exception as e:
            self.logger.log_security_event('scan_error', {
                'scan_id': scan_id,
                'scan_path': scan_path,
                'error': str(e),
                'status': 'failed'
            })
            raise
    
    def _validate_scan_path(self, scan_path: str):
        """Validate scan path for security threats.
        
        Args:
            scan_path: Path to validate
            
        Raises:
            SecurityException: If path is potentially dangerous
        """
        path_obj = Path(scan_path).resolve()
        
        # Check for dangerous paths
        dangerous_paths = [
            '/etc', '/sys', '/proc', '/dev', '/root',
            '/usr/bin', '/usr/sbin', '/sbin', '/bin'
        ]
        
        for dangerous in dangerous_paths:
            if str(path_obj).startswith(dangerous):
                raise SecurityException(
                    f"Scanning system directory '{dangerous}' is not allowed",
                    error_code="DANGEROUS_PATH",
                    details={"path": str(path_obj), "matched_pattern": dangerous}
                )
        
        # Check for symlink attacks
        if path_obj.is_symlink():
            target = path_obj.readlink()
            if target.is_absolute() and not str(target).startswith(str(path_obj.parent)):
                raise SecurityException(
                    f"Symlink '{path_obj}' points to potentially dangerous location",
                    error_code="SYMLINK_ATTACK",
                    details={"symlink": str(path_obj), "target": str(target)}
                )
    
    def _calculate_baseline_checksum(self, scan_path: str):
        """Calculate baseline checksum for integrity verification.
        
        Args:
            scan_path: Path to calculate checksum for
        """
        if not self.enable_integrity_checks:
            return
        
        try:
            path_obj = Path(scan_path)
            
            if path_obj.is_file():
                # Single file checksum
                self.scan_checksums[scan_path] = self._file_checksum(path_obj)
            else:
                # Directory tree checksum
                files_hash = hashlib.sha256()
                
                for file_path in sorted(path_obj.rglob('*')):
                    if file_path.is_file():
                        try:
                            file_checksum = self._file_checksum(file_path)
                            files_hash.update(f"{file_path}:{file_checksum}".encode())
                        except (PermissionError, OSError):
                            continue
                
                self.scan_checksums[scan_path] = files_hash.hexdigest()
                
        except Exception as e:
            self.logger.log_security_event('checksum_error', {
                'path': scan_path,
                'error': str(e)
            })
    
    def _file_checksum(self, file_path: Path) -> str:
        """Calculate file checksum.
        
        Args:
            file_path: Path to file
            
        Returns:
            SHA256 checksum
        """
        sha256_hash = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                # Read in chunks to handle large files
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256_hash.update(chunk)
        except Exception:
            # Use file metadata if content unreadable
            stat = file_path.stat()
            sha256_hash.update(f"{file_path}:{stat.st_size}:{stat.st_mtime}".encode())
        
        return sha256_hash.hexdigest()
    
    def _validate_scan_integrity(self, scan_path: str):
        """Validate scan integrity after completion.
        
        Args:
            scan_path: Path that was scanned
            
        Raises:
            SecurityException: If integrity check fails
        """
        if not self.enable_integrity_checks or scan_path not in self.scan_checksums:
            return
        
        try:
            current_checksum = self._calculate_current_checksum(scan_path)
            baseline_checksum = self.scan_checksums[scan_path]
            
            if current_checksum != baseline_checksum:
                # Files were modified during scan - potential TOCTOU attack
                self._record_security_event(
                    'integrity_violation',
                    ThreatLevel.HIGH,
                    {
                        'path': scan_path,
                        'baseline_checksum': baseline_checksum,
                        'current_checksum': current_checksum
                    },
                    'Time-of-check-time-of-use (TOCTOU) attack detected'
                )
                
                if self.security_level == SecurityLevel.PARANOID:
                    raise SecurityException(
                        "File integrity violation detected during scan",
                        error_code="INTEGRITY_VIOLATION",
                        details={
                            'path': scan_path,
                            'threat': 'TOCTOU attack'
                        }
                    )
                
        except Exception as e:
            self.logger.log_error(e, {'context': 'integrity_validation', 'path': scan_path})
    
    def _calculate_current_checksum(self, scan_path: str) -> str:
        """Calculate current checksum for comparison.
        
        Args:
            scan_path: Path to calculate checksum for
            
        Returns:
            Current checksum
        """
        path_obj = Path(scan_path)
        
        if path_obj.is_file():
            return self._file_checksum(path_obj)
        else:
            files_hash = hashlib.sha256()
            
            for file_path in sorted(path_obj.rglob('*')):
                if file_path.is_file():
                    try:
                        file_checksum = self._file_checksum(file_path)
                        files_hash.update(f"{file_path}:{file_checksum}".encode())
                    except (PermissionError, OSError):
                        continue
            
            return files_hash.hexdigest()
    
    def _detect_anomalies(self, scan_path: str, scan_duration: float):
        """Detect anomalous behavior during scan.
        
        Args:
            scan_path: Path that was scanned
            scan_duration: Time taken for scan
        """
        if not self.enable_anomaly_detection:
            return
        
        # Check for unusually long scan times
        if scan_duration > 300:  # 5 minutes
            self._record_security_event(
                'anomaly_long_scan',
                ThreatLevel.MEDIUM,
                {
                    'path': scan_path,
                    'duration': scan_duration,
                    'threshold': 300
                },
                'Unusually long scan duration may indicate large files or system issues'
            )
        
        # Check for resource consumption anomalies
        try:
            import psutil
            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024
            
            if memory_mb > 1000:  # 1GB
                self._record_security_event(
                    'anomaly_high_memory',
                    ThreatLevel.MEDIUM,
                    {
                        'path': scan_path,
                        'memory_mb': memory_mb,
                        'threshold': 1000
                    },
                    'High memory usage may indicate memory exhaustion attack'
                )
                
        except ImportError:
            pass
    
    def _record_security_event(self, event_type: str, threat_level: ThreatLevel, 
                              details: Dict[str, Any], remediation: str = ""):
        """Record security event.
        
        Args:
            event_type: Type of security event
            threat_level: Severity level
            details: Event details
            remediation: Suggested remediation
        """
        event = SecurityEvent(
            event_type=event_type,
            threat_level=threat_level,
            timestamp=time.time(),
            details=details,
            source='security_monitor',
            remediation=remediation
        )
        
        self.security_events.append(event)
        
        # Log based on threat level
        if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            self.logger.log_security_event(event_type, details)
    
    def _generate_scan_id(self, scan_path: str) -> str:
        """Generate unique scan ID.
        
        Args:
            scan_path: Path being scanned
            
        Returns:
            Unique scan identifier
        """
        timestamp = str(time.time())
        data = f"{scan_path}:{timestamp}:{os.getpid()}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get security monitoring summary.
        
        Returns:
            Security summary report
        """
        threat_counts = {level.value: 0 for level in ThreatLevel}
        event_types = {}
        
        for event in self.security_events:
            threat_counts[event.threat_level.value] += 1
            event_types[event.event_type] = event_types.get(event.event_type, 0) + 1
        
        return {
            'total_events': len(self.security_events),
            'threat_distribution': threat_counts,
            'event_types': event_types,
            'security_level': self.security_level.value,
            'features_enabled': {
                'threat_detection': self.enable_threat_detection,
                'integrity_checks': self.enable_integrity_checks,
                'anomaly_detection': self.enable_anomaly_detection
            }
        }


class InputSanitizer:
    """Input sanitization and validation."""
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.ENHANCED):
        """Initialize input sanitizer.
        
        Args:
            security_level: Security validation level
        """
        self.security_level = security_level
        self.logger = get_logger('pqc_audit.security')
    
    def sanitize_path(self, path: str) -> str:
        """Sanitize file path input.
        
        Args:
            path: Raw path input
            
        Returns:
            Sanitized path
            
        Raises:
            ValidationException: If path is invalid
        """
        # Convert Path objects to strings
        if hasattr(path, '__fspath__'):
            path = str(path)
        
        if not path or not isinstance(path, str):
            raise ValidationException("Path must be a non-empty string")
        
        # Remove null bytes and control characters
        sanitized = ''.join(char for char in path if ord(char) >= 32)
        
        # Resolve path and check for directory traversal
        try:
            resolved_path = Path(sanitized).resolve()
        except (OSError, ValueError) as e:
            raise ValidationException(f"Invalid path format: {e}")
        
        # Check for directory traversal attempts (but allow legitimate absolute paths)
        if '..' in sanitized:
            if self.security_level == SecurityLevel.PARANOID:
                raise ValidationException("Directory traversal attempts not allowed")
            elif self.security_level == SecurityLevel.ENHANCED:
                # Allow if it resolves to a safe path under /tmp or current working directory
                safe_prefixes = ['/tmp/', str(Path.cwd())]
                if not any(str(resolved_path).startswith(prefix) for prefix in safe_prefixes):
                    raise ValidationException("Directory traversal attempts not allowed")
        
        return str(resolved_path)
    
    def sanitize_filename(self, filename: str) -> str:
        """Sanitize filename input.
        
        Args:
            filename: Raw filename
            
        Returns:
            Sanitized filename
        """
        if not filename or not isinstance(filename, str):
            raise ValidationException("Filename must be a non-empty string")
        
        # Remove dangerous characters
        dangerous_chars = '<>:"|?*\x00'
        sanitized = ''.join(char for char in filename if char not in dangerous_chars)
        
        # Prevent reserved names on Windows
        reserved_names = [
            'CON', 'PRN', 'AUX', 'NUL',
            'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
            'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
        ]
        
        if sanitized.upper() in reserved_names:
            sanitized = f"safe_{sanitized}"
        
        # Ensure reasonable length
        if len(sanitized) > 255:
            sanitized = sanitized[:255]
        
        return sanitized
    
    def validate_configuration(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and sanitize configuration input.
        
        Args:
            config: Raw configuration
            
        Returns:
            Validated configuration
        """
        if not isinstance(config, dict):
            raise ValidationException("Configuration must be a dictionary")
        
        validated = {}
        
        # Allowed configuration keys
        allowed_keys = {
            'max_scan_time_seconds', 'max_files_per_scan', 'enable_security_validation',
            'enable_performance_optimization', 'log_level', 'enable_file_logging',
            'enable_structured_logging', 'security_level', 'exclude_patterns',
            'custom_patterns', 'timeout', 'incremental'
        }
        
        for key, value in config.items():
            if key not in allowed_keys:
                if self.security_level == SecurityLevel.PARANOID:
                    raise ValidationException(f"Unknown configuration key: {key}")
                else:
                    self.logger.log_security_event('unknown_config_key', {'key': key})
                    continue
            
            # Type validation and sanitization
            validated[key] = self._sanitize_config_value(key, value)
        
        return validated
    
    def _sanitize_config_value(self, key: str, value: Any) -> Any:
        """Sanitize individual configuration value.
        
        Args:
            key: Configuration key
            value: Configuration value
            
        Returns:
            Sanitized value
        """
        if key in ['max_scan_time_seconds', 'max_files_per_scan', 'timeout']:
            if not isinstance(value, (int, float)):
                raise ValidationException(f"{key} must be a number")
            if value <= 0:
                raise ValidationException(f"{key} must be a positive number")
            return min(value, 86400)  # Cap at 24 hours
        
        elif key in ['enable_security_validation', 'enable_performance_optimization',
                    'enable_file_logging', 'enable_structured_logging', 'incremental']:
            return bool(value)
        
        elif key == 'log_level':
            valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
            if str(value).upper() not in valid_levels:
                raise ValidationException(f"Invalid log level: {value}")
            return str(value).upper()
        
        elif key == 'security_level':
            try:
                return SecurityLevel(value).value
            except ValueError:
                raise ValidationException(f"Invalid security level: {value}")
        
        elif key in ['exclude_patterns', 'custom_patterns']:
            if not isinstance(value, (list, dict)):
                raise ValidationException(f"{key} must be a list or dict")
            return value
        
        else:
            return value