"""Advanced security scanner with threat detection and validation."""

import os
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

from .types import Severity


class ThreatLevel(Enum):
    """Security threat levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityThreat:
    """Represents a security threat detected during scanning."""
    threat_type: str
    severity: ThreatLevel
    description: str
    file_path: str
    line_number: int
    evidence: str
    mitigation: str


class SecurityScanner:
    """Advanced security scanner for threat detection."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.suspicious_patterns = {
            'code_injection': [
                r'eval\s*\(',
                r'exec\s*\(',
                r'os\.system\s*\(',
                r'subprocess\.call.*shell\s*=\s*True',
            ],
            'path_traversal': [
                r'\.\./.*\.\.',
                r'\\\\.*\\.\\.',
                r'os\.path\.join.*\.\.',
            ],
            'hardcoded_secrets': [
                r'password\s*=\s*["\'][^"\']{8,}["\']',
                r'api_key\s*=\s*["\'][A-Za-z0-9_-]{20,}["\']',
                r'secret_key\s*=\s*["\'][A-Za-z0-9_-]{20,}["\']',
                r'token\s*=\s*["\'][A-Za-z0-9._-]{20,}["\']',
            ],
            'unsafe_crypto': [
                r'hashlib\.md5\s*\(',
                r'hashlib\.sha1\s*\(',
                r'DES\.',
                r'des\.',
                r'RC4\.',
                r'rc4\.',
            ]
        }
    
    def scan_file_security(self, file_path: Path) -> List[SecurityThreat]:
        """Scan file for security threats."""
        threats = []
        
        try:
            # Check file permissions
            file_stat = file_path.stat()
            if file_stat.st_mode & 0o777 == 0o777:  # World writable
                threats.append(SecurityThreat(
                    threat_type="file_permissions",
                    severity=ThreatLevel.HIGH,
                    description="File has overly permissive permissions",
                    file_path=str(file_path),
                    line_number=0,
                    evidence=f"Permissions: {oct(file_stat.st_mode)[-3:]}",
                    mitigation="Set appropriate file permissions (644 or 600)"
                ))
            
            # Check file size (prevent DoS)
            if file_stat.st_size > 50 * 1024 * 1024:  # 50MB
                threats.append(SecurityThreat(
                    threat_type="large_file",
                    severity=ThreatLevel.MEDIUM,
                    description="File size exceeds safe scanning limits",
                    file_path=str(file_path),
                    line_number=0,
                    evidence=f"Size: {file_stat.st_size} bytes",
                    mitigation="Consider splitting large files or excluding from scan"
                ))
                return threats  # Don't scan content of huge files
            
            # Scan file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            # Detect suspicious patterns
            for threat_type, patterns in self.suspicious_patterns.items():
                threats.extend(self._scan_patterns(content, lines, patterns, threat_type, str(file_path)))
            
            # Additional security checks
            threats.extend(self._check_file_integrity(file_path, content))
            
        except PermissionError:
            threats.append(SecurityThreat(
                threat_type="permission_denied",
                severity=ThreatLevel.LOW,
                description="Permission denied accessing file",
                file_path=str(file_path),
                line_number=0,
                evidence="Access denied",
                mitigation="Check file permissions and ownership"
            ))
        except Exception as e:
            self.logger.error(f"Security scan error for {file_path}: {e}")
        
        return threats
    
    def _scan_patterns(self, content: str, lines: List[str], patterns: List[str], 
                      threat_type: str, file_path: str) -> List[SecurityThreat]:
        """Scan content for suspicious patterns."""
        threats = []
        
        import re
        
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                
                severity = self._assess_pattern_severity(threat_type, pattern)
                
                threats.append(SecurityThreat(
                    threat_type=threat_type,
                    severity=severity,
                    description=f"Suspicious {threat_type} pattern detected",
                    file_path=file_path,
                    line_number=line_num,
                    evidence=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    mitigation=self._get_mitigation(threat_type)
                ))
        
        return threats
    
    def _assess_pattern_severity(self, threat_type: str, pattern: str) -> ThreatLevel:
        """Assess severity of detected pattern."""
        high_risk_patterns = ['eval', 'exec', 'os.system', 'shell=True']
        
        if any(risk in pattern for risk in high_risk_patterns):
            return ThreatLevel.CRITICAL
        elif threat_type in ['code_injection', 'hardcoded_secrets']:
            return ThreatLevel.HIGH
        elif threat_type in ['path_traversal', 'unsafe_crypto']:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
    
    def _get_mitigation(self, threat_type: str) -> str:
        """Get mitigation advice for threat type."""
        mitigations = {
            'code_injection': 'Avoid dynamic code execution; use safer alternatives',
            'path_traversal': 'Validate and sanitize file paths; use Path.resolve()',
            'hardcoded_secrets': 'Use environment variables or secure key management',
            'unsafe_crypto': 'Replace with secure cryptographic functions (SHA-256+)',
        }
        return mitigations.get(threat_type, 'Review and validate code')
    
    def _check_file_integrity(self, file_path: Path, content: str) -> List[SecurityThreat]:
        """Check file integrity and detect potential tampering."""
        threats = []
        
        # Check for binary content in text files
        try:
            if '\0' in content:
                threats.append(SecurityThreat(
                    threat_type="binary_content",
                    severity=ThreatLevel.MEDIUM,
                    description="Binary content detected in text file",
                    file_path=str(file_path),
                    line_number=0,
                    evidence="Null bytes found",
                    mitigation="Verify file integrity and encoding"
                ))
        except Exception:
            pass
        
        # Check for excessively long lines (potential attack)
        max_line_length = max((len(line) for line in content.split('\n')), default=0)
        if max_line_length > 10000:
            threats.append(SecurityThreat(
                threat_type="long_line",
                severity=ThreatLevel.LOW,
                description="Extremely long line detected",
                file_path=str(file_path),
                line_number=0,
                evidence=f"Max line length: {max_line_length}",
                mitigation="Review line content for potential buffer overflow attempts"
            ))
        
        return threats


class SecurityValidator:
    """Validates scan results for security compliance."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def validate_scan_environment(self) -> Dict[str, Any]:
        """Validate the scanning environment for security."""
        validation_results = {
            'is_secure': True,
            'warnings': [],
            'errors': []
        }
        
        # Check running user
        if os.geteuid() == 0:  # Running as root
            validation_results['warnings'].append("Running as root - potential security risk")
            validation_results['is_secure'] = False
        
        # Check temp directory permissions
        temp_dir = Path('/tmp')
        if temp_dir.exists():
            temp_stat = temp_dir.stat()
            if temp_stat.st_mode & 0o002:  # World writable
                validation_results['warnings'].append("Temp directory is world-writable")
        
        # Check for debug mode
        if __debug__:
            validation_results['warnings'].append("Debug mode enabled - may expose sensitive information")
        
        return validation_results
    
    def validate_file_access(self, file_path: Path) -> bool:
        """Validate safe file access."""
        try:
            # Resolve symbolic links to prevent link attacks
            resolved_path = file_path.resolve()
            
            # Check if path escapes scan directory
            # This would be implemented based on scan root directory
            
            # Check file type
            if not resolved_path.is_file():
                return False
            
            # Check file permissions
            if not os.access(resolved_path, os.R_OK):
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"File access validation failed: {e}")
            return False