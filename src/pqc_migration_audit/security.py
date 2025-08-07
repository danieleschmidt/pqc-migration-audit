"""Enhanced security scanning and validation for PQC Migration Audit."""

import re
import hashlib
import hmac
import secrets
import os
from typing import List, Dict, Any, Optional, Set, Tuple
from pathlib import Path
from dataclasses import dataclass, field
import json
import logging
from datetime import datetime, timedelta
import tempfile
import subprocess

from .exceptions import (
    SecurityException, MaliciousContentException, PathTraversalException,
    ValidationException, FileSystemException
)
from .types import ScanResults, Vulnerability, Severity


@dataclass 
class SecurityThreat:
    """Represents a detected security threat."""
    threat_type: str
    severity: str
    file_path: str
    line_number: int
    description: str
    pattern_matched: str
    mitigation: str
    cve_references: List[str] = field(default_factory=list)
    confidence_score: float = 1.0


@dataclass
class SecurityScanResults:
    """Results from security scanning."""
    threats: List[SecurityThreat] = field(default_factory=list)
    scan_timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    files_scanned: int = 0
    threat_summary: Dict[str, int] = field(default_factory=dict)
    overall_risk_score: float = 0.0


class AdvancedSecurityScanner:
    """Advanced security scanner for detecting various threats."""
    
    def __init__(self):
        """Initialize security scanner."""
        self.logger = logging.getLogger(__name__)
        
        # Malicious code patterns
        self.malicious_patterns = {
            'code_injection': [
                r'eval\s*\(\s*["\'].*["\']\s*\)',
                r'exec\s*\(\s*["\'].*["\']\s*\)',
                r'system\s*\(\s*["\'].*["\']\s*\)',
                r'shell_exec\s*\(\s*["\'].*["\']\s*\)',
                r'passthru\s*\(\s*["\'].*["\']\s*\)',
                r'subprocess\.call\s*\(\s*["\'].*["\']\s*\)',
                r'os\.system\s*\(\s*["\'].*["\']\s*\)',
                r'Runtime\.getRuntime\(\)\.exec',
                r'ProcessBuilder\s*\(',
                r'__import__\s*\(\s*["\'].*["\']\s*\)'
            ],
            
            'path_traversal': [
                r'\.\./',
                r'\.\.\x5c',
                r'%2e%2e%2f',
                r'%2e%2e/',
                r'..%2f',
                r'%2e%2e%5c'
            ],
            
            'hardcoded_secrets': [
                r'password\s*[=:]\s*["\'][^"\']{8,}["\']',
                r'api[_-]?key\s*[=:]\s*["\'][^"\']{16,}["\']',
                r'secret\s*[=:]\s*["\'][^"\']{16,}["\']',
                r'token\s*[=:]\s*["\'][^"\']{20,}["\']',
                r'private[_-]?key\s*[=:]\s*["\'].*-----BEGIN.*-----["\']',
                r'aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*["\'][A-Z0-9]{20}["\']',
                r'aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\'][A-Za-z0-9/+]{40}["\']'
            ],
            
            'sql_injection': [
                r'SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*["\']?\s*\+\s*["\']?',
                r'INSERT\s+INTO\s+.*VALUES\s*\(.*["\']?\s*\+\s*["\']?',
                r'UPDATE\s+.*\s+SET\s+.*["\']?\s*\+\s*["\']?',
                r'DELETE\s+FROM\s+.*WHERE\s+.*["\']?\s*\+\s*["\']?',
                r'UNION\s+SELECT',
                r'DROP\s+TABLE',
                r';\s*DROP\s+'
            ],
            
            'xss_patterns': [
                r'<script[^>]*>.*</script>',
                r'javascript:',
                r'onload\s*=',
                r'onerror\s*=',
                r'onclick\s*=',
                r'eval\s*\(\s*["\'].*["\']\s*\)',
                r'innerHTML\s*=\s*.*\+',
                r'document\.write\s*\('
            ],
            
            'crypto_weaknesses': [
                r'MD5\s*\(',
                r'SHA1\s*\(',
                r'DES\s*\(',
                r'3DES\s*\(',
                r'RC4\s*\(',
                r'ECB\s*mode',
                r'key_size\s*=\s*(512|1024)\b',
                r'random\.randint\s*\(',  # Weak random number generation
                r'Math\.random\s*\(\)',
                r'rand\s*\(\)'
            ],
            
            'backdoor_indicators': [
                r'backdoor',
                r'rootkit',
                r'keylogger',
                r'reverse[_-]?shell',
                r'bind[_-]?shell',
                r'nc\s+-[el]+',
                r'netcat\s+-[el]+',
                r'/dev/tcp/',
                r'bash\s+-i\s*>\s*&\s*/dev/tcp'
            ],
            
            'information_disclosure': [
                r'print\s*\(\s*.*password',
                r'console\.log\s*\(\s*.*password',
                r'echo\s+.*password',
                r'System\.out\.println\s*\(\s*.*password',
                r'printStackTrace\s*\(\s*\)',
                r'error_reporting\s*\(\s*E_ALL\s*\)',
                r'display_errors\s*=\s*On'
            ]
        }
        
        # File type signatures for detecting disguised files
        self.file_signatures = {
            b'\x4D\x5A': 'PE executable',
            b'\x7F\x45\x4C\x46': 'ELF executable',
            b'\xCF\xFA\xED\xFE': 'Mach-O executable',
            b'\x50\x4B\x03\x04': 'ZIP archive',
            b'\x89\x50\x4E\x47': 'PNG image',
            b'\xFF\xD8\xFF': 'JPEG image',
            b'\x25\x50\x44\x46': 'PDF document'
        }
        
        # Suspicious file extensions
        self.suspicious_extensions = {
            '.exe', '.dll', '.scr', '.bat', '.cmd', '.com', '.pif',
            '.vbs', '.ps1', '.sh', '.jar', '.class', '.dex', '.apk'
        }
        
        # Known malicious file hashes (example - would normally be from threat intel)
        self.known_malicious_hashes = set()
        
        # Entropy threshold for detecting packed/encrypted content
        self.entropy_threshold = 7.5
    
    def scan_file_security(self, file_path: Path) -> List[SecurityThreat]:
        """Scan a single file for security threats.
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            List of detected security threats
        """
        threats = []
        
        try:
            # Check file permissions and ownership
            threats.extend(self._check_file_permissions(file_path))
            
            # Check file signature vs extension
            threats.extend(self._check_file_signature(file_path))
            
            # Check file hash against known malicious files
            threats.extend(self._check_file_hash(file_path))
            
            # Read and analyze file content
            if self._is_text_file(file_path):
                content = self._read_file_safely(file_path)
                if content:
                    threats.extend(self._scan_content_patterns(file_path, content))
                    threats.extend(self._check_entropy(file_path, content))
            else:
                # Binary file analysis
                threats.extend(self._analyze_binary_file(file_path))
            
        except Exception as e:
            self.logger.error(f"Error scanning file {file_path}: {e}")
            threats.append(SecurityThreat(
                threat_type='scan_error',
                severity='medium',
                file_path=str(file_path),
                line_number=0,
                description=f"Failed to scan file: {e}",
                pattern_matched='',
                mitigation='Investigate file manually'
            ))
        
        return threats
    
    def _check_file_permissions(self, file_path: Path) -> List[SecurityThreat]:
        """Check file permissions for security issues."""
        threats = []
        
        try:
            stat = file_path.stat()
            mode = stat.st_mode
            
            # Check for world-writable files
            if mode & 0o002:
                threats.append(SecurityThreat(
                    threat_type='permissions',
                    severity='high',
                    file_path=str(file_path),
                    line_number=0,
                    description='File is world-writable',
                    pattern_matched=f'mode: {oct(mode)}',
                    mitigation='Remove write permissions for others'
                ))
            
            # Check for setuid/setgid bits
            if mode & 0o4000:  # setuid
                threats.append(SecurityThreat(
                    threat_type='permissions',
                    severity='critical',
                    file_path=str(file_path),
                    line_number=0,
                    description='File has setuid bit set',
                    pattern_matched=f'mode: {oct(mode)}',
                    mitigation='Review setuid necessity and remove if not required'
                ))
            
            if mode & 0o2000:  # setgid
                threats.append(SecurityThreat(
                    threat_type='permissions',
                    severity='high',
                    file_path=str(file_path),
                    line_number=0,
                    description='File has setgid bit set',
                    pattern_matched=f'mode: {oct(mode)}',
                    mitigation='Review setgid necessity and remove if not required'
                ))
        
        except Exception as e:
            self.logger.warning(f"Could not check permissions for {file_path}: {e}")
        
        return threats
    
    def _check_file_signature(self, file_path: Path) -> List[SecurityThreat]:
        """Check file signature vs extension for disguised files."""
        threats = []
        
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
            
            for signature, file_type in self.file_signatures.items():
                if header.startswith(signature):
                    expected_extensions = {
                        'PE executable': ['.exe', '.dll', '.scr'],
                        'ELF executable': [''],  # Usually no extension
                        'ZIP archive': ['.zip', '.jar', '.war'],
                        'PNG image': ['.png'],
                        'JPEG image': ['.jpg', '.jpeg']
                    }
                    
                    if file_type in expected_extensions:
                        if file_path.suffix.lower() not in expected_extensions[file_type]:
                            threats.append(SecurityThreat(
                                threat_type='file_masquerading',
                                severity='high',
                                file_path=str(file_path),
                                line_number=0,
                                description=f'File appears to be {file_type} but has extension {file_path.suffix}',
                                pattern_matched=signature.hex(),
                                mitigation='Verify file legitimacy and rename with correct extension'
                            ))
                    break
            
            # Check for suspicious extensions
            if file_path.suffix.lower() in self.suspicious_extensions:
                threats.append(SecurityThreat(
                    threat_type='suspicious_extension',
                    severity='medium',
                    file_path=str(file_path),
                    line_number=0,
                    description=f'File has suspicious extension: {file_path.suffix}',
                    pattern_matched=file_path.suffix,
                    mitigation='Verify file is legitimate and necessary'
                ))
        
        except Exception as e:
            self.logger.warning(f"Could not check file signature for {file_path}: {e}")
        
        return threats
    
    def _check_file_hash(self, file_path: Path) -> List[SecurityThreat]:
        """Check file hash against known malicious files."""
        threats = []
        
        try:
            file_hash = self._calculate_file_hash(file_path)
            
            if file_hash in self.known_malicious_hashes:
                threats.append(SecurityThreat(
                    threat_type='known_malware',
                    severity='critical',
                    file_path=str(file_path),
                    line_number=0,
                    description='File matches known malware signature',
                    pattern_matched=file_hash[:16] + '...',
                    mitigation='IMMEDIATE: Quarantine and remove file'
                ))
        
        except Exception as e:
            self.logger.warning(f"Could not calculate hash for {file_path}: {e}")
        
        return threats
    
    def _scan_content_patterns(self, file_path: Path, content: str) -> List[SecurityThreat]:
        """Scan file content for malicious patterns."""
        threats = []
        lines = content.split('\n')
        
        for threat_type, patterns in self.malicious_patterns.items():
            for pattern in patterns:
                try:
                    for line_num, line in enumerate(lines, 1):
                        matches = re.finditer(pattern, line, re.IGNORECASE)
                        for match in matches:
                            severity = self._get_threat_severity(threat_type, match.group())
                            confidence = self._calculate_confidence(threat_type, line, match.group())
                            
                            threat = SecurityThreat(
                                threat_type=threat_type,
                                severity=severity,
                                file_path=str(file_path),
                                line_number=line_num,
                                description=self._get_threat_description(threat_type, match.group()),
                                pattern_matched=match.group(),
                                mitigation=self._get_mitigation(threat_type),
                                confidence_score=confidence
                            )
                            threats.append(threat)
                
                except re.error as e:
                    self.logger.warning(f"Invalid regex pattern {pattern}: {e}")
        
        return threats
    
    def _check_entropy(self, file_path: Path, content: str) -> List[SecurityThreat]:
        """Check content entropy to detect packed/encrypted content."""
        threats = []
        
        try:
            # Calculate Shannon entropy
            if len(content) > 0:
                entropy = self._calculate_shannon_entropy(content.encode())
                
                if entropy > self.entropy_threshold:
                    threats.append(SecurityThreat(
                        threat_type='high_entropy',
                        severity='medium',
                        file_path=str(file_path),
                        line_number=0,
                        description=f'File has high entropy ({entropy:.2f}), may be packed/encrypted',
                        pattern_matched=f'entropy: {entropy:.2f}',
                        mitigation='Analyze file for packing or encryption'
                    ))
        
        except Exception as e:
            self.logger.warning(f"Could not calculate entropy for {file_path}: {e}")
        
        return threats
    
    def _analyze_binary_file(self, file_path: Path) -> List[SecurityThreat]:
        """Analyze binary files for threats."""
        threats = []
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read(8192)  # Read first 8KB
            
            # Check for suspicious strings in binary
            strings = self._extract_strings(data)
            
            suspicious_strings = [
                'backdoor', 'rootkit', 'keylogger', 'password', 'admin',
                'shell', 'cmd.exe', '/bin/sh', 'reverse', 'bind'
            ]
            
            for string in strings:
                for suspicious in suspicious_strings:
                    if suspicious.lower() in string.lower():
                        threats.append(SecurityThreat(
                            threat_type='suspicious_strings',
                            severity='medium',
                            file_path=str(file_path),
                            line_number=0,
                            description=f'Suspicious string found in binary: {string}',
                            pattern_matched=string,
                            mitigation='Analyze binary with security tools'
                        ))
        
        except Exception as e:
            self.logger.warning(f"Could not analyze binary file {file_path}: {e}")
        
        return threats
    
    def _is_text_file(self, file_path: Path) -> bool:
        """Check if file is likely a text file."""
        try:
            with open(file_path, 'rb') as f:
                sample = f.read(8192)
            
            # Check for null bytes (indicator of binary)
            if b'\x00' in sample:
                return False
            
            # Try to decode as UTF-8
            try:
                sample.decode('utf-8')
                return True
            except UnicodeDecodeError:
                return False
        
        except Exception:
            return False
    
    def _read_file_safely(self, file_path: Path, max_size: int = 10*1024*1024) -> Optional[str]:
        """Safely read file content with size limits."""
        try:
            file_size = file_path.stat().st_size
            if file_size > max_size:
                self.logger.warning(f"File too large to scan: {file_path} ({file_size} bytes)")
                return None
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        
        except Exception as e:
            self.logger.warning(f"Could not read file {file_path}: {e}")
            return None
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def _calculate_shannon_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if len(data) == 0:
            return 0
        
        # Count frequency of each byte
        frequency = [0] * 256
        for byte in data:
            frequency[byte] += 1
        
        # Calculate entropy
        entropy = 0
        data_len = len(data)
        for count in frequency:
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract readable strings from binary data."""
        strings = []
        current_string = ""
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""
        
        if len(current_string) >= min_length:
            strings.append(current_string)
        
        return strings
    
    def _get_threat_severity(self, threat_type: str, matched_pattern: str) -> str:
        """Get severity level for threat type."""
        severity_map = {
            'code_injection': 'critical',
            'path_traversal': 'high',
            'hardcoded_secrets': 'high',
            'sql_injection': 'critical',
            'xss_patterns': 'high',
            'crypto_weaknesses': 'medium',
            'backdoor_indicators': 'critical',
            'information_disclosure': 'medium'
        }
        
        base_severity = severity_map.get(threat_type, 'medium')
        
        # Upgrade severity for certain patterns
        critical_indicators = ['eval', 'exec', 'system', 'shell', 'backdoor', 'DROP TABLE']
        if any(indicator in matched_pattern.lower() for indicator in critical_indicators):
            return 'critical'
        
        return base_severity
    
    def _calculate_confidence(self, threat_type: str, line: str, pattern: str) -> float:
        """Calculate confidence score for threat detection."""
        base_confidence = 0.7
        
        # Increase confidence for exact matches
        if pattern in line:
            base_confidence += 0.1
        
        # Increase confidence for suspicious contexts
        suspicious_context = ['password', 'secret', 'admin', 'root', 'shell']
        if any(context in line.lower() for context in suspicious_context):
            base_confidence += 0.2
        
        # Decrease confidence for comments
        if line.strip().startswith(('#', '//', '/*', '--')):
            base_confidence -= 0.3
        
        return max(0.1, min(1.0, base_confidence))
    
    def _get_threat_description(self, threat_type: str, pattern: str) -> str:
        """Get human-readable threat description."""
        descriptions = {
            'code_injection': f'Potential code injection vulnerability: {pattern}',
            'path_traversal': f'Path traversal attempt detected: {pattern}',
            'hardcoded_secrets': f'Hardcoded secret or credential found: {pattern[:20]}...',
            'sql_injection': f'SQL injection vulnerability: {pattern}',
            'xss_patterns': f'Cross-site scripting vulnerability: {pattern}',
            'crypto_weaknesses': f'Cryptographic weakness: {pattern}',
            'backdoor_indicators': f'Potential backdoor indicator: {pattern}',
            'information_disclosure': f'Information disclosure risk: {pattern}'
        }
        
        return descriptions.get(threat_type, f'Security threat detected: {pattern}')
    
    def _get_mitigation(self, threat_type: str) -> str:
        """Get mitigation advice for threat type."""
        mitigations = {
            'code_injection': 'Use parameterized queries and input validation',
            'path_traversal': 'Implement proper path validation and sandboxing',
            'hardcoded_secrets': 'Move secrets to secure configuration or key management',
            'sql_injection': 'Use prepared statements and parameterized queries',
            'xss_patterns': 'Implement output encoding and input validation',
            'crypto_weaknesses': 'Upgrade to modern cryptographic algorithms',
            'backdoor_indicators': 'Remove suspicious code and scan for malware',
            'information_disclosure': 'Remove sensitive information from output'
        }
        
        return mitigations.get(threat_type, 'Review and remediate security issue')
    
    def scan_directory_security(self, directory_path: Path, 
                               exclude_patterns: List[str] = None) -> SecurityScanResults:
        """Scan entire directory for security threats.
        
        Args:
            directory_path: Directory to scan
            exclude_patterns: Patterns to exclude from scanning
            
        Returns:
            SecurityScanResults with all detected threats
        """
        if exclude_patterns is None:
            exclude_patterns = ['*/node_modules/*', '*/venv/*', '*/build/*', '*/.git/*']
        
        results = SecurityScanResults()
        
        try:
            # Find all files to scan
            for file_path in directory_path.rglob('*'):
                if file_path.is_file():
                    # Check exclude patterns
                    if any(self._matches_pattern(str(file_path), pattern) 
                           for pattern in exclude_patterns):
                        continue
                    
                    # Scan file
                    threats = self.scan_file_security(file_path)
                    results.threats.extend(threats)
                    results.files_scanned += 1
            
            # Calculate summary statistics
            results.threat_summary = {}
            for threat in results.threats:
                threat_type = threat.threat_type
                results.threat_summary[threat_type] = results.threat_summary.get(threat_type, 0) + 1
            
            # Calculate overall risk score
            results.overall_risk_score = self._calculate_risk_score(results.threats)
            
        except Exception as e:
            self.logger.error(f"Error scanning directory {directory_path}: {e}")
        
        return results
    
    def _matches_pattern(self, file_path: str, pattern: str) -> bool:
        """Check if file path matches exclude pattern."""
        # Simple glob-like pattern matching
        pattern_regex = pattern.replace('*', '.*')
        return re.search(pattern_regex, file_path) is not None
    
    def _calculate_risk_score(self, threats: List[SecurityThreat]) -> float:
        """Calculate overall risk score based on threats."""
        if not threats:
            return 0.0
        
        severity_weights = {
            'critical': 10.0,
            'high': 7.0,
            'medium': 4.0,
            'low': 1.0
        }
        
        total_score = 0.0
        for threat in threats:
            weight = severity_weights.get(threat.severity, 1.0)
            confidence = threat.confidence_score
            total_score += weight * confidence
        
        # Normalize to 0-100 scale
        max_possible_score = len(threats) * 10.0
        normalized_score = (total_score / max_possible_score) * 100 if max_possible_score > 0 else 0
        
        return min(100.0, normalized_score)


class SecureFileHandler:
    """Handles file operations securely."""
    
    def __init__(self):
        """Initialize secure file handler."""
        self.logger = logging.getLogger(__name__)
        self.max_path_depth = 10
        self.allowed_path_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/')
    
    def validate_path(self, path: str) -> None:
        """Validate file path for security.
        
        Args:
            path: Path to validate
            
        Raises:
            PathTraversalException: If path traversal detected
            ValidationException: If path is invalid
        """
        # Normalize path
        normalized = os.path.normpath(path)
        
        # Check for path traversal
        if '..' in normalized:
            raise PathTraversalException(path)
        
        # Check path depth
        path_parts = Path(normalized).parts
        if len(path_parts) > self.max_path_depth:
            raise ValidationException(
                f"Path too deep: {len(path_parts)} > {self.max_path_depth}",
                error_code="PATH_TOO_DEEP"
            )
        
        # Check for suspicious characters
        if not all(c in self.allowed_path_chars for c in path):
            raise ValidationException(
                f"Path contains suspicious characters: {path}",
                error_code="SUSPICIOUS_PATH_CHARS"
            )
    
    def secure_write(self, file_path: Path, content: str, mode: int = 0o600) -> None:
        """Write file securely with proper permissions.
        
        Args:
            file_path: Path to write to
            content: Content to write
            mode: File permissions mode
            
        Raises:
            FileSystemException: If write fails
            ValidationException: If path is invalid
        """
        try:
            # Validate path
            self.validate_path(str(file_path))
            
            # Create parent directories securely
            file_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            
            # Write to temporary file first
            with tempfile.NamedTemporaryFile(
                mode='w',
                dir=file_path.parent,
                prefix=f'.{file_path.name}_tmp_',
                delete=False
            ) as temp_file:
                temp_file.write(content)
                temp_path = Path(temp_file.name)
            
            # Set secure permissions
            temp_path.chmod(mode)
            
            # Atomic move to final location
            temp_path.replace(file_path)
            
            self.logger.info(f"Securely wrote file: {file_path}")
            
        except Exception as e:
            # Clean up temporary file if it exists
            try:
                if 'temp_path' in locals():
                    temp_path.unlink(missing_ok=True)
            except Exception:
                pass
            
            raise FileSystemException(
                f"Failed to write file {file_path}: {e}",
                error_code="SECURE_WRITE_FAILED"
            )
    
    def secure_read(self, file_path: Path, max_size: int = 10*1024*1024) -> str:
        """Read file securely with size limits.
        
        Args:
            file_path: Path to read from
            max_size: Maximum file size to read
            
        Returns:
            File content as string
            
        Raises:
            FileSystemException: If read fails
            ValidationException: If file too large or path invalid
        """
        try:
            # Validate path
            self.validate_path(str(file_path))
            
            # Check file size
            file_size = file_path.stat().st_size
            if file_size > max_size:
                raise ValidationException(
                    f"File too large: {file_size} > {max_size}",
                    error_code="FILE_TOO_LARGE"
                )
            
            # Read file securely
            with open(file_path, 'r', encoding='utf-8', errors='strict') as f:
                content = f.read()
            
            return content
            
        except Exception as e:
            raise FileSystemException(
                f"Failed to read file {file_path}: {e}",
                error_code="SECURE_READ_FAILED"
            )
    
    def calculate_checksum(self, file_path: Path, algorithm: str = 'sha256') -> str:
        """Calculate secure checksum of file.
        
        Args:
            file_path: Path to file
            algorithm: Hash algorithm to use
            
        Returns:
            Hex digest of checksum
            
        Raises:
            FileSystemException: If checksum calculation fails
        """
        try:
            if algorithm == 'sha256':
                hasher = hashlib.sha256()
            elif algorithm == 'sha512':
                hasher = hashlib.sha512()
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
            
            return hasher.hexdigest()
            
        except Exception as e:
            raise FileSystemException(
                f"Failed to calculate checksum for {file_path}: {e}",
                error_code="CHECKSUM_FAILED"
            )


class CryptoSecurityAnalyzer:
    """Analyzes cryptographic security specifically for PQC migration."""
    
    def __init__(self):
        """Initialize crypto security analyzer."""
        self.logger = logging.getLogger(__name__)
        
        # Quantum vulnerability timeline
        self.quantum_threat_timeline = {
            2025: "Preparation phase - inventory crypto assets",
            2027: "Migration phase - begin PQC deployment",
            2030: "Quantum advantage likely - critical vulnerabilities",
            2035: "Full quantum threat - all classical crypto vulnerable"
        }
        
        # Algorithm risk assessment
        self.algorithm_risks = {
            'RSA': {'quantum_vulnerable': True, 'risk_level': 'high', 'years_remaining': 5},
            'ECDSA': {'quantum_vulnerable': True, 'risk_level': 'critical', 'years_remaining': 5},
            'ECDH': {'quantum_vulnerable': True, 'risk_level': 'critical', 'years_remaining': 5},
            'DSA': {'quantum_vulnerable': True, 'risk_level': 'high', 'years_remaining': 5},
            'DH': {'quantum_vulnerable': True, 'risk_level': 'high', 'years_remaining': 5},
            'AES': {'quantum_vulnerable': False, 'risk_level': 'low', 'years_remaining': None},
            'SHA2': {'quantum_vulnerable': False, 'risk_level': 'low', 'years_remaining': None},
            'SHA3': {'quantum_vulnerable': False, 'risk_level': 'low', 'years_remaining': None}
        }
    
    def assess_quantum_readiness(self, scan_results: ScanResults) -> Dict[str, Any]:
        """Assess quantum readiness based on scan results.
        
        Args:
            scan_results: Results from vulnerability scan
            
        Returns:
            Quantum readiness assessment
        """
        assessment = {
            'overall_readiness': 'Not Ready',
            'readiness_score': 0,
            'critical_vulnerabilities': 0,
            'high_vulnerabilities': 0,
            'estimated_migration_time': 0,
            'quantum_threat_timeline': self.quantum_threat_timeline,
            'recommendations': [],
            'algorithm_breakdown': {}
        }
        
        try:
            # Count vulnerabilities by algorithm
            for vuln in scan_results.vulnerabilities:
                algo_name = vuln.algorithm.value
                if algo_name not in assessment['algorithm_breakdown']:
                    assessment['algorithm_breakdown'][algo_name] = {
                        'count': 0,
                        'risk_info': self.algorithm_risks.get(algo_name, {})
                    }
                assessment['algorithm_breakdown'][algo_name]['count'] += 1
                
                if vuln.severity == Severity.CRITICAL:
                    assessment['critical_vulnerabilities'] += 1
                elif vuln.severity == Severity.HIGH:
                    assessment['high_vulnerabilities'] += 1
            
            # Calculate readiness score (0-100)
            total_vulns = len(scan_results.vulnerabilities)
            if total_vulns == 0:
                assessment['readiness_score'] = 100
                assessment['overall_readiness'] = 'Quantum Ready'
            else:
                # Weight vulnerabilities by severity
                weighted_score = (
                    assessment['critical_vulnerabilities'] * 4 +
                    assessment['high_vulnerabilities'] * 2 +
                    (total_vulns - assessment['critical_vulnerabilities'] - assessment['high_vulnerabilities'])
                )
                
                # Normalize to 0-100 scale (inverse relationship)
                max_weighted = total_vulns * 4  # If all were critical
                assessment['readiness_score'] = max(0, 100 - int((weighted_score / max_weighted) * 100))
                
                if assessment['readiness_score'] >= 90:
                    assessment['overall_readiness'] = 'Quantum Ready'
                elif assessment['readiness_score'] >= 70:
                    assessment['overall_readiness'] = 'Mostly Ready'
                elif assessment['readiness_score'] >= 40:
                    assessment['overall_readiness'] = 'Partially Ready'
                else:
                    assessment['overall_readiness'] = 'Not Ready'
            
            # Estimate migration time (weeks)
            assessment['estimated_migration_time'] = self._estimate_migration_time(scan_results)
            
            # Generate recommendations
            assessment['recommendations'] = self._generate_quantum_recommendations(assessment)
            
        except Exception as e:
            self.logger.error(f"Error assessing quantum readiness: {e}")
            assessment['error'] = str(e)
        
        return assessment
    
    def _estimate_migration_time(self, scan_results: ScanResults) -> int:
        """Estimate migration time in weeks."""
        # Base time estimates per vulnerability type
        time_estimates = {
            Severity.CRITICAL: 2.0,  # 2 weeks per critical
            Severity.HIGH: 1.0,      # 1 week per high
            Severity.MEDIUM: 0.5,    # 0.5 weeks per medium
            Severity.LOW: 0.25       # 0.25 weeks per low
        }
        
        total_time = 0
        for vuln in scan_results.vulnerabilities:
            total_time += time_estimates.get(vuln.severity, 0.5)
        
        # Add overhead for testing and integration (25%)
        total_time *= 1.25
        
        # Add base infrastructure setup time
        total_time += 2  # 2 weeks base
        
        return int(total_time)
    
    def _generate_quantum_recommendations(self, assessment: Dict[str, Any]) -> List[str]:
        """Generate quantum security recommendations."""
        recommendations = []
        
        readiness_score = assessment['readiness_score']
        
        if readiness_score < 40:
            recommendations.extend([
                "URGENT: Begin immediate PQC migration planning",
                "Inventory all cryptographic implementations",
                "Prioritize critical and high-severity vulnerabilities",
                "Establish quantum-safe cryptography working group",
                "Begin testing NIST-approved PQC algorithms"
            ])
        elif readiness_score < 70:
            recommendations.extend([
                "Accelerate PQC migration efforts",
                "Implement hybrid classical+PQC approach",
                "Update security policies for quantum threats",
                "Train development teams on PQC best practices"
            ])
        elif readiness_score < 90:
            recommendations.extend([
                "Complete remaining PQC migrations",
                "Perform comprehensive PQC testing",
                "Update documentation and procedures",
                "Plan for regular PQC algorithm updates"
            ])
        else:
            recommendations.extend([
                "Maintain quantum-ready posture",
                "Monitor for new quantum threats",
                "Keep PQC algorithms updated",
                "Share quantum security best practices"
            ])
        
        # Algorithm-specific recommendations
        for algo, info in assessment['algorithm_breakdown'].items():
            if info.get('risk_info', {}).get('quantum_vulnerable', False):
                if algo == 'RSA':
                    recommendations.append(f"Replace RSA with ML-KEM (Kyber) for key exchange")
                elif algo in ['ECDSA', 'DSA']:
                    recommendations.append(f"Replace {algo} with ML-DSA (Dilithium) for signatures")
                elif algo in ['ECDH', 'DH']:
                    recommendations.append(f"Replace {algo} with ML-KEM (Kyber) for key agreement")
        
        return recommendations