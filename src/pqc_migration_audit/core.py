"""Core functionality for cryptographic auditing."""

import os
import re
import ast
import time
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, NamedTuple
from dataclasses import dataclass, field
from enum import Enum
import json
from contextlib import contextmanager

from .types import Severity, CryptoAlgorithm, Vulnerability, ScanResults, ScanStats
from .exceptions import (
    ScanException, ValidationException, SecurityException, FileSystemException,
    UnsupportedFileTypeException, FileTooLargeException, InsufficientPermissionsException,
    ScanTimeoutException, ExceptionHandler
)

# Import enhanced features for Generation 2: MAKE IT ROBUST
try:
    from .logging_config import setup_logging, get_logger
    from .security_enhanced import SecurityMonitor, InputSanitizer, SecurityLevel
    from .resilience_framework import ResilienceManager
    ENHANCED_FEATURES_AVAILABLE = True
except ImportError:
    # Fallback for environments without enhanced features
    ENHANCED_FEATURES_AVAILABLE = False
    
    def get_logger(name='pqc_audit'):
        return logging.getLogger(name)

# Import performance optimizations (lazy loading to avoid circular imports)


class CryptoPatterns:
    """Cryptographic vulnerability patterns for different languages."""
    
    PYTHON_PATTERNS = {
        'rsa_generation': [
            r'rsa\.generate_private_key\s*\(',
            r'RSA\.generate\s*\(',
            r'Crypto\.PublicKey\.RSA\.generate\s*\(',
            r'RSA\.importKey\s*\(',
            r'from\s+Crypto\.PublicKey\s+import\s+RSA',
            r'from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+rsa',
        ],
        'ecc_generation': [
            r'ec\.generate_private_key\s*\(',
            r'ECC\.generate\s*\(',
            r'ecdsa\.SigningKey\.generate\s*\(',
            r'from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+ec',
            r'from\s+ecdsa\s+import\s+SigningKey',
            r'SECP256R1\s*\(',
            r'SECP384R1\s*\(',
            r'SECP521R1\s*\(',
        ],
        'dsa_generation': [
            r'dsa\.generate_private_key\s*\(',
            r'DSA\.generate\s*\(',
            r'from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+dsa',
        ],
        'diffie_hellman': [
            r'dh\.generate_private_key\s*\(',
            r'DiffieHellman\s*\(',
            r'from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+dh',
        ],
        'weak_key_sizes': [
            r'key_size\s*=\s*(512|1024)\b',
            r'bits\s*=\s*(512|1024)\b',
        ],
        'legacy_ssl_tls': [
            r'ssl\.PROTOCOL_TLSv1\b',
            r'ssl\.PROTOCOL_SSLv\d',
            r'TLSVersion\.TLSv1\b',
            r'context\.minimum_version\s*=\s*ssl\.TLSVersion\.TLSv1',
        ],
        'pki_certificates': [
            r'x509\.CertificateBuilder\s*\(',
            r'RSAPrivateKey\s*\(',
            r'ECPrivateKey\s*\(',
        ]
    }
    
    JAVA_PATTERNS = {
        'rsa_generation': [
            r'KeyPairGenerator\.getInstance\s*\(\s*["\']RSA["\']',
            r'RSAKeyGenParameterSpec\s*\(',
            r'Cipher\.getInstance\s*\(\s*["\']RSA',
            r'import\s+java\.security\.interfaces\.RSA',
        ],
        'ecc_generation': [
            r'KeyPairGenerator\.getInstance\s*\(\s*["\']EC["\']',
            r'ECGenParameterSpec\s*\(',
            r'Signature\.getInstance\s*\(\s*["\'].*ECDSA',
            r'import\s+java\.security\.interfaces\.EC',
        ],
        'dsa_generation': [
            r'KeyPairGenerator\.getInstance\s*\(\s*["\']DSA["\']',
            r'Signature\.getInstance\s*\(\s*["\'].*DSA',
        ],
        'legacy_tls': [
            r'TLSv1\b',
            r'SSLv\d',
            r'setEnabledProtocols.*TLSv1',
        ]
    }
    
    GO_PATTERNS = {
        'rsa_generation': [
            r'rsa\.GenerateKey\s*\(',
            r'rsa\.GenerateMultiPrimeKey\s*\(',
            r'crypto/rsa',
            r'rsa\.PrivateKey',
        ],
        'ecdsa_generation': [
            r'ecdsa\.GenerateKey\s*\(',
            r'crypto/ecdsa',
            r'elliptic\.P256\(\)',
            r'elliptic\.P384\(\)',
            r'elliptic\.P521\(\)',
        ],
        'legacy_tls': [
            r'tls\.VersionTLS10',
            r'tls\.VersionTLS11',
            r'tls\.VersionSSL30',
        ]
    }
    
    JAVASCRIPT_PATTERNS = {
        'rsa_generation': [
            r'crypto\.generateKeyPair\s*\(\s*["\']rsa["\']',
            r'generateKeyPairSync\s*\(\s*["\']rsa["\']',
            r'RSA_PKCS1_PADDING',
            r'node-rsa',
            r'jsrsasign',
        ],
        'ecc_generation': [
            r'crypto\.generateKeyPair\s*\(\s*["\']ec["\']',
            r'secp256r1',
            r'secp384r1',
            r'secp521r1',
            r'elliptic',
        ],
        'legacy_crypto': [
            r'crypto\.createHash\s*\(\s*["\']md5["\']',
            r'crypto\.createHash\s*\(\s*["\']sha1["\']',
        ]
    }
    
    C_CPP_PATTERNS = {
        'openssl_rsa': [
            r'RSA_generate_key\s*\(',
            r'RSA_generate_key_ex\s*\(',
            r'EVP_PKEY_RSA',
            r'#include\s*<openssl/rsa\.h>',
        ],
        'openssl_ecc': [
            r'EC_KEY_generate_key\s*\(',
            r'EVP_PKEY_EC',
            r'#include\s*<openssl/ec\.h>',
            r'EC_GROUP_new_by_curve_name',
        ],
        'legacy_functions': [
            r'MD5\s*\(',
            r'SHA1\s*\(',
            r'DES_\w+',
        ]
    }


class CryptoAuditor:
    """Main auditor class for scanning cryptographic vulnerabilities."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the crypto auditor.
        
        Args:
            config: Configuration options for the auditor
        """
        self.config = config or {}
        
        # Generation 2: Enhanced logging and monitoring
        if ENHANCED_FEATURES_AVAILABLE:
            # Setup advanced logging
            logging_config = self.config.get('logging', {})
            setup_logging(logging_config)
            self.logger = get_logger('pqc_audit.core')
            
            # Initialize security monitor
            security_config = self.config.get('security', {})
            self.security_monitor = SecurityMonitor(security_config)
            
            # Initialize input sanitizer
            security_level = SecurityLevel(security_config.get('security_level', 'enhanced'))
            self.input_sanitizer = InputSanitizer(security_level)
            
            # Initialize resilience manager
            resilience_config = self.config.get('resilience', {})
            self.resilience_manager = ResilienceManager(resilience_config)
        else:
            # Fallback to basic logging
            self.logger = logging.getLogger(__name__)
            self.security_monitor = None
            self.input_sanitizer = None
            self.resilience_manager = None
        
        # Initialize validators (lazy loading to avoid circular imports)
        self._input_validator = None
        self._security_validator = None
        self._integrity_validator = None
        
        # Incremental scanning state
        self._processed_files = set()
        
        # Scan settings with defaults (Generation 2: Enhanced validation)
        if self.input_sanitizer and ENHANCED_FEATURES_AVAILABLE:
            # Validate and sanitize configuration
            self.config = self.input_sanitizer.validate_configuration(self.config)
        
        self.max_scan_time = self.config.get('max_scan_time_seconds', 3600)  # 1 hour default
        self.max_files_per_scan = self.config.get('max_files_per_scan', 10000)
        self.enable_security_validation = self.config.get('enable_security_validation', True)
        self.enable_performance_optimization = self.config.get('enable_performance_optimization', True)
        
        # Generation 2: Enhanced error tracking
        self.error_recovery_enabled = self.config.get('enable_error_recovery', True)
        self.comprehensive_logging = self.config.get('enable_comprehensive_logging', True)
        
        # Performance components (lazy loading)
        self._adaptive_scanner = None
        self.performance_metrics = None
        
        self.supported_extensions = {
            '.py': 'python',
            '.java': 'java',
            '.go': 'go',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'javascript',
            '.tsx': 'typescript',
            '.c': 'c',
            '.cpp': 'cpp',
            '.cc': 'cpp',
            '.cxx': 'cpp',
            '.h': 'c',
            '.hpp': 'cpp',
            '.hxx': 'cpp',
            '.cs': 'csharp',
            '.php': 'php',
            '.rb': 'ruby',
            '.rs': 'rust',
            '.kt': 'kotlin',
            '.swift': 'swift'
        }
        self.patterns = CryptoPatterns()
        
        # Statistics tracking
        self.stats = {
            'files_processed': 0,
            'files_skipped': 0,
            'errors_encountered': 0,
            'scan_start_time': None,
            'vulnerabilities_found': 0
        }

    @ExceptionHandler.handle_scan_exception
    def scan_directory(self, path: str, **kwargs) -> ScanResults:
        """Scan a directory for quantum-vulnerable cryptography.
        
        Args:
            path: Directory path to scan
            **kwargs: Additional scanning options
            
        Returns:
            ScanResults containing vulnerabilities and metadata
            
        Raises:
            ScanException: If scanning fails
            ValidationException: If path validation fails
            SecurityException: If security validation fails
        """
        # Generation 2: Enhanced input sanitization
        if self.input_sanitizer and ENHANCED_FEATURES_AVAILABLE:
            path = self.input_sanitizer.sanitize_path(path)
        
        # Initialize statistics
        self.stats = {
            'files_processed': 0,
            'files_skipped': 0,
            'errors_encountered': 0,
            'scan_start_time': time.time(),
            'vulnerabilities_found': 0
        }
        
        start_time = time.time()
        
        # Generation 2: Enhanced logging
        if self.comprehensive_logging:
            self.logger.log_scan_start(path, {
                'kwargs': kwargs,
                'max_scan_time': self.max_scan_time,
                'max_files_per_scan': self.max_files_per_scan,
                'security_validation_enabled': self.enable_security_validation
            })
        
        # Generation 2: Resilient operation context
        if self.resilience_manager and ENHANCED_FEATURES_AVAILABLE:
            with self.resilience_manager.resilient_operation('scan_directory', {'path': path}):
                return self._execute_scan_with_resilience(path, start_time, **kwargs)
        else:
            return self._execute_scan_basic(path, start_time, **kwargs)
    
    def _execute_scan_with_resilience(self, path: str, start_time: float, **kwargs) -> ScanResults:
        """Execute scan with enhanced resilience features.
        
        Args:
            path: Directory path to scan
            start_time: Scan start time
            **kwargs: Additional scanning options
            
        Returns:
            ScanResults containing vulnerabilities and metadata
        """
        # Generation 2: Security monitoring context
        with self.security_monitor.secure_scan_context(path) as scan_id:
            return self._execute_core_scan(path, start_time, scan_id, **kwargs)
    
    def _execute_scan_basic(self, path: str, start_time: float, **kwargs) -> ScanResults:
        """Execute basic scan without enhanced features.
        
        Args:
            path: Directory path to scan
            start_time: Scan start time
            **kwargs: Additional scanning options
            
        Returns:
            ScanResults containing vulnerabilities and metadata
        """
        return self._execute_core_scan(path, start_time, None, **kwargs)
    
    def _execute_core_scan(self, path: str, start_time: float, scan_id: Optional[str], **kwargs) -> ScanResults:
        
        # Validate input path
        if self._input_validator is None:
            from .validators import InputValidator
            self._input_validator = InputValidator()
        validation_result = self._input_validator.validate_scan_path(path)
        if not validation_result.is_valid:
            raise ValidationException(
                f"Path validation failed: {validation_result.error_message}",
                error_code="INVALID_SCAN_PATH"
            )
        
        # Log warnings from validation
        for warning in validation_result.warnings:
            if hasattr(self.logger, 'logger'):
                self.logger.logger.warning(f"Path validation warning: {warning}")
            else:
                self.logger.warning(f"Path validation warning: {warning}")
        
        results = ScanResults(
            scan_path=path,
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
            scan_stats=ScanStats(
                scan_start_time=start_time,
                files_processed=0,
                files_skipped=0,
                errors_encountered=0,
                vulnerabilities_found=0
            )
        )
        
        path_obj = Path(path).resolve()
        if not path_obj.exists():
            raise FileSystemException(f"Path does not exist: {path_obj}", error_code="PATH_NOT_FOUND")
        
        if not os.access(path_obj, os.R_OK):
            raise InsufficientPermissionsException(str(path_obj), "read")
        
        try:
            exclude_patterns = kwargs.get('exclude_patterns', [
                '*/node_modules/*', '*/venv/*', '*/build/*', '*/dist/*',
                '*/.git/*', '*/tests/*', '*/test/*'
            ])
            
            # Handle custom patterns if provided
            custom_patterns = kwargs.get('custom_patterns', {})
            if custom_patterns:
                self._initialize_custom_analyzer(custom_patterns)
            
            # Handle incremental scanning
            incremental = kwargs.get('incremental', False)
            if incremental:
                if hasattr(self.logger, 'logger'):
                    self.logger.logger.debug("Incremental scanning enabled")
                else:
                    self.logger.debug("Incremental scanning enabled")
            else:
                # Reset processed files for non-incremental scans
                self._processed_files = set()
            
            # Get timeout from config or kwargs
            timeout_seconds = kwargs.get('timeout', self.max_scan_time)
            
            languages_found = set()
            
            # Find source files with error handling
            try:
                source_files = self._find_source_files(path_obj, exclude_patterns)
            except Exception as e:
                raise ScanException(
                    f"Failed to enumerate source files: {str(e)}",
                    error_code="FILE_ENUMERATION_FAILED"
                )
            
            # Check if we have too many files
            if len(source_files) > self.max_files_per_scan:
                if hasattr(self.logger, 'logger'):
                    self.logger.logger.warning(
                        f"Large scan detected: {len(source_files)} files (limit: {self.max_files_per_scan})"
                    )
                else:
                    self.logger.warning(
                        f"Large scan detected: {len(source_files)} files (limit: {self.max_files_per_scan})"
                    )
                source_files = source_files[:self.max_files_per_scan]
            
            # Scan files with timeout protection
            with self._timeout_context(timeout_seconds):
                for file_path in source_files:
                    try:
                        # Check timeout periodically
                        if time.time() - start_time > timeout_seconds:
                            raise ScanTimeoutException(timeout_seconds, self.stats['files_processed'])
                        
                        # Skip already processed files in incremental mode
                        if incremental and str(file_path) in self._processed_files:
                            self.stats['files_skipped'] += 1
                            continue
                        
                        # Validate file before scanning
                        if self._input_validator is None:
                            from .validators import InputValidator
                            self._input_validator = InputValidator()
                        file_validation = self._input_validator.validate_file_for_scanning(file_path)
                        if not file_validation.is_valid:
                            self.logger.warning(f"Skipping file: {file_validation.error_message}")
                            self.stats['files_skipped'] += 1
                            continue
                        
                        # Log file validation warnings
                        for warning in file_validation.warnings:
                            self.logger.warning(f"File warning: {warning}")
                        
                        language = self._detect_language(file_path)
                        if language:
                            languages_found.add(language)
                            file_vulnerabilities = self._scan_file_safely(file_path, language, custom_patterns)
                            results.vulnerabilities.extend(file_vulnerabilities)
                            self.stats['vulnerabilities_found'] += len(file_vulnerabilities)
                            results.scanned_files += 1
                            self.stats['files_processed'] += 1
                            
                            # Mark file as processed for incremental scanning
                            self._processed_files.add(str(file_path))
                            
                            # Count lines safely
                            try:
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    results.total_lines += sum(1 for _ in f)
                            except Exception as e:
                                self.logger.warning(f"Could not count lines in {file_path}: {e}")
                        else:
                            self.stats['files_skipped'] += 1
                            
                    except Exception as e:
                        self.stats['errors_encountered'] += 1
                        self.logger.error(f"Error scanning file {file_path}: {str(e)}")
                        
                        # Don't fail entire scan for individual file errors
                        if self.stats['errors_encountered'] > 100:  # Reasonable error threshold
                            raise ScanException(
                                f"Too many file scan errors ({self.stats['errors_encountered']})",
                                error_code="EXCESSIVE_SCAN_ERRORS"
                            )
            
            results.languages_detected = list(languages_found)
            results.scan_time = time.time() - start_time
            
            # Update scan stats
            if results.scan_stats:
                results.scan_stats.files_processed = self.stats['files_processed']
                results.scan_stats.files_skipped = self.stats['files_skipped']
                results.scan_stats.errors_encountered = self.stats['errors_encountered']
                results.scan_stats.vulnerabilities_found = self.stats['vulnerabilities_found']
            
            # Validate scan results if security validation enabled
            if self.enable_security_validation:
                if self._security_validator is None:
                    from .validators import SecurityValidator
                    self._security_validator = SecurityValidator()
                security_validation = self._security_validator.validate_scan_results(results)
                if not security_validation.is_valid:
                    raise SecurityException(
                        f"Security validation failed: {security_validation.error_message}",
                        error_code="SECURITY_VALIDATION_FAILED"
                    )
                
                # Log security warnings
                for warning in security_validation.warnings:
                    if hasattr(self.logger, 'logger'):
                        self.logger.logger.warning(f"Security warning: {warning}")
                    else:
                        self.logger.warning(f"Security warning: {warning}")
            
            # Log scan statistics
            if hasattr(self.logger, 'logger'):
                self.logger.logger.info(
                    f"Scan completed: {self.stats['files_processed']} files processed, "
                    f"{self.stats['files_skipped']} skipped, {self.stats['errors_encountered']} errors, "
                    f"{self.stats['vulnerabilities_found']} vulnerabilities found"
                )
            else:
                self.logger.info(
                    f"Scan completed: {self.stats['files_processed']} files processed, "
                    f"{self.stats['files_skipped']} skipped, {self.stats['errors_encountered']} errors, "
                    f"{self.stats['vulnerabilities_found']} vulnerabilities found"
                )
            
            return results
            
        except (ScanException, ValidationException, SecurityException):
            # Re-raise our custom exceptions
            raise
        except Exception as e:
            # Wrap unexpected exceptions
            raise ScanException(
                f"Unexpected error during scan: {str(e)}",
                error_code="UNEXPECTED_SCAN_ERROR",
                details={"scan_stats": self.stats}
            )

    def _find_source_files(self, path: Path, exclude_patterns: List[str]) -> List[Path]:
        """Find source code files to scan with robust error handling.
        
        Args:
            path: Directory path to search
            exclude_patterns: Patterns to exclude from scanning
            
        Returns:
            List of source file paths
            
        Raises:
            FileSystemException: If file system operations fail
        """
        files = []
        
        try:
            if path.is_file():
                if self._should_scan_file(path, exclude_patterns):
                    files.append(path)
            else:
                # Use iterative approach for large directories to avoid recursion limits
                directories_to_process = [path]
                files_processed = 0
                
                while directories_to_process:
                    current_dir = directories_to_process.pop(0)
                    
                    try:
                        # Check directory permissions
                        if not os.access(current_dir, os.R_OK):
                            self.logger.warning(f"Skipping unreadable directory: {current_dir}")
                            continue
                        
                        # Process directory contents
                        for item in current_dir.iterdir():
                            files_processed += 1
                            
                            # Prevent infinite processing
                            if files_processed > self.max_files_per_scan * 10:  # Safety margin
                                self.logger.warning(f"File enumeration limit reached: {files_processed}")
                                break
                            
                            if item.is_file():
                                if self._should_scan_file(item, exclude_patterns):
                                    files.append(item)
                            elif item.is_dir() and not item.is_symlink():  # Avoid symlink loops
                                if not self._is_excluded_directory(item, exclude_patterns):
                                    directories_to_process.append(item)
                                    
                    except PermissionError:
                        self.logger.warning(f"Permission denied accessing directory: {current_dir}")
                        continue
                    except OSError as e:
                        self.logger.warning(f"OS error accessing directory {current_dir}: {e}")
                        continue
            
            # Sort files for consistent processing order
            files.sort()
            return files
            
        except Exception as e:
            raise FileSystemException(
                f"Failed to find source files in {path}: {str(e)}",
                error_code="FILE_ENUMERATION_ERROR"
            )
    
    def _is_excluded_directory(self, dir_path: Path, exclude_patterns: List[str]) -> bool:
        """Check if directory should be excluded from scanning.
        
        Args:
            dir_path: Directory path to check
            exclude_patterns: Patterns to exclude
            
        Returns:
            True if directory should be excluded
        """
        dir_str = str(dir_path)
        dir_name = dir_path.name
        
        # Check against exclude patterns
        for pattern in exclude_patterns:
            pattern_regex = pattern.replace('*', '.*')
            if re.search(pattern_regex, dir_str) or re.search(pattern_regex, dir_name):
                return True
        
        # Additional safety exclusions
        dangerous_dirs = {'.git', '.svn', '.hg', 'node_modules', '__pycache__', '.pytest_cache'}
        if dir_name in dangerous_dirs:
            return True
        
        return False

    def _should_scan_file(self, file_path: Path, exclude_patterns: List[str]) -> bool:
        """Check if a file should be scanned.
        
        Args:
            file_path: Path to the file
            exclude_patterns: Patterns to exclude
            
        Returns:
            True if file should be scanned
        """
        if file_path.suffix not in self.supported_extensions:
            return False
            
        file_str = str(file_path)
        for pattern in exclude_patterns:
            pattern_regex = pattern.replace('*', '.*')
            if re.search(pattern_regex, file_str):
                return False
                
        return True

    def _detect_language(self, file_path: Path) -> Optional[str]:
        """Detect programming language from file extension.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Language name or None if not supported
        """
        return self.supported_extensions.get(file_path.suffix)

    def _scan_file_safely(self, file_path: Path, language: str, custom_patterns: Dict[str, Any] = None) -> List[Vulnerability]:
        """Safely scan a single file for cryptographic vulnerabilities.
        
        Args:
            file_path: Path to the file to scan
            language: Programming language of the file
            
        Returns:
            List of vulnerabilities found
            
        Raises:
            Does not raise exceptions - logs errors and returns empty list on failures
        """
        vulnerabilities = []
        
        try:
            # Check file size before reading
            file_size = file_path.stat().st_size
            if self._input_validator is None:
                from .validators import InputValidator
                self._input_validator = InputValidator()
            if file_size > self._input_validator.max_file_size:
                self.logger.warning(
                    f"File too large to scan: {file_path} ({file_size} bytes)"
                )
                return vulnerabilities
            
            # Read file content safely
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')
            except UnicodeDecodeError:
                # Try alternative encodings
                encodings = ['latin-1', 'cp1252', 'iso-8859-1']
                content = None
                for encoding in encodings:
                    try:
                        with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                            content = f.read()
                            lines = content.split('\n')
                        break
                    except Exception:
                        continue
                
                if content is None:
                    self.logger.warning(f"Could not decode file: {file_path}")
                    return vulnerabilities
            
            # Scan based on language with error handling
            try:
                if language == 'python':
                    vulnerabilities.extend(self._scan_python_file(file_path, content, lines))
                elif language == 'java':
                    vulnerabilities.extend(self._scan_java_file(file_path, content, lines))
                elif language == 'go':
                    vulnerabilities.extend(self._scan_go_file(file_path, content, lines))
                elif language in ['javascript', 'typescript']:
                    vulnerabilities.extend(self._scan_javascript_file(file_path, content, lines, language))
                elif language in ['c', 'cpp']:
                    vulnerabilities.extend(self._scan_c_cpp_file(file_path, content, lines, language))
                else:
                    self.logger.debug(f"Unsupported language for scanning: {language}")
                    
            except Exception as e:
                self.logger.error(f"Error scanning {language} file {file_path}: {str(e)}")
                return vulnerabilities
            
            # Check for custom patterns if provided
            if custom_patterns:
                try:
                    custom_vulns = self._analyze_custom_patterns(file_path, content, custom_patterns)
                    vulnerabilities.extend(custom_vulns)
                except Exception as e:
                    self.logger.error(f"Custom pattern analysis failed for {file_path}: {e}")
            
            # Validate found vulnerabilities
            validated_vulnerabilities = []
            for vuln in vulnerabilities:
                if self._validate_vulnerability(vuln):
                    validated_vulnerabilities.append(vuln)
                else:
                    self.logger.warning(f"Invalid vulnerability detected in {file_path}:{vuln.line_number}")
            
            return validated_vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Unexpected error scanning file {file_path}: {str(e)}")
            return vulnerabilities
    
    def _validate_vulnerability(self, vulnerability: Vulnerability) -> bool:
        """Validate a vulnerability object for correctness.
        
        Args:
            vulnerability: Vulnerability to validate
            
        Returns:
            True if vulnerability is valid, False otherwise
        """
        try:
            # Check required fields
            if not vulnerability.file_path or not vulnerability.description:
                return False
            
            # Check line number is reasonable
            if vulnerability.line_number < 1 or vulnerability.line_number > 1000000:
                return False
            
            # Check algorithm and severity are valid enums
            if not isinstance(vulnerability.algorithm, CryptoAlgorithm):
                return False
                
            if not isinstance(vulnerability.severity, Severity):
                return False
            
            return True
            
        except Exception:
            return False
    
    @contextmanager
    def _timeout_context(self, timeout_seconds: int):
        """Context manager for scan timeout protection.
        
        Args:
            timeout_seconds: Timeout in seconds
        """
        start_time = time.time()
        try:
            yield
        finally:
            elapsed = time.time() - start_time
            if elapsed > timeout_seconds:
                self.logger.warning(f"Scan exceeded timeout: {elapsed:.2f}s > {timeout_seconds}s")

    def _scan_javascript_file(self, file_path: Path, content: str, lines: List[str], language: str) -> List[Vulnerability]:
        """Scan JavaScript/TypeScript file for cryptographic vulnerabilities."""
        vulnerabilities = []
        
        # RSA vulnerabilities
        for pattern in self.patterns.JAVASCRIPT_PATTERNS['rsa_generation']:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(Vulnerability(
                    file_path=str(file_path),
                    line_number=line_num,
                    algorithm=CryptoAlgorithm.RSA,
                    severity=Severity.HIGH,
                    description=f"RSA cryptography detected in {language} (quantum-vulnerable)",
                    code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    recommendation="Replace with Web Crypto API post-quantum alternatives or migrate to PQC libraries",
                    cwe_id="CWE-327"
                ))
        
        # ECC vulnerabilities
        for pattern in self.patterns.JAVASCRIPT_PATTERNS['ecc_generation']:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(Vulnerability(
                    file_path=str(file_path),
                    line_number=line_num,
                    algorithm=CryptoAlgorithm.ECC,
                    severity=Severity.HIGH,
                    description=f"ECC cryptography detected in {language} (quantum-vulnerable)",
                    code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    recommendation="Replace with post-quantum digital signature schemes",
                    cwe_id="CWE-327"
                ))
        
        # Legacy crypto vulnerabilities
        for pattern in self.patterns.JAVASCRIPT_PATTERNS['legacy_crypto']:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(Vulnerability(
                    file_path=str(file_path),
                    line_number=line_num,
                    algorithm=CryptoAlgorithm.RSA,  # Generic legacy crypto
                    severity=Severity.MEDIUM,
                    description=f"Legacy hash function detected in {language}",
                    code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    recommendation="Upgrade to SHA-256 or SHA-3 hash functions",
                    cwe_id="CWE-327"
                ))
        
        return vulnerabilities

    def _scan_c_cpp_file(self, file_path: Path, content: str, lines: List[str], language: str) -> List[Vulnerability]:
        """Scan C/C++ file for cryptographic vulnerabilities."""
        vulnerabilities = []
        
        # OpenSSL RSA vulnerabilities
        for pattern in self.patterns.C_CPP_PATTERNS['openssl_rsa']:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(Vulnerability(
                    file_path=str(file_path),
                    line_number=line_num,
                    algorithm=CryptoAlgorithm.RSA,
                    severity=Severity.HIGH,
                    description=f"OpenSSL RSA usage detected in {language} (quantum-vulnerable)",
                    code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    recommendation="Migrate to liboqs (Open Quantum Safe) for post-quantum cryptography",
                    cwe_id="CWE-327"
                ))
        
        # OpenSSL ECC vulnerabilities
        for pattern in self.patterns.C_CPP_PATTERNS['openssl_ecc']:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(Vulnerability(
                    file_path=str(file_path),
                    line_number=line_num,
                    algorithm=CryptoAlgorithm.ECC,
                    severity=Severity.HIGH,
                    description=f"OpenSSL ECC usage detected in {language} (quantum-vulnerable)",
                    code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    recommendation="Replace with post-quantum signatures using liboqs",
                    cwe_id="CWE-327"
                ))
        
        # Legacy function vulnerabilities
        for pattern in self.patterns.C_CPP_PATTERNS['legacy_functions']:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(Vulnerability(
                    file_path=str(file_path),
                    line_number=line_num,
                    algorithm=CryptoAlgorithm.RSA,  # Generic legacy
                    severity=Severity.MEDIUM,
                    description=f"Legacy cryptographic function detected in {language}",
                    code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    recommendation="Replace with modern cryptographic functions",
                    cwe_id="CWE-327"
                ))
        
        return vulnerabilities

    def _scan_python_file(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        """Scan Python file for cryptographic vulnerabilities."""
        vulnerabilities = []
        
        # RSA vulnerabilities
        for pattern in self.patterns.PYTHON_PATTERNS['rsa_generation']:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                severity, key_size = self._analyze_rsa_usage(lines[line_num - 1] if line_num <= len(lines) else "")
                
                vulnerabilities.append(Vulnerability(
                    file_path=str(file_path),
                    line_number=line_num,
                    algorithm=CryptoAlgorithm.RSA,
                    severity=severity,
                    key_size=key_size,
                    description=f"RSA key generation detected (quantum-vulnerable)",
                    code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    recommendation="Replace with ML-KEM (Kyber) for key exchange or ML-DSA (Dilithium) for signatures",
                    cwe_id="CWE-327"
                ))
        
        # ECC vulnerabilities
        for pattern in self.patterns.PYTHON_PATTERNS['ecc_generation']:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(Vulnerability(
                    file_path=str(file_path),
                    line_number=line_num,
                    algorithm=CryptoAlgorithm.ECC,
                    severity=Severity.HIGH,
                    description="ECC key generation detected (quantum-vulnerable)",
                    code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    recommendation="Replace with ML-DSA (Dilithium) for signatures or ML-KEM (Kyber) for key exchange",
                    cwe_id="CWE-327"
                ))
        
        # DSA vulnerabilities
        for pattern in self.patterns.PYTHON_PATTERNS['dsa_generation']:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(Vulnerability(
                    file_path=str(file_path),
                    line_number=line_num,
                    algorithm=CryptoAlgorithm.DSA,
                    severity=Severity.HIGH,
                    description="DSA key generation detected (quantum-vulnerable)",
                    code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    recommendation="Replace with ML-DSA (Dilithium) for digital signatures",
                    cwe_id="CWE-327"
                ))
        
        return vulnerabilities

    def _scan_java_file(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        """Scan Java file for cryptographic vulnerabilities."""
        vulnerabilities = []
        
        for pattern in self.patterns.JAVA_PATTERNS['rsa_generation']:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(Vulnerability(
                    file_path=str(file_path),
                    line_number=line_num,
                    algorithm=CryptoAlgorithm.RSA,
                    severity=Severity.HIGH,
                    description="RSA KeyPairGenerator detected (quantum-vulnerable)",
                    code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    recommendation="Migrate to post-quantum key exchange using ML-KEM (Kyber)",
                    cwe_id="CWE-327"
                ))
        
        return vulnerabilities

    def _scan_go_file(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        """Scan Go file for cryptographic vulnerabilities."""
        vulnerabilities = []
        
        for pattern in self.patterns.GO_PATTERNS['rsa_generation']:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(Vulnerability(
                    file_path=str(file_path),
                    line_number=line_num,
                    algorithm=CryptoAlgorithm.RSA,
                    severity=Severity.HIGH,
                    description="RSA key generation detected (quantum-vulnerable)",
                    code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    recommendation="Replace with post-quantum cryptography using liboqs Go bindings",
                    cwe_id="CWE-327"
                ))
        
        return vulnerabilities

    def _analyze_rsa_usage(self, code_line: str) -> Tuple[Severity, Optional[int]]:
        """Analyze RSA usage to determine severity and key size.
        
        Args:
            code_line: Line of code containing RSA usage
            
        Returns:
            Tuple of (severity, key_size)
        """
        # Look for key_size parameter
        key_size_match = re.search(r'key_size\s*=\s*(\d+)', code_line)
        if key_size_match:
            key_size = int(key_size_match.group(1))
            if key_size < 2048:
                return Severity.CRITICAL, key_size
            elif key_size < 4096:
                return Severity.HIGH, key_size
            else:
                return Severity.MEDIUM, key_size
        
        return Severity.HIGH, None

    def create_migration_plan(self, results: ScanResults) -> Dict[str, Any]:
        """Create a migration plan based on scan results.
        
        Args:
            results: Scan results containing vulnerabilities
            
        Returns:
            Migration plan with prioritized recommendations
        """
        plan = {
            "summary": {
                "total_vulnerabilities": len(results.vulnerabilities),
                "critical": len([v for v in results.vulnerabilities if v.severity == Severity.CRITICAL]),
                "high": len([v for v in results.vulnerabilities if v.severity == Severity.HIGH]),
                "medium": len([v for v in results.vulnerabilities if v.severity == Severity.MEDIUM]),
                "low": len([v for v in results.vulnerabilities if v.severity == Severity.LOW]),
            },
            "migration_phases": [
                {
                    "phase": 1,
                    "name": "Critical Vulnerabilities",
                    "description": "Address all critical and high-severity vulnerabilities",
                    "vulnerabilities": [v for v in results.vulnerabilities if v.severity in [Severity.CRITICAL, Severity.HIGH]],
                    "estimated_effort": "2-4 weeks"
                },
                {
                    "phase": 2,
                    "name": "Medium Priority Items",
                    "description": "Address medium-severity vulnerabilities",
                    "vulnerabilities": [v for v in results.vulnerabilities if v.severity == Severity.MEDIUM],
                    "estimated_effort": "1-2 weeks"
                },
                {
                    "phase": 3,
                    "name": "Cleanup and Optimization",
                    "description": "Address remaining low-severity items and optimize",
                    "vulnerabilities": [v for v in results.vulnerabilities if v.severity == Severity.LOW],
                    "estimated_effort": "1 week"
                }
            ],
            "recommendations": {
                "immediate_actions": [
                    "Inventory all cryptographic implementations",
                    "Prioritize customer-facing and critical system components",
                    "Begin testing PQC alternatives in development environment"
                ],
                "pqc_algorithms": {
                    "key_exchange": "ML-KEM (Kyber) - NIST standardized",
                    "digital_signatures": "ML-DSA (Dilithium) - NIST standardized",
                    "alternative_signatures": "SLH-DSA (SPHINCS+) - Hash-based signatures"
                },
                "migration_strategy": "Hybrid approach during transition period (2025-2027)"
            }
        }
        
        return plan
    
    def _initialize_custom_analyzer(self, custom_patterns: Dict[str, Any]):
        """Initialize custom pattern analyzer."""
        self.custom_patterns = custom_patterns
        # Use safe logging that works with both AuditLogger and standard Logger
        if hasattr(self.logger, 'debug'):
            self.logger.debug(f"Initialized custom analyzer with {len(custom_patterns)} patterns")
        elif hasattr(self.logger, 'logger') and hasattr(self.logger.logger, 'debug'):
            self.logger.logger.debug(f"Initialized custom analyzer with {len(custom_patterns)} patterns")
        else:
            print(f"DEBUG: Initialized custom analyzer with {len(custom_patterns)} patterns")
    
    def _analyze_custom_patterns(self, file_path: Path, content: str, custom_patterns: Dict[str, Any]) -> List[Vulnerability]:
        """Analyze content with custom patterns."""
        vulnerabilities = []
        lines = content.split('\n')
        
        for pattern_name, pattern_config in custom_patterns.items():
            try:
                pattern = pattern_config.get('pattern', '')
                severity_str = pattern_config.get('severity', 'HIGH')
                description = pattern_config.get('description', f'Custom pattern {pattern_name} detected')
                # Ensure pattern name is in description for searchability
                if pattern_name not in description:
                    description = f'{description} ({pattern_name})'
                
                # Convert severity string to enum
                try:
                    severity = Severity(severity_str.lower())
                except ValueError:
                    severity = Severity.HIGH
                
                # Find matches
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    line_num = content[:match.start()].count('\n') + 1
                    code_snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                    
                    vulnerability = Vulnerability(
                        file_path=str(file_path),
                        line_number=line_num,
                        algorithm=CryptoAlgorithm.RSA,  # Generic
                        severity=severity,
                        description=description,
                        code_snippet=code_snippet,
                        recommendation="Review and migrate to secure alternatives",
                        cwe_id="CWE-327"
                    )
                    
                    vulnerabilities.append(vulnerability)
            except Exception as e:
                self.logger.error(f"Error processing custom pattern {pattern_name}: {e}")
        
        return vulnerabilities


class RiskAssessment:
    """Risk assessment for quantum-vulnerable cryptography."""

    def __init__(self, scan_results: ScanResults):
        """Initialize risk assessment with scan results.
        
        Args:
            scan_results: Results from CryptoAuditor scan
        """
        self.results = scan_results

    def calculate_harvest_now_decrypt_later_risk(self) -> int:
        """Calculate HNDL (Harvest Now, Decrypt Later) risk score.
        
        Returns:
            Risk score from 0-100
        """
        if not self.results.vulnerabilities:
            return 0
        
        # Risk factors
        vulnerability_count = len(self.results.vulnerabilities)
        critical_count = len([v for v in self.results.vulnerabilities if v.severity == Severity.CRITICAL])
        high_count = len([v for v in self.results.vulnerabilities if v.severity == Severity.HIGH])
        
        # Algorithm-specific risk weights
        algorithm_weights = {
            CryptoAlgorithm.RSA: 0.8,  # High risk for RSA
            CryptoAlgorithm.ECC: 0.9,  # Higher risk for ECC (easier to break)
            CryptoAlgorithm.DSA: 0.7,
            CryptoAlgorithm.DH: 0.8,
            CryptoAlgorithm.ECDSA: 0.9,
            CryptoAlgorithm.ECDH: 0.9
        }
        
        # Calculate weighted algorithm risk
        algorithm_risk = 0
        for vuln in self.results.vulnerabilities:
            weight = algorithm_weights.get(vuln.algorithm, 0.5)
            if vuln.severity == Severity.CRITICAL:
                algorithm_risk += weight * 25
            elif vuln.severity == Severity.HIGH:
                algorithm_risk += weight * 15
            elif vuln.severity == Severity.MEDIUM:
                algorithm_risk += weight * 10
            else:
                algorithm_risk += weight * 5
        
        # Normalize to 0-100 scale
        base_risk = min(algorithm_risk, 100)
        
        # Apply time pressure factor (quantum threat timeline)
        # Assuming current year is 2025, with quantum threat by 2030
        timeline_factor = 1.2  # Increasing urgency
        
        final_risk = min(int(base_risk * timeline_factor), 100)
        
        return final_risk

    @property
    def migration_hours(self) -> int:
        """Estimate migration effort in hours.
        
        Returns:
            Estimated hours needed for migration
        """
        if not self.results.vulnerabilities:
            return 0
        
        # Base effort estimates per vulnerability type
        effort_map = {
            Severity.CRITICAL: 16,  # 2 days per critical
            Severity.HIGH: 8,       # 1 day per high
            Severity.MEDIUM: 4,     # Half day per medium
            Severity.LOW: 2         # Quarter day per low
        }
        
        total_hours = 0
        for vuln in self.results.vulnerabilities:
            total_hours += effort_map.get(vuln.severity, 2)
        
        # Add overhead for testing and integration (25%)
        total_hours = int(total_hours * 1.25)
        
        return total_hours

    def generate_risk_report(self) -> Dict[str, Any]:
        """Generate comprehensive risk assessment report.
        
        Returns:
            Risk assessment report
        """
        hndl_risk = self.calculate_harvest_now_decrypt_later_risk()
        
        report = {
            "risk_summary": {
                "hndl_risk_score": hndl_risk,
                "risk_level": self._get_risk_level(hndl_risk),
                "total_vulnerabilities": len(self.results.vulnerabilities),
                "migration_effort_hours": self.migration_hours,
                "scan_metadata": {
                    "files_scanned": self.results.scanned_files,
                    "lines_analyzed": self.results.total_lines,
                    "scan_duration": f"{self.results.scan_time:.2f}s",
                    "languages_detected": self.results.languages_detected
                }
            },
            "vulnerability_breakdown": {
                "by_severity": self._get_severity_breakdown(),
                "by_algorithm": self._get_algorithm_breakdown(),
                "by_file": self._get_file_breakdown()
            },
            "recommendations": self._generate_recommendations(hndl_risk)
        }
        
        return report

    def _get_risk_level(self, risk_score: int) -> str:
        """Convert numeric risk score to risk level."""
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 60:
            return "HIGH"
        elif risk_score >= 40:
            return "MEDIUM"
        elif risk_score >= 20:
            return "LOW"
        else:
            return "MINIMAL"

    def _get_severity_breakdown(self) -> Dict[str, int]:
        """Get vulnerability count by severity."""
        breakdown = {severity.value: 0 for severity in Severity}
        for vuln in self.results.vulnerabilities:
            breakdown[vuln.severity.value] += 1
        return breakdown

    def _get_algorithm_breakdown(self) -> Dict[str, int]:
        """Get vulnerability count by algorithm."""
        breakdown = {}
        for vuln in self.results.vulnerabilities:
            algo = vuln.algorithm.value
            breakdown[algo] = breakdown.get(algo, 0) + 1
        return breakdown

    def _get_file_breakdown(self) -> Dict[str, int]:
        """Get vulnerability count by file."""
        breakdown = {}
        for vuln in self.results.vulnerabilities:
            file_path = vuln.file_path
            breakdown[file_path] = breakdown.get(file_path, 0) + 1
        return breakdown

    def _generate_recommendations(self, risk_score: int) -> List[str]:
        """Generate recommendations based on risk score."""
        recommendations = [
            "Begin immediate inventory of all cryptographic implementations",
            "Establish PQC migration timeline with 2027 deadline",
            "Test ML-KEM (Kyber) and ML-DSA (Dilithium) in development environment"
        ]
        
        if risk_score >= 80:
            recommendations.extend([
                "URGENT: Address critical vulnerabilities within 30 days",
                "Implement crypto-agility framework immediately",
                "Consider hybrid classical+PQC approach for critical systems"
            ])
        elif risk_score >= 60:
            recommendations.extend([
                "Prioritize high-risk components for immediate attention",
                "Begin pilot PQC implementation in non-critical systems",
                "Establish regular security scanning in CI/CD pipeline"
            ])
        
        return recommendations