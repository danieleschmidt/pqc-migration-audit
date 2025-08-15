"""Advanced logging configuration for PQC Migration Audit."""

import logging
import logging.handlers
import json
import sys
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
import os


class StructuredFormatter(logging.Formatter):
    """Structured JSON formatter for logs."""
    
    def format(self, record):
        """Format log record as structured JSON."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                          'filename', 'module', 'exc_info', 'exc_text', 'stack_info',
                          'lineno', 'funcName', 'created', 'msecs', 'relativeCreated',
                          'thread', 'threadName', 'processName', 'process', 'getMessage']:
                log_entry[key] = value
        
        return json.dumps(log_entry)


class SecurityFilter(logging.Filter):
    """Filter to sanitize security-sensitive information from logs."""
    
    SENSITIVE_PATTERNS = [
        'password', 'passwd', 'secret', 'token', 'key', 'auth',
        'credential', 'private', 'confidential'
    ]
    
    def filter(self, record):
        """Filter out sensitive information."""
        message = str(record.getMessage()).lower()
        
        # Check for sensitive patterns
        for pattern in self.SENSITIVE_PATTERNS:
            if pattern in message:
                record.msg = "[REDACTED - Sensitive information filtered]"
                break
        
        return True


class PerformanceFilter(logging.Filter):
    """Filter to add performance metrics to logs."""
    
    def filter(self, record):
        """Add performance context to log records."""
        # Add memory usage
        try:
            import psutil
            process = psutil.Process()
            record.memory_mb = round(process.memory_info().rss / 1024 / 1024, 2)
            record.cpu_percent = round(process.cpu_percent(), 2)
        except ImportError:
            record.memory_mb = "N/A"
            record.cpu_percent = "N/A"
        
        return True


class LoggingConfig:
    """Advanced logging configuration manager."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize logging configuration.
        
        Args:
            config: Logging configuration options
        """
        self.config = config or {}
        self.log_dir = Path(self.config.get('log_dir', 'logs'))
        self.log_level = getattr(logging, self.config.get('log_level', 'INFO').upper())
        self.enable_file_logging = self.config.get('enable_file_logging', True)
        self.enable_structured_logging = self.config.get('enable_structured_logging', False)
        self.enable_security_filtering = self.config.get('enable_security_filtering', True)
        self.enable_performance_metrics = self.config.get('enable_performance_metrics', False)
        self.max_log_size = self.config.get('max_log_size_mb', 100) * 1024 * 1024
        self.backup_count = self.config.get('backup_count', 5)
        
        self._setup_logging()
    
    def _setup_logging(self):
        """Setup comprehensive logging configuration."""
        # Create log directory
        if self.enable_file_logging:
            self.log_dir.mkdir(exist_ok=True)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(self.log_level)
        
        # Clear existing handlers
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Setup console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(self.log_level)
        
        if self.enable_structured_logging:
            console_handler.setFormatter(StructuredFormatter())
        else:
            console_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            console_handler.setFormatter(console_formatter)
        
        # Add filters
        if self.enable_security_filtering:
            console_handler.addFilter(SecurityFilter())
        
        if self.enable_performance_metrics:
            console_handler.addFilter(PerformanceFilter())
        
        root_logger.addHandler(console_handler)
        
        # Setup file handlers if enabled
        if self.enable_file_logging:
            self._setup_file_handlers()
    
    def _setup_file_handlers(self):
        """Setup file-based logging handlers."""
        root_logger = logging.getLogger()
        
        # Main application log
        app_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / 'pqc_audit.log',
            maxBytes=self.max_log_size,
            backupCount=self.backup_count,
            encoding='utf-8'
        )
        app_handler.setLevel(logging.INFO)
        
        if self.enable_structured_logging:
            app_handler.setFormatter(StructuredFormatter())
        else:
            app_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
            )
            app_handler.setFormatter(app_formatter)
        
        # Add filters
        if self.enable_security_filtering:
            app_handler.addFilter(SecurityFilter())
        
        if self.enable_performance_metrics:
            app_handler.addFilter(PerformanceFilter())
        
        root_logger.addHandler(app_handler)
        
        # Error log (errors and above only)
        error_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / 'pqc_audit_errors.log',
            maxBytes=self.max_log_size,
            backupCount=self.backup_count,
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(StructuredFormatter())
        root_logger.addHandler(error_handler)
        
        # Security audit log
        security_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / 'pqc_audit_security.log',
            maxBytes=self.max_log_size,
            backupCount=self.backup_count,
            encoding='utf-8'
        )
        security_handler.setLevel(logging.WARNING)
        security_handler.setFormatter(StructuredFormatter())
        
        # Security logger (separate namespace)
        security_logger = logging.getLogger('pqc_audit.security')
        security_logger.addHandler(security_handler)
        security_logger.setLevel(logging.WARNING)
        security_logger.propagate = False
        
        # Performance log
        if self.enable_performance_metrics:
            perf_handler = logging.handlers.RotatingFileHandler(
                self.log_dir / 'pqc_audit_performance.log',
                maxBytes=self.max_log_size,
                backupCount=self.backup_count,
                encoding='utf-8'
            )
            perf_handler.setLevel(logging.DEBUG)
            perf_handler.setFormatter(StructuredFormatter())
            
            perf_logger = logging.getLogger('pqc_audit.performance')
            perf_logger.addHandler(perf_handler)
            perf_logger.setLevel(logging.DEBUG)
            perf_logger.propagate = False


class AuditLogger:
    """Specialized logger for audit events."""
    
    def __init__(self, name: str = 'pqc_audit'):
        """Initialize audit logger.
        
        Args:
            name: Logger name
        """
        self.logger = logging.getLogger(name)
        self.security_logger = logging.getLogger(f'{name}.security')
        self.performance_logger = logging.getLogger(f'{name}.performance')
    
    def log_scan_start(self, scan_path: str, config: Dict[str, Any]):
        """Log scan start event."""
        self.logger.info(
            "Scan started",
            extra={
                "event_type": "scan_start",
                "scan_path": scan_path,
                "config": config
            }
        )
    
    def log_scan_complete(self, scan_path: str, results: Dict[str, Any]):
        """Log scan completion event."""
        self.logger.info(
            "Scan completed",
            extra={
                "event_type": "scan_complete",
                "scan_path": scan_path,
                "results_summary": results
            }
        )
    
    def log_vulnerability_found(self, vulnerability: Dict[str, Any]):
        """Log vulnerability discovery."""
        self.security_logger.warning(
            "Vulnerability detected",
            extra={
                "event_type": "vulnerability_found",
                "vulnerability": vulnerability
            }
        )
    
    def log_security_event(self, event_type: str, details: Dict[str, Any]):
        """Log security-related events."""
        self.security_logger.warning(
            f"Security event: {event_type}",
            extra={
                "event_type": f"security_{event_type}",
                "details": details
            }
        )
    
    def log_performance_metric(self, metric_name: str, value: float, unit: str = ""):
        """Log performance metrics."""
        self.performance_logger.debug(
            f"Performance metric: {metric_name}",
            extra={
                "event_type": "performance_metric",
                "metric_name": metric_name,
                "value": value,
                "unit": unit
            }
        )
    
    def log_error(self, error: Exception, context: Dict[str, Any] = None):
        """Log error with context."""
        self.logger.error(
            f"Error occurred: {str(error)}",
            extra={
                "event_type": "error",
                "error_type": type(error).__name__,
                "context": context or {},
                "exception": str(error)
            },
            exc_info=True
        )


def setup_logging(config: Optional[Dict[str, Any]] = None) -> AuditLogger:
    """Setup logging configuration and return audit logger.
    
    Args:
        config: Logging configuration
        
    Returns:
        Configured audit logger
    """
    logging_config = LoggingConfig(config)
    return AuditLogger()


def get_logger(name: str = 'pqc_audit') -> AuditLogger:
    """Get audit logger instance.
    
    Args:
        name: Logger name
        
    Returns:
        Audit logger instance
    """
    return AuditLogger(name)