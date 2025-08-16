"""
Enhanced Logging for Generation 2: Make It Robust
Comprehensive logging, audit trails, and monitoring capabilities.
"""

import os
import json
import time
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, asdict
from enum import Enum
import logging
import logging.handlers


class LogLevel(Enum):
    """Enhanced log levels."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    SECURITY = "security"
    AUDIT = "audit"


@dataclass
class AuditEvent:
    """Audit event record."""
    event_id: str
    timestamp: str
    event_type: str
    user_context: str
    action: str
    resource: str
    outcome: str
    details: Dict[str, Any]
    risk_level: str
    correlation_id: Optional[str] = None


class EnhancedLogger:
    """Enhanced logging system with audit trails and security monitoring."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize enhanced logger."""
        self.config = config or {}
        self.session_id = self._generate_session_id()
        self.audit_events: List[AuditEvent] = []
        
        # Configure log levels
        self.log_level = self.config.get('log_level', 'INFO')
        self.audit_enabled = self.config.get('audit_enabled', True)
        self.security_logging = self.config.get('security_logging', True)
        
        # Configure output locations
        self.log_dir = Path(self.config.get('log_dir', '/tmp/pqc_audit_logs'))
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize loggers
        self._setup_loggers()
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID."""
        timestamp = str(time.time())
        random_data = os.urandom(8)
        return hashlib.sha256((timestamp + str(random_data)).encode()).hexdigest()[:16]
    
    def _setup_loggers(self):
        """Set up various specialized loggers."""
        # Main application logger
        self.app_logger = logging.getLogger('pqc_audit.app')
        self.app_logger.setLevel(getattr(logging, self.log_level.upper()))
        
        # Security events logger
        self.security_logger = logging.getLogger('pqc_audit.security')
        self.security_logger.setLevel(logging.INFO)
        
        # Audit trail logger
        self.audit_logger = logging.getLogger('pqc_audit.audit')
        self.audit_logger.setLevel(logging.INFO)
        
        # Performance logger
        self.perf_logger = logging.getLogger('pqc_audit.performance')
        self.perf_logger.setLevel(logging.INFO)
        
        # Configure handlers
        self._setup_handlers()
    
    def _setup_handlers(self):
        """Set up log handlers with rotation and formatting."""
        # Console handler for immediate feedback
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        
        # File handlers with rotation
        app_file_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / 'pqc_audit_app.log',
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        app_file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
        )
        app_file_handler.setFormatter(app_file_formatter)
        
        # Security events handler (JSON format)
        security_file_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / 'pqc_audit_security.log',
            maxBytes=5*1024*1024,  # 5MB
            backupCount=10
        )
        security_formatter = logging.Formatter('%(asctime)s - %(message)s')
        security_file_handler.setFormatter(security_formatter)
        
        # Audit trail handler (JSON format)
        audit_file_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / 'pqc_audit_audit.log',
            maxBytes=5*1024*1024,  # 5MB
            backupCount=10
        )
        audit_formatter = logging.Formatter('%(message)s')
        audit_file_handler.setFormatter(audit_formatter)
        
        # Add handlers to loggers
        self.app_logger.addHandler(console_handler)
        self.app_logger.addHandler(app_file_handler)
        
        self.security_logger.addHandler(security_file_handler)
        self.audit_logger.addHandler(audit_file_handler)
        self.perf_logger.addHandler(app_file_handler)
    
    def log_scan_start(self, scan_path: str, scan_config: Dict[str, Any]):
        """Log scan initiation with full context."""
        self.app_logger.info(f"Starting PQC audit scan on: {scan_path}")
        
        # Security event
        if self.security_logging:
            security_event = {
                'event_type': 'scan_initiated',
                'session_id': self.session_id,
                'scan_path': scan_path,
                'config': scan_config,
                'timestamp': datetime.now().isoformat(),
                'user': os.getenv('USER', 'unknown')
            }
            self.security_logger.info(json.dumps(security_event))
        
        # Audit event
        if self.audit_enabled:
            audit_event = AuditEvent(
                event_id=self._generate_event_id(),
                timestamp=datetime.now().isoformat(),
                event_type='SCAN_START',
                user_context=os.getenv('USER', 'unknown'),
                action='scan_initiate',
                resource=scan_path,
                outcome='initiated',
                details={'config': scan_config, 'session_id': self.session_id},
                risk_level='low'
            )
            self._record_audit_event(audit_event)
    
    def log_vulnerability_found(self, vulnerability_details: Dict[str, Any]):
        """Log vulnerability discovery with security implications."""
        file_path = vulnerability_details.get('file_path', 'unknown')
        severity = vulnerability_details.get('severity', 'unknown')
        algorithm = vulnerability_details.get('algorithm', 'unknown')
        
        self.app_logger.warning(
            f"Quantum-vulnerable crypto found: {algorithm} in {file_path} (severity: {severity})"
        )
        
        # Security event for high/critical vulnerabilities
        if severity.upper() in ['HIGH', 'CRITICAL']:
            security_event = {
                'event_type': 'high_risk_vulnerability_detected',
                'session_id': self.session_id,
                'vulnerability': vulnerability_details,
                'timestamp': datetime.now().isoformat(),
                'requires_attention': True
            }
            self.security_logger.warning(json.dumps(security_event))
        
        # Audit event
        if self.audit_enabled:
            audit_event = AuditEvent(
                event_id=self._generate_event_id(),
                timestamp=datetime.now().isoformat(),
                event_type='VULNERABILITY_DETECTED',
                user_context=os.getenv('USER', 'unknown'),
                action='vulnerability_scan',
                resource=file_path,
                outcome='vulnerability_found',
                details=vulnerability_details,
                risk_level=severity.lower()
            )
            self._record_audit_event(audit_event)
    
    def log_scan_complete(self, scan_results: Dict[str, Any]):
        """Log scan completion with comprehensive results."""
        total_vulns = scan_results.get('total_vulnerabilities', 0)
        files_scanned = scan_results.get('files_scanned', 0)
        scan_time = scan_results.get('scan_time', 0)
        
        self.app_logger.info(
            f"PQC audit scan completed: {total_vulns} vulnerabilities found "
            f"in {files_scanned} files ({scan_time:.2f}s)"
        )
        
        # Performance logging
        self.perf_logger.info(json.dumps({
            'event_type': 'scan_performance',
            'session_id': self.session_id,
            'files_scanned': files_scanned,
            'scan_time_seconds': scan_time,
            'vulnerabilities_found': total_vulns,
            'files_per_second': files_scanned / max(scan_time, 0.1),
            'timestamp': datetime.now().isoformat()
        }))
        
        # Security summary
        if self.security_logging and total_vulns > 0:
            security_summary = {
                'event_type': 'scan_security_summary',
                'session_id': self.session_id,
                'total_vulnerabilities': total_vulns,
                'critical_vulnerabilities': scan_results.get('critical_count', 0),
                'high_vulnerabilities': scan_results.get('high_count', 0),
                'risk_assessment': 'requires_attention' if total_vulns > 0 else 'clean',
                'timestamp': datetime.now().isoformat()
            }
            self.security_logger.info(json.dumps(security_summary))
        
        # Audit completion
        if self.audit_enabled:
            audit_event = AuditEvent(
                event_id=self._generate_event_id(),
                timestamp=datetime.now().isoformat(),
                event_type='SCAN_COMPLETE',
                user_context=os.getenv('USER', 'unknown'),
                action='scan_complete',
                resource=scan_results.get('scan_path', 'unknown'),
                outcome='completed',
                details=scan_results,
                risk_level='medium' if total_vulns > 5 else 'low'
            )
            self._record_audit_event(audit_event)
    
    def log_security_event(self, event_type: str, details: Dict[str, Any], risk_level: str = 'medium'):
        """Log security-specific events."""
        if not self.security_logging:
            return
        
        security_event = {
            'event_type': f'security_{event_type}',
            'session_id': self.session_id,
            'risk_level': risk_level,
            'details': details,
            'timestamp': datetime.now().isoformat(),
            'requires_investigation': risk_level in ['high', 'critical']
        }
        
        log_method = getattr(self.security_logger, risk_level.lower(), self.security_logger.info)
        log_method(json.dumps(security_event))
    
    def log_error_with_context(self, error: Exception, context: Dict[str, Any]):
        """Log errors with full context for debugging."""
        error_details = {
            'error_type': type(error).__name__,
            'error_message': str(error),
            'context': context,
            'session_id': self.session_id,
            'timestamp': datetime.now().isoformat()
        }
        
        self.app_logger.error(f"Error occurred: {error_details}")
        
        # Log as security event if it might be security-related
        if any(keyword in str(error).lower() for keyword in ['permission', 'access', 'security', 'unauthorized']):
            self.log_security_event('error_security_related', error_details, 'high')
    
    def get_audit_trail(self) -> List[Dict[str, Any]]:
        """Get current session audit trail."""
        return [asdict(event) for event in self.audit_events]
    
    def export_audit_trail(self, output_path: str):
        """Export audit trail to file."""
        audit_data = {
            'session_id': self.session_id,
            'export_timestamp': datetime.now().isoformat(),
            'audit_events': self.get_audit_trail()
        }
        
        with open(output_path, 'w') as f:
            json.dump(audit_data, f, indent=2)
        
        self.app_logger.info(f"Audit trail exported to: {output_path}")
    
    def _generate_event_id(self) -> str:
        """Generate unique event ID."""
        timestamp = str(time.time())
        return hashlib.sha256((self.session_id + timestamp).encode()).hexdigest()[:12]
    
    def _record_audit_event(self, event: AuditEvent):
        """Record audit event."""
        self.audit_events.append(event)
        
        # Also log to audit file
        audit_json = json.dumps(asdict(event))
        self.audit_logger.info(audit_json)


def main():
    """Test enhanced logging functionality."""
    print("📝 Enhanced Logging System Test")
    
    # Initialize logger
    config = {
        'log_level': 'INFO',
        'audit_enabled': True,
        'security_logging': True
    }
    
    logger = EnhancedLogger(config)
    
    # Test different log types
    logger.log_scan_start('/tmp/test', {'test': True})
    
    logger.log_vulnerability_found({
        'file_path': '/tmp/test.py',
        'severity': 'HIGH',
        'algorithm': 'RSA',
        'line_number': 42,
        'description': 'Test vulnerability'
    })
    
    logger.log_scan_complete({
        'total_vulnerabilities': 3,
        'files_scanned': 10,
        'scan_time': 2.5,
        'scan_path': '/tmp/test'
    })
    
    logger.log_security_event('test_event', {'test': 'data'}, 'low')
    
    # Export audit trail
    audit_path = '/tmp/pqc_audit_trail.json'
    logger.export_audit_trail(audit_path)
    
    print(f"✅ Logging test completed")
    print(f"📄 Audit trail: {audit_path}")
    print(f"📁 Log directory: {logger.log_dir}")


if __name__ == "__main__":
    main()