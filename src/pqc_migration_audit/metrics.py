# Application metrics for PQC Migration Audit
import time
import psutil
from prometheus_client import Counter, Histogram, Gauge, Summary, CollectorRegistry
from functools import wraps
from typing import Dict, Any, Optional

# Create custom registry for application metrics
REGISTRY = CollectorRegistry()

# Application metrics
SCAN_REQUESTS_TOTAL = Counter(
    'pqc_audit_scan_requests_total',
    'Total number of scan requests',
    ['repository_type', 'scan_type'],
    registry=REGISTRY
)

SCAN_DURATION_SECONDS = Histogram(
    'pqc_audit_scan_duration_seconds',
    'Time spent scanning repositories',
    ['repository_type', 'scan_result'],
    buckets=[1, 5, 10, 30, 60, 120, 300],
    registry=REGISTRY
)

VULNERABILITIES_FOUND = Counter(
    'pqc_audit_vulnerabilities_total',
    'Total vulnerabilities found by severity',
    ['severity', 'vulnerability_type'],
    registry=REGISTRY
)

SCAN_ERRORS_TOTAL = Counter(
    'pqc_audit_scan_errors_total',
    'Total number of scan errors',
    ['error_type', 'error_category'],
    registry=REGISTRY
)

# Performance metrics
MEMORY_USAGE_BYTES = Gauge(
    'pqc_audit_memory_usage_bytes',
    'Current memory usage in bytes',
    registry=REGISTRY
)

CPU_USAGE_PERCENT = Gauge(
    'pqc_audit_cpu_usage_percent',
    'Current CPU usage percentage',
    registry=REGISTRY
)

FILES_PROCESSED_TOTAL = Counter(
    'pqc_audit_files_processed_total',
    'Total number of files processed',
    ['file_type', 'processing_result'],
    registry=REGISTRY
)

# Security-specific metrics
CRYPTO_PATTERNS_DETECTED = Counter(
    'pqc_audit_crypto_patterns_total',
    'Cryptographic patterns detected',
    ['pattern_type', 'algorithm'],
    registry=REGISTRY
)

QUANTUM_VULNERABLE_FINDINGS = Counter(
    'pqc_audit_quantum_vulnerable_total',
    'Quantum-vulnerable cryptography findings',  
    ['algorithm_type', 'severity'],
    registry=REGISTRY
)

PQC_RECOMMENDATIONS_GENERATED = Counter(
    'pqc_audit_pqc_recommendations_total',
    'Post-quantum cryptography recommendations generated',
    ['recommendation_type', 'target_algorithm'],
    registry=REGISTRY
)

# Business metrics
SCAN_COMPLETION_RATE = Gauge(
    'pqc_audit_scan_completion_rate',
    'Percentage of successful scans',
    registry=REGISTRY
)

FALSE_POSITIVE_RATE = Gauge(
    'pqc_audit_false_positive_rate', 
    'Percentage of findings marked as false positives',
    registry=REGISTRY
)

USER_SATISFACTION_SCORE = Gauge(
    'pqc_audit_user_satisfaction_score',
    'User satisfaction score (1-10)',
    registry=REGISTRY
)

# System health metrics
ACTIVE_SCANS_GAUGE = Gauge(
    'pqc_audit_active_scans',
    'Number of currently active scans',
    registry=REGISTRY
)

LAST_SUCCESSFUL_SCAN_TIMESTAMP = Gauge(
    'pqc_audit_last_successful_scan_timestamp',
    'Timestamp of last successful scan',
    registry=REGISTRY
)

class MetricsCollector:
    """Central metrics collection and reporting."""
    
    def __init__(self):
        self.registry = REGISTRY
        self._start_system_monitoring()
    
    def _start_system_monitoring(self):
        """Start background system metrics collection."""
        import threading
        import time
        
        def collect_system_metrics():
            while True:
                try:
                    # Memory usage
                    memory_info = psutil.virtual_memory()
                    MEMORY_USAGE_BYTES.set(memory_info.used)
                    
                    # CPU usage
                    cpu_percent = psutil.cpu_percent(interval=1)
                    CPU_USAGE_PERCENT.set(cpu_percent)
                    
                    time.sleep(30)  # Collect every 30 seconds
                except Exception as e:
                    print(f"Error collecting system metrics: {e}")
                    time.sleep(60)  # Wait longer on error
        
        thread = threading.Thread(target=collect_system_metrics, daemon=True)
        thread.start()

    @staticmethod
    def record_scan_request(repository_type: str, scan_type: str):
        """Record a scan request."""
        SCAN_REQUESTS_TOTAL.labels(
            repository_type=repository_type,
            scan_type=scan_type
        ).inc()

    @staticmethod
    def record_vulnerability(severity: str, vuln_type: str):
        """Record a vulnerability finding."""
        VULNERABILITIES_FOUND.labels(
            severity=severity,
            vulnerability_type=vuln_type
        ).inc()

    @staticmethod
    def record_scan_error(error_type: str, error_category: str):
        """Record a scan error."""
        SCAN_ERRORS_TOTAL.labels(
            error_type=error_type,
            error_category=error_category
        ).inc()

    @staticmethod
    def record_crypto_pattern(pattern_type: str, algorithm: str):
        """Record detection of cryptographic pattern."""
        CRYPTO_PATTERNS_DETECTED.labels(
            pattern_type=pattern_type,
            algorithm=algorithm
        ).inc()

    @staticmethod
    def record_quantum_vulnerable_finding(algorithm_type: str, severity: str):
        """Record quantum-vulnerable cryptography finding."""
        QUANTUM_VULNERABLE_FINDINGS.labels(
            algorithm_type=algorithm_type,
            severity=severity
        ).inc()

    @staticmethod
    def record_pqc_recommendation(recommendation_type: str, target_algorithm: str):
        """Record PQC recommendation generation."""
        PQC_RECOMMENDATIONS_GENERATED.labels(
            recommendation_type=recommendation_type,
            target_algorithm=target_algorithm
        ).inc()

    @staticmethod
    def update_completion_rate(rate: float):
        """Update scan completion rate."""
        SCAN_COMPLETION_RATE.set(rate)

    @staticmethod
    def update_false_positive_rate(rate: float):
        """Update false positive rate."""
        FALSE_POSITIVE_RATE.set(rate)

    @staticmethod
    def record_successful_scan():
        """Record timestamp of successful scan."""
        LAST_SUCCESSFUL_SCAN_TIMESTAMP.set(time.time())

def timed_scan(repository_type: str):
    """Decorator to time scan operations."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            ACTIVE_SCANS_GAUGE.inc()
            
            try:
                result = func(*args, **kwargs)
                scan_result = "success"
                return result
            except Exception as e:
                scan_result = "error"
                MetricsCollector.record_scan_error(
                    error_type=type(e).__name__,
                    error_category="scan_execution"
                )
                raise
            finally:
                duration = time.time() - start_time
                SCAN_DURATION_SECONDS.labels(
                    repository_type=repository_type,
                    scan_result=scan_result
                ).observe(duration)
                ACTIVE_SCANS_GAUGE.dec()
        
        return wrapper
    return decorator

def track_file_processing(file_type: str):
    """Decorator to track file processing."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                result = func(*args, **kwargs)
                FILES_PROCESSED_TOTAL.labels(
                    file_type=file_type,
                    processing_result="success"
                ).inc()
                return result
            except Exception as e:
                FILES_PROCESSED_TOTAL.labels(
                    file_type=file_type,
                    processing_result="error"
                ).inc()
                raise
        
        return wrapper
    return decorator

# Initialize metrics collector
metrics_collector = MetricsCollector()