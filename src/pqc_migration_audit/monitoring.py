"""Monitoring and observability for PQC Migration Audit."""

import time
import logging
import threading
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import psutil
from contextlib import contextmanager

from .exceptions import (
    PQCAuditException, ResourceExhaustedException, 
    NetworkException, ExceptionHandler
)
from .types import ScanResults, Vulnerability, Severity


@dataclass
class PerformanceMetrics:
    """Performance metrics for monitoring."""
    scan_duration: float = 0.0
    files_processed: int = 0
    vulnerabilities_found: int = 0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    disk_io_mb: float = 0.0
    errors_count: int = 0
    warnings_count: int = 0
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class HealthStatus:
    """System health status."""
    is_healthy: bool = True
    status_message: str = "OK"
    last_check: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    performance_metrics: Optional[PerformanceMetrics] = None
    system_resources: Dict[str, Any] = field(default_factory=dict)
    error_rate: float = 0.0
    uptime_seconds: float = 0.0


class MetricsCollector:
    """Collects performance and health metrics."""
    
    def __init__(self, collect_interval: int = 30):
        """Initialize metrics collector.
        
        Args:
            collect_interval: Interval in seconds for metric collection
        """
        self.collect_interval = collect_interval
        self.start_time = time.time()
        self.metrics_history: List[PerformanceMetrics] = []
        self.max_history_size = 1000
        self.logger = logging.getLogger(__name__)
        self.is_collecting = False
        self.collection_thread: Optional[threading.Thread] = None
        self.lock = threading.Lock()
        
        # Counters
        self.total_scans = 0
        self.total_files_processed = 0
        self.total_vulnerabilities_found = 0
        self.total_errors = 0
        self.total_warnings = 0
    
    def start_collection(self):
        """Start background metrics collection."""
        if self.is_collecting:
            return
        
        self.is_collecting = True
        self.collection_thread = threading.Thread(
            target=self._collection_loop,
            daemon=True
        )
        self.collection_thread.start()
        self.logger.info("Metrics collection started")
    
    def stop_collection(self):
        """Stop background metrics collection."""
        self.is_collecting = False
        if self.collection_thread:
            self.collection_thread.join(timeout=5)
        self.logger.info("Metrics collection stopped")
    
    def _collection_loop(self):
        """Background loop for collecting metrics."""
        while self.is_collecting:
            try:
                metrics = self.collect_current_metrics()
                with self.lock:
                    self.metrics_history.append(metrics)
                    if len(self.metrics_history) > self.max_history_size:
                        self.metrics_history.pop(0)
                
                time.sleep(self.collect_interval)
            except Exception as e:
                self.logger.error(f"Error collecting metrics: {e}")
                time.sleep(self.collect_interval)
    
    def collect_current_metrics(self) -> PerformanceMetrics:
        """Collect current system metrics."""
        try:
            # Get system metrics
            memory_usage = psutil.virtual_memory().used / (1024 * 1024)  # MB
            cpu_usage = psutil.cpu_percent(interval=1)
            
            # Get disk I/O (simplified)
            disk_io = 0.0
            try:
                disk_counters = psutil.disk_io_counters()
                if disk_counters:
                    disk_io = (disk_counters.read_bytes + disk_counters.write_bytes) / (1024 * 1024)
            except Exception:
                pass
            
            return PerformanceMetrics(
                memory_usage_mb=memory_usage,
                cpu_usage_percent=cpu_usage,
                disk_io_mb=disk_io,
                files_processed=self.total_files_processed,
                vulnerabilities_found=self.total_vulnerabilities_found,
                errors_count=self.total_errors,
                warnings_count=self.total_warnings
            )
        except Exception as e:
            self.logger.error(f"Failed to collect system metrics: {e}")
            return PerformanceMetrics()
    
    @contextmanager
    def track_scan(self, scan_path: str):
        """Context manager to track scan performance.
        
        Args:
            scan_path: Path being scanned
        """
        start_time = time.time()
        initial_memory = psutil.Process().memory_info().rss / (1024 * 1024)
        
        try:
            yield
        except Exception as e:
            self.total_errors += 1
            raise
        finally:
            # Record scan metrics
            duration = time.time() - start_time
            final_memory = psutil.Process().memory_info().rss / (1024 * 1024)
            memory_delta = final_memory - initial_memory
            
            with self.lock:
                self.total_scans += 1
            
            self.logger.info(
                f"Scan completed: {scan_path}, duration: {duration:.2f}s, "
                f"memory delta: {memory_delta:.2f}MB"
            )
    
    def record_scan_results(self, results: ScanResults):
        """Record scan results in metrics.
        
        Args:
            results: Scan results to record
        """
        with self.lock:
            self.total_files_processed += results.scanned_files
            self.total_vulnerabilities_found += len(results.vulnerabilities)
    
    def record_error(self):
        """Record an error occurrence."""
        with self.lock:
            self.total_errors += 1
    
    def record_warning(self):
        """Record a warning occurrence."""
        with self.lock:
            self.total_warnings += 1
    
    def get_health_status(self) -> HealthStatus:
        """Get current system health status."""
        try:
            current_metrics = self.collect_current_metrics()
            
            # Calculate error rate
            error_rate = 0.0
            if self.total_scans > 0:
                error_rate = self.total_errors / self.total_scans
            
            # Check health thresholds
            is_healthy = True
            status_messages = []
            
            if current_metrics.memory_usage_mb > 1024:  # 1GB threshold
                is_healthy = False
                status_messages.append(f"High memory usage: {current_metrics.memory_usage_mb:.1f}MB")
            
            if current_metrics.cpu_usage_percent > 80:
                is_healthy = False
                status_messages.append(f"High CPU usage: {current_metrics.cpu_usage_percent:.1f}%")
            
            if error_rate > 0.1:  # 10% error rate threshold
                is_healthy = False
                status_messages.append(f"High error rate: {error_rate:.1%}")
            
            # System resources
            system_resources = {
                "memory_total_gb": psutil.virtual_memory().total / (1024**3),
                "memory_available_gb": psutil.virtual_memory().available / (1024**3),
                "disk_usage_percent": psutil.disk_usage('/').percent,
                "cpu_count": psutil.cpu_count(),
                "load_average": os.getloadavg() if hasattr(os, 'getloadavg') else [0, 0, 0]
            }
            
            return HealthStatus(
                is_healthy=is_healthy,
                status_message="; ".join(status_messages) if status_messages else "OK",
                performance_metrics=current_metrics,
                system_resources=system_resources,
                error_rate=error_rate,
                uptime_seconds=time.time() - self.start_time
            )
            
        except Exception as e:
            self.logger.error(f"Failed to get health status: {e}")
            return HealthStatus(
                is_healthy=False,
                status_message=f"Health check failed: {e}"
            )
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of collected metrics."""
        with self.lock:
            if not self.metrics_history:
                return {"error": "No metrics collected"}
            
            # Calculate averages over last 10 minutes
            recent_cutoff = datetime.utcnow() - timedelta(minutes=10)
            recent_metrics = [
                m for m in self.metrics_history 
                if datetime.fromisoformat(m.timestamp) > recent_cutoff
            ]
            
            if not recent_metrics:
                recent_metrics = self.metrics_history[-10:]  # Last 10 entries
            
            avg_memory = sum(m.memory_usage_mb for m in recent_metrics) / len(recent_metrics)
            avg_cpu = sum(m.cpu_usage_percent for m in recent_metrics) / len(recent_metrics)
            
            return {
                "total_scans": self.total_scans,
                "total_files_processed": self.total_files_processed,
                "total_vulnerabilities_found": self.total_vulnerabilities_found,
                "total_errors": self.total_errors,
                "total_warnings": self.total_warnings,
                "error_rate": self.total_errors / max(self.total_scans, 1),
                "uptime_seconds": time.time() - self.start_time,
                "recent_avg_memory_mb": avg_memory,
                "recent_avg_cpu_percent": avg_cpu,
                "metrics_collected": len(self.metrics_history)
            }
    
    def export_metrics(self, output_path: Path, format: str = "json"):
        """Export collected metrics to file.
        
        Args:
            output_path: Path to export metrics
            format: Export format (json, csv)
        """
        try:
            with self.lock:
                if format.lower() == "json":
                    data = {
                        "summary": self.get_metrics_summary(),
                        "health_status": self.get_health_status().__dict__,
                        "metrics_history": [m.__dict__ for m in self.metrics_history]
                    }
                    
                    with open(output_path, 'w') as f:
                        json.dump(data, f, indent=2, default=str)
                
                elif format.lower() == "csv":
                    import csv
                    with open(output_path, 'w', newline='') as f:
                        if self.metrics_history:
                            writer = csv.DictWriter(f, fieldnames=self.metrics_history[0].__dict__.keys())
                            writer.writeheader()
                            for metric in self.metrics_history:
                                writer.writerow(metric.__dict__)
                
                self.logger.info(f"Metrics exported to {output_path}")
                
        except Exception as e:
            self.logger.error(f"Failed to export metrics: {e}")
            raise


class AlertManager:
    """Manages alerts and notifications for system health."""
    
    def __init__(self, metrics_collector: MetricsCollector):
        """Initialize alert manager.
        
        Args:
            metrics_collector: Metrics collector instance
        """
        self.metrics_collector = metrics_collector
        self.logger = logging.getLogger(__name__)
        self.alert_handlers: List[Callable] = []
        self.alert_thresholds = {
            "memory_mb": 2048,
            "cpu_percent": 85,
            "error_rate": 0.15,
            "disk_usage_percent": 90
        }
        self.alert_cooldown = 300  # 5 minutes
        self.last_alerts: Dict[str, float] = {}
    
    def add_alert_handler(self, handler: Callable[[str, Dict[str, Any]], None]):
        """Add alert handler function.
        
        Args:
            handler: Function to handle alerts (alert_type, details)
        """
        self.alert_handlers.append(handler)
    
    def check_alerts(self):
        """Check system status and trigger alerts if needed."""
        try:
            health_status = self.metrics_collector.get_health_status()
            current_time = time.time()
            
            # Memory usage alert
            if health_status.performance_metrics:
                memory_usage = health_status.performance_metrics.memory_usage_mb
                if memory_usage > self.alert_thresholds["memory_mb"]:
                    self._trigger_alert(
                        "high_memory_usage",
                        {
                            "current": memory_usage,
                            "threshold": self.alert_thresholds["memory_mb"],
                            "message": f"High memory usage: {memory_usage:.1f}MB"
                        },
                        current_time
                    )
                
                # CPU usage alert
                cpu_usage = health_status.performance_metrics.cpu_usage_percent
                if cpu_usage > self.alert_thresholds["cpu_percent"]:
                    self._trigger_alert(
                        "high_cpu_usage",
                        {
                            "current": cpu_usage,
                            "threshold": self.alert_thresholds["cpu_percent"],
                            "message": f"High CPU usage: {cpu_usage:.1f}%"
                        },
                        current_time
                    )
            
            # Error rate alert
            if health_status.error_rate > self.alert_thresholds["error_rate"]:
                self._trigger_alert(
                    "high_error_rate",
                    {
                        "current": health_status.error_rate,
                        "threshold": self.alert_thresholds["error_rate"],
                        "message": f"High error rate: {health_status.error_rate:.1%}"
                    },
                    current_time
                )
            
            # Disk usage alert
            if "disk_usage_percent" in health_status.system_resources:
                disk_usage = health_status.system_resources["disk_usage_percent"]
                if disk_usage > self.alert_thresholds["disk_usage_percent"]:
                    self._trigger_alert(
                        "high_disk_usage",
                        {
                            "current": disk_usage,
                            "threshold": self.alert_thresholds["disk_usage_percent"],
                            "message": f"High disk usage: {disk_usage:.1f}%"
                        },
                        current_time
                    )
        
        except Exception as e:
            self.logger.error(f"Error checking alerts: {e}")
    
    def _trigger_alert(self, alert_type: str, details: Dict[str, Any], current_time: float):
        """Trigger an alert if cooldown period has passed.
        
        Args:
            alert_type: Type of alert
            details: Alert details
            current_time: Current timestamp
        """
        # Check cooldown
        if alert_type in self.last_alerts:
            if current_time - self.last_alerts[alert_type] < self.alert_cooldown:
                return
        
        # Update last alert time
        self.last_alerts[alert_type] = current_time
        
        # Trigger alert handlers
        for handler in self.alert_handlers:
            try:
                handler(alert_type, details)
            except Exception as e:
                self.logger.error(f"Error in alert handler: {e}")


class CircuitBreaker:
    """Circuit breaker for resilient operations."""
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60,
                 expected_exception: type = Exception):
        """Initialize circuit breaker.
        
        Args:
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds before attempting recovery
            expected_exception: Exception type that counts as failure
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
        self.lock = threading.Lock()
        self.logger = logging.getLogger(__name__)
    
    def __call__(self, func):
        """Decorator to apply circuit breaker to function."""
        def wrapper(*args, **kwargs):
            with self.lock:
                # Check if circuit should be closed after timeout
                if self.state == "OPEN" and self.last_failure_time:
                    if time.time() - self.last_failure_time > self.recovery_timeout:
                        self.state = "HALF_OPEN"
                        self.logger.info(f"Circuit breaker transitioning to HALF_OPEN: {func.__name__}")
                
                # Reject calls if circuit is open
                if self.state == "OPEN":
                    raise ResourceExhaustedException(
                        "circuit_breaker", 
                        self.failure_threshold, 
                        self.failure_count
                    )
            
            try:
                result = func(*args, **kwargs)
                
                # Success - reset failure count if in HALF_OPEN
                with self.lock:
                    if self.state == "HALF_OPEN":
                        self.state = "CLOSED"
                        self.failure_count = 0
                        self.logger.info(f"Circuit breaker closed: {func.__name__}")
                
                return result
                
            except self.expected_exception as e:
                with self.lock:
                    self.failure_count += 1
                    self.last_failure_time = time.time()
                    
                    if self.failure_count >= self.failure_threshold:
                        self.state = "OPEN"
                        self.logger.warning(
                            f"Circuit breaker opened: {func.__name__} "
                            f"({self.failure_count} failures)"
                        )
                
                raise
        
        return wrapper
    
    def get_status(self) -> Dict[str, Any]:
        """Get circuit breaker status."""
        with self.lock:
            return {
                "state": self.state,
                "failure_count": self.failure_count,
                "failure_threshold": self.failure_threshold,
                "last_failure_time": self.last_failure_time,
                "recovery_timeout": self.recovery_timeout
            }


class RetryHandler:
    """Handles retry logic for failed operations."""
    
    def __init__(self, max_retries: int = 3, backoff_factor: float = 2.0,
                 retry_exceptions: tuple = (Exception,)):
        """Initialize retry handler.
        
        Args:
            max_retries: Maximum number of retry attempts
            backoff_factor: Exponential backoff factor
            retry_exceptions: Exceptions that should trigger retry
        """
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.retry_exceptions = retry_exceptions
        self.logger = logging.getLogger(__name__)
    
    def __call__(self, func):
        """Decorator to apply retry logic to function."""
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(self.max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except self.retry_exceptions as e:
                    last_exception = e
                    
                    if attempt == self.max_retries:
                        self.logger.error(
                            f"Function {func.__name__} failed after {self.max_retries + 1} attempts: {e}"
                        )
                        break
                    
                    wait_time = (self.backoff_factor ** attempt)
                    self.logger.warning(
                        f"Function {func.__name__} attempt {attempt + 1} failed: {e}. "
                        f"Retrying in {wait_time:.1f}s..."
                    )
                    time.sleep(wait_time)
            
            # Re-raise the last exception
            raise last_exception
        
        return wrapper


class RateLimiter:
    """Rate limiter for controlling operation frequency."""
    
    def __init__(self, max_calls: int = 100, time_window: int = 60):
        """Initialize rate limiter.
        
        Args:
            max_calls: Maximum calls allowed in time window
            time_window: Time window in seconds
        """
        self.max_calls = max_calls
        self.time_window = time_window
        self.calls = []
        self.lock = threading.Lock()
    
    def __call__(self, func):
        """Decorator to apply rate limiting to function."""
        def wrapper(*args, **kwargs):
            with self.lock:
                current_time = time.time()
                
                # Remove old calls outside time window
                self.calls = [call_time for call_time in self.calls 
                             if current_time - call_time < self.time_window]
                
                # Check if rate limit exceeded
                if len(self.calls) >= self.max_calls:
                    raise ResourceExhaustedException(
                        "rate_limit",
                        self.max_calls,
                        len(self.calls)
                    )
                
                # Record this call
                self.calls.append(current_time)
            
            return func(*args, **kwargs)
        
        return wrapper
    
    def get_status(self) -> Dict[str, Any]:
        """Get rate limiter status."""
        with self.lock:
            current_time = time.time()
            recent_calls = [call_time for call_time in self.calls 
                           if current_time - call_time < self.time_window]
            
            return {
                "current_calls": len(recent_calls),
                "max_calls": self.max_calls,
                "time_window": self.time_window,
                "remaining_calls": max(0, self.max_calls - len(recent_calls))
            }


# Global metrics collector instance
_global_metrics_collector: Optional[MetricsCollector] = None


def get_metrics_collector() -> MetricsCollector:
    """Get global metrics collector instance."""
    global _global_metrics_collector
    if _global_metrics_collector is None:
        _global_metrics_collector = MetricsCollector()
        _global_metrics_collector.start_collection()
    return _global_metrics_collector


def setup_monitoring(
    collect_interval: int = 30,
    alert_handlers: Optional[List[Callable]] = None
) -> tuple[MetricsCollector, AlertManager]:
    """Setup comprehensive monitoring system.
    
    Args:
        collect_interval: Metrics collection interval in seconds
        alert_handlers: List of alert handler functions
        
    Returns:
        Tuple of (MetricsCollector, AlertManager)
    """
    metrics_collector = MetricsCollector(collect_interval)
    metrics_collector.start_collection()
    
    alert_manager = AlertManager(metrics_collector)
    if alert_handlers:
        for handler in alert_handlers:
            alert_manager.add_alert_handler(handler)
    
    return metrics_collector, alert_manager