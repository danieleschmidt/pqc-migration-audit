"""Real-time health monitoring and alerting system for research operations."""

import time
import threading
import logging
import json
import psutil
import os
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import queue
import statistics


class HealthStatus(Enum):
    """System health status levels."""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    DEGRADED = "degraded"
    RECOVERING = "recovering"


class AlertLevel(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class HealthMetric:
    """Individual health metric measurement."""
    name: str
    value: float
    threshold_warning: float
    threshold_critical: float
    unit: str
    timestamp: datetime = field(default_factory=datetime.now)
    status: HealthStatus = HealthStatus.HEALTHY
    
    def __post_init__(self):
        """Determine status based on thresholds."""
        if self.value >= self.threshold_critical:
            self.status = HealthStatus.CRITICAL
        elif self.value >= self.threshold_warning:
            self.status = HealthStatus.WARNING
        else:
            self.status = HealthStatus.HEALTHY


@dataclass
class HealthAlert:
    """Health monitoring alert."""
    alert_id: str
    level: AlertLevel
    component: str
    message: str
    timestamp: datetime
    metric_value: float
    threshold: float
    resolved: bool = False
    resolution_time: Optional[datetime] = None


class SystemHealthMonitor:
    """Comprehensive system health monitoring."""
    
    def __init__(self, check_interval: float = 30.0):
        self.check_interval = check_interval
        self.is_monitoring = False
        self.metrics_history: Dict[str, List[HealthMetric]] = {}
        self.active_alerts: List[HealthAlert] = []
        self.alert_handlers: List[Callable[[HealthAlert], None]] = []
        self.logger = logging.getLogger(__name__)
        
        # Health thresholds
        self.thresholds = {
            'cpu_usage_percent': {'warning': 80.0, 'critical': 95.0},
            'memory_usage_percent': {'warning': 85.0, 'critical': 95.0},
            'disk_usage_percent': {'warning': 85.0, 'critical': 95.0},
            'algorithm_failure_rate': {'warning': 0.1, 'critical': 0.3},
            'experiment_duration_seconds': {'warning': 300.0, 'critical': 1800.0},
            'error_rate_per_minute': {'warning': 5.0, 'critical': 20.0},
            'circuit_breaker_trips': {'warning': 3.0, 'critical': 10.0}
        }
        
        # Performance tracking
        self.performance_metrics = {
            'operations_completed': 0,
            'operations_failed': 0,
            'total_processing_time': 0.0,
            'circuit_breaker_trips': 0,
            'last_successful_operation': datetime.now()
        }
        
        self._monitoring_thread = None
        self._stop_event = threading.Event()
    
    def start_monitoring(self):
        """Start continuous health monitoring."""
        if self.is_monitoring:
            self.logger.warning("Health monitoring is already running")
            return
        
        self.is_monitoring = True
        self._stop_event.clear()
        self._monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self._monitoring_thread.start()
        self.logger.info(f"Started health monitoring with {self.check_interval}s interval")
    
    def stop_monitoring(self):
        """Stop health monitoring."""
        if not self.is_monitoring:
            return
        
        self.is_monitoring = False
        self._stop_event.set()
        if self._monitoring_thread:
            self._monitoring_thread.join(timeout=5.0)
        self.logger.info("Stopped health monitoring")
    
    def _monitoring_loop(self):
        """Main monitoring loop."""
        while not self._stop_event.is_set():
            try:
                self._collect_system_metrics()
                self._collect_application_metrics()
                self._evaluate_health_status()
                self._cleanup_old_metrics()
            except Exception as e:
                self.logger.error(f"Error in health monitoring loop: {e}")
            
            self._stop_event.wait(self.check_interval)
    
    def _collect_system_metrics(self):
        """Collect system-level health metrics."""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            self._record_metric('cpu_usage_percent', cpu_percent, '%')
            
            # Memory usage
            memory = psutil.virtual_memory()
            self._record_metric('memory_usage_percent', memory.percent, '%')
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            self._record_metric('disk_usage_percent', disk_percent, '%')
            
            # Process information
            process = psutil.Process()
            process_memory = process.memory_info().rss / 1024 / 1024  # MB
            self._record_metric('process_memory_mb', process_memory, 'MB', 
                              warning_threshold=500.0, critical_threshold=1000.0)
            
        except Exception as e:
            self.logger.error(f"Error collecting system metrics: {e}")
    
    def _collect_application_metrics(self):
        """Collect application-specific health metrics."""
        try:
            # Calculate error rates
            current_time = datetime.now()
            one_minute_ago = current_time - timedelta(minutes=1)
            
            # Get recent metrics from recovery manager if available
            from .error_recovery import recovery_manager
            
            recovery_stats = recovery_manager.recovery_stats
            
            # Error rate calculation
            recent_errors = recovery_stats.get('total_errors', 0)
            error_rate = recent_errors / 60.0  # errors per minute (simplified)
            self._record_metric('error_rate_per_minute', error_rate, 'errors/min')
            
            # Success rate
            total_operations = recovery_stats.get('total_errors', 0) + recovery_stats.get('successful_recoveries', 0)
            if total_operations > 0:
                failure_rate = recovery_stats.get('total_errors', 0) / total_operations
                self._record_metric('algorithm_failure_rate', failure_rate, 'ratio')
            
            # Circuit breaker metrics
            circuit_breaks = recovery_stats.get('circuit_breaks', 0)
            self._record_metric('circuit_breaker_trips', circuit_breaks, 'count',
                              warning_threshold=3.0, critical_threshold=10.0)
            
        except Exception as e:
            self.logger.error(f"Error collecting application metrics: {e}")
    
    def _record_metric(self, name: str, value: float, unit: str, 
                      warning_threshold: Optional[float] = None, 
                      critical_threshold: Optional[float] = None):
        """Record a health metric."""
        thresholds = self.thresholds.get(name, {})
        warning_thresh = warning_threshold or thresholds.get('warning', float('inf'))
        critical_thresh = critical_threshold or thresholds.get('critical', float('inf'))
        
        metric = HealthMetric(
            name=name,
            value=value,
            threshold_warning=warning_thresh,
            threshold_critical=critical_thresh,
            unit=unit
        )
        
        # Store metric
        if name not in self.metrics_history:
            self.metrics_history[name] = []
        
        self.metrics_history[name].append(metric)
        
        # Check for alerts
        self._check_metric_alerts(metric)
    
    def _check_metric_alerts(self, metric: HealthMetric):
        """Check if metric triggers any alerts."""
        if metric.status == HealthStatus.CRITICAL:
            self._create_alert(
                AlertLevel.CRITICAL,
                f"system.{metric.name}",
                f"CRITICAL: {metric.name} is {metric.value}{metric.unit} (threshold: {metric.threshold_critical})",
                metric.value,
                metric.threshold_critical
            )
        elif metric.status == HealthStatus.WARNING:
            self._create_alert(
                AlertLevel.WARNING,
                f"system.{metric.name}",
                f"WARNING: {metric.name} is {metric.value}{metric.unit} (threshold: {metric.threshold_warning})",
                metric.value,
                metric.threshold_warning
            )
    
    def _create_alert(self, level: AlertLevel, component: str, message: str, 
                     value: float, threshold: float):
        """Create and dispatch a health alert."""
        alert_id = f"alert_{int(time.time())}_{hash(message) % 1000}"
        
        alert = HealthAlert(
            alert_id=alert_id,
            level=level,
            component=component,
            message=message,
            timestamp=datetime.now(),
            metric_value=value,
            threshold=threshold
        )
        
        self.active_alerts.append(alert)
        
        # Dispatch to handlers
        for handler in self.alert_handlers:
            try:
                handler(alert)
            except Exception as e:
                self.logger.error(f"Error in alert handler: {e}")
        
        # Log alert
        if level == AlertLevel.CRITICAL:
            self.logger.critical(message)
        elif level == AlertLevel.ERROR:
            self.logger.error(message)
        elif level == AlertLevel.WARNING:
            self.logger.warning(message)
        else:
            self.logger.info(message)
    
    def _evaluate_health_status(self):
        """Evaluate overall system health status."""
        if not self.metrics_history:
            return
        
        # Get latest metrics
        latest_metrics = {}
        for metric_name, history in self.metrics_history.items():
            if history:
                latest_metrics[metric_name] = history[-1]
        
        # Determine overall status
        critical_count = sum(1 for m in latest_metrics.values() if m.status == HealthStatus.CRITICAL)
        warning_count = sum(1 for m in latest_metrics.values() if m.status == HealthStatus.WARNING)
        
        if critical_count > 0:
            overall_status = HealthStatus.CRITICAL
        elif warning_count > 0:
            overall_status = HealthStatus.WARNING
        else:
            overall_status = HealthStatus.HEALTHY
        
        # Update performance tracking
        self._update_performance_metrics(overall_status)
    
    def _update_performance_metrics(self, status: HealthStatus):
        """Update performance tracking metrics."""
        if status == HealthStatus.HEALTHY:
            self.performance_metrics['last_successful_operation'] = datetime.now()
    
    def _cleanup_old_metrics(self):
        """Remove old metrics to prevent memory growth."""
        cutoff_time = datetime.now() - timedelta(hours=24)  # Keep 24 hours of data
        
        for metric_name, history in self.metrics_history.items():
            # Keep only recent metrics
            recent_metrics = [m for m in history if m.timestamp > cutoff_time]
            self.metrics_history[metric_name] = recent_metrics[-1000:]  # Max 1000 entries per metric
        
        # Cleanup old alerts
        self.active_alerts = [a for a in self.active_alerts if not a.resolved or 
                             a.timestamp > datetime.now() - timedelta(hours=6)]
    
    def add_alert_handler(self, handler: Callable[[HealthAlert], None]):
        """Add a custom alert handler."""
        self.alert_handlers.append(handler)
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get comprehensive health status report."""
        if not self.metrics_history:
            return {'status': 'no_data', 'message': 'No health data available'}
        
        # Get latest metrics
        latest_metrics = {}
        metric_statuses = {}
        
        for metric_name, history in self.metrics_history.items():
            if history:
                latest = history[-1]
                latest_metrics[metric_name] = {
                    'value': latest.value,
                    'unit': latest.unit,
                    'status': latest.status.value,
                    'timestamp': latest.timestamp.isoformat()
                }
                metric_statuses[latest.status] = metric_statuses.get(latest.status, 0) + 1
        
        # Determine overall status
        if HealthStatus.CRITICAL in metric_statuses:
            overall_status = HealthStatus.CRITICAL
        elif HealthStatus.WARNING in metric_statuses:
            overall_status = HealthStatus.WARNING
        else:
            overall_status = HealthStatus.HEALTHY
        
        # Get active alerts
        active_alerts = [
            {
                'id': a.alert_id,
                'level': a.level.value,
                'component': a.component,
                'message': a.message,
                'timestamp': a.timestamp.isoformat(),
                'resolved': a.resolved
            }
            for a in self.active_alerts[-10:]  # Last 10 alerts
        ]
        
        return {
            'overall_status': overall_status.value,
            'timestamp': datetime.now().isoformat(),
            'metrics': latest_metrics,
            'active_alerts': active_alerts,
            'alert_summary': {
                'total_active': len([a for a in self.active_alerts if not a.resolved]),
                'critical': len([a for a in self.active_alerts if a.level == AlertLevel.CRITICAL and not a.resolved]),
                'warning': len([a for a in self.active_alerts if a.level == AlertLevel.WARNING and not a.resolved])
            },
            'performance_summary': self._get_performance_summary(),
            'recommendations': self._generate_health_recommendations()
        }
    
    def _get_performance_summary(self) -> Dict[str, Any]:
        """Get performance metrics summary."""
        total_ops = self.performance_metrics['operations_completed'] + self.performance_metrics['operations_failed']
        success_rate = (self.performance_metrics['operations_completed'] / max(1, total_ops)) * 100
        
        avg_processing_time = 0.0
        if self.performance_metrics['operations_completed'] > 0:
            avg_processing_time = self.performance_metrics['total_processing_time'] / self.performance_metrics['operations_completed']
        
        return {
            'total_operations': total_ops,
            'success_rate_percent': success_rate,
            'average_processing_time_seconds': avg_processing_time,
            'circuit_breaker_trips': self.performance_metrics['circuit_breaker_trips'],
            'last_successful_operation': self.performance_metrics['last_successful_operation'].isoformat()
        }
    
    def _generate_health_recommendations(self) -> List[str]:
        """Generate health improvement recommendations."""
        recommendations = []
        
        if not self.metrics_history:
            return ['Enable health monitoring to get recommendations']
        
        # Check recent metrics for patterns
        latest_metrics = {name: history[-1] for name, history in self.metrics_history.items() if history}
        
        # CPU recommendations
        if 'cpu_usage_percent' in latest_metrics:
            cpu_metric = latest_metrics['cpu_usage_percent']
            if cpu_metric.status == HealthStatus.CRITICAL:
                recommendations.append("URGENT: CPU usage is critically high - consider reducing workload or scaling resources")
            elif cpu_metric.status == HealthStatus.WARNING:
                recommendations.append("CPU usage is elevated - monitor workload and consider optimization")
        
        # Memory recommendations
        if 'memory_usage_percent' in latest_metrics:
            memory_metric = latest_metrics['memory_usage_percent']
            if memory_metric.status == HealthStatus.CRITICAL:
                recommendations.append("URGENT: Memory usage is critically high - restart application or increase memory")
            elif memory_metric.status == HealthStatus.WARNING:
                recommendations.append("Memory usage is high - consider implementing memory optimization")
        
        # Error rate recommendations
        if 'error_rate_per_minute' in latest_metrics:
            error_metric = latest_metrics['error_rate_per_minute']
            if error_metric.value > 0:
                recommendations.append(f"Error rate is {error_metric.value:.1f} errors/min - investigate recent failures")
        
        # Active alerts recommendations
        critical_alerts = [a for a in self.active_alerts if a.level == AlertLevel.CRITICAL and not a.resolved]
        if critical_alerts:
            recommendations.append(f"Address {len(critical_alerts)} critical alerts immediately")
        
        return recommendations
    
    def record_operation_start(self, operation_id: str):
        """Record the start of an operation for performance tracking."""
        # This could be expanded to track individual operations
        pass
    
    def record_operation_complete(self, operation_id: str, duration: float, success: bool):
        """Record the completion of an operation."""
        if success:
            self.performance_metrics['operations_completed'] += 1
            self.performance_metrics['total_processing_time'] += duration
        else:
            self.performance_metrics['operations_failed'] += 1
    
    def record_circuit_breaker_trip(self):
        """Record a circuit breaker trip."""
        self.performance_metrics['circuit_breaker_trips'] += 1
    
    def resolve_alert(self, alert_id: str):
        """Mark an alert as resolved."""
        for alert in self.active_alerts:
            if alert.alert_id == alert_id:
                alert.resolved = True
                alert.resolution_time = datetime.now()
                self.logger.info(f"Resolved alert {alert_id}")
                break


# Global health monitor instance
global_health_monitor = SystemHealthMonitor()


def default_alert_handler(alert: HealthAlert):
    """Default alert handler that logs alerts."""
    logger = logging.getLogger('health_monitor')
    
    if alert.level == AlertLevel.CRITICAL:
        logger.critical(f"🚨 CRITICAL ALERT: {alert.message}")
    elif alert.level == AlertLevel.ERROR:
        logger.error(f"❌ ERROR ALERT: {alert.message}")
    elif alert.level == AlertLevel.WARNING:
        logger.warning(f"⚠️  WARNING ALERT: {alert.message}")
    else:
        logger.info(f"ℹ️  INFO ALERT: {alert.message}")


# Register default alert handler
global_health_monitor.add_alert_handler(default_alert_handler)


def monitored_operation(operation_name: str):
    """Decorator for monitoring operation performance."""
    def decorator(func):
        from functools import wraps
        @wraps(func)
        def wrapper(*args, **kwargs):
            operation_id = f"{operation_name}_{int(time.time())}"
            start_time = time.time()
            success = False
            
            try:
                global_health_monitor.record_operation_start(operation_id)
                result = func(*args, **kwargs)
                success = True
                return result
            except Exception as e:
                success = False
                raise
            finally:
                duration = time.time() - start_time
                global_health_monitor.record_operation_complete(operation_id, duration, success)
        return wrapper
    return decorator