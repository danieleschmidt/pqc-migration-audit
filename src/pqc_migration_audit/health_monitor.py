"""Health monitoring and system diagnostics for PQC Migration Audit."""

import time
import psutil
import threading
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum
import logging


class HealthStatus(Enum):
    """System health status levels."""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class HealthCheck:
    """Individual health check result."""
    name: str
    status: HealthStatus
    message: str
    details: Dict[str, Any]
    timestamp: float
    duration_ms: float


class SystemHealthMonitor:
    """Comprehensive system health monitoring."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.checks = {}
        self.thresholds = {
            'cpu_usage': 80.0,      # %
            'memory_usage': 85.0,   # %
            'disk_usage': 90.0,     # %
            'scan_rate': 10.0,      # files/sec minimum
            'error_rate': 5.0,      # % maximum
        }
        
    def perform_health_check(self) -> Dict[str, HealthCheck]:
        """Perform comprehensive health check."""
        results = {}
        
        # System resource checks
        results['cpu'] = self._check_cpu_usage()
        results['memory'] = self._check_memory_usage()
        results['disk'] = self._check_disk_usage()
        
        # Application-specific checks
        results['dependencies'] = self._check_dependencies()
        results['file_access'] = self._check_file_system_access()
        results['network'] = self._check_network_connectivity()
        
        # Performance checks
        results['performance'] = self._check_performance_metrics()
        
        return results
    
    def _check_cpu_usage(self) -> HealthCheck:
        """Check CPU usage levels."""
        start_time = time.time()
        
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            duration_ms = (time.time() - start_time) * 1000
            
            if cpu_percent > self.thresholds['cpu_usage']:
                status = HealthStatus.CRITICAL
                message = f"High CPU usage: {cpu_percent:.1f}%"
            elif cpu_percent > self.thresholds['cpu_usage'] * 0.8:
                status = HealthStatus.WARNING
                message = f"Elevated CPU usage: {cpu_percent:.1f}%"
            else:
                status = HealthStatus.HEALTHY
                message = f"CPU usage normal: {cpu_percent:.1f}%"
            
            return HealthCheck(
                name="cpu_usage",
                status=status,
                message=message,
                details={
                    'cpu_percent': cpu_percent,
                    'cpu_count': psutil.cpu_count(),
                    'load_avg': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
                },
                timestamp=time.time(),
                duration_ms=duration_ms
            )
            
        except Exception as e:
            return HealthCheck(
                name="cpu_usage",
                status=HealthStatus.UNKNOWN,
                message=f"CPU check failed: {str(e)}",
                details={'error': str(e)},
                timestamp=time.time(),
                duration_ms=(time.time() - start_time) * 1000
            )
    
    def _check_memory_usage(self) -> HealthCheck:
        """Check memory usage levels."""
        start_time = time.time()
        
        try:
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            duration_ms = (time.time() - start_time) * 1000
            
            if memory_percent > self.thresholds['memory_usage']:
                status = HealthStatus.CRITICAL
                message = f"High memory usage: {memory_percent:.1f}%"
            elif memory_percent > self.thresholds['memory_usage'] * 0.8:
                status = HealthStatus.WARNING
                message = f"Elevated memory usage: {memory_percent:.1f}%"
            else:
                status = HealthStatus.HEALTHY
                message = f"Memory usage normal: {memory_percent:.1f}%"
            
            return HealthCheck(
                name="memory_usage",
                status=status,
                message=message,
                details={
                    'memory_percent': memory_percent,
                    'total_gb': memory.total / (1024**3),
                    'available_gb': memory.available / (1024**3),
                    'used_gb': memory.used / (1024**3)
                },
                timestamp=time.time(),
                duration_ms=duration_ms
            )
            
        except Exception as e:
            return HealthCheck(
                name="memory_usage",
                status=HealthStatus.UNKNOWN,
                message=f"Memory check failed: {str(e)}",
                details={'error': str(e)},
                timestamp=time.time(),
                duration_ms=(time.time() - start_time) * 1000
            )
    
    def _check_disk_usage(self) -> HealthCheck:
        """Check disk space usage."""
        start_time = time.time()
        
        try:
            # Check current directory disk usage
            usage = psutil.disk_usage('.')
            disk_percent = (usage.used / usage.total) * 100
            duration_ms = (time.time() - start_time) * 1000
            
            if disk_percent > self.thresholds['disk_usage']:
                status = HealthStatus.CRITICAL
                message = f"Low disk space: {disk_percent:.1f}% used"
            elif disk_percent > self.thresholds['disk_usage'] * 0.8:
                status = HealthStatus.WARNING
                message = f"Disk space getting low: {disk_percent:.1f}% used"
            else:
                status = HealthStatus.HEALTHY
                message = f"Disk space adequate: {disk_percent:.1f}% used"
            
            return HealthCheck(
                name="disk_usage",
                status=status,
                message=message,
                details={
                    'disk_percent': disk_percent,
                    'total_gb': usage.total / (1024**3),
                    'free_gb': usage.free / (1024**3),
                    'used_gb': usage.used / (1024**3)
                },
                timestamp=time.time(),
                duration_ms=duration_ms
            )
            
        except Exception as e:
            return HealthCheck(
                name="disk_usage",
                status=HealthStatus.UNKNOWN,
                message=f"Disk check failed: {str(e)}",
                details={'error': str(e)},
                timestamp=time.time(),
                duration_ms=(time.time() - start_time) * 1000
            )
    
    def _check_dependencies(self) -> HealthCheck:
        """Check critical dependencies."""
        start_time = time.time()
        
        dependencies = {
            'click': 'CLI framework',
            'pyyaml': 'YAML parsing',
            'requests': 'HTTP requests',
            'gitpython': 'Git integration',
            'rich': 'Rich console output',
            'jinja2': 'Template rendering'
        }
        
        missing = []
        versions = {}
        
        for dep, description in dependencies.items():
            try:
                module = __import__(dep)
                version = getattr(module, '__version__', 'unknown')
                versions[dep] = version
            except ImportError:
                missing.append(f"{dep} ({description})")
        
        duration_ms = (time.time() - start_time) * 1000
        
        if missing:
            status = HealthStatus.CRITICAL
            message = f"Missing dependencies: {', '.join(missing)}"
        else:
            status = HealthStatus.HEALTHY
            message = "All dependencies available"
        
        return HealthCheck(
            name="dependencies",
            status=status,
            message=message,
            details={
                'missing': missing,
                'versions': versions
            },
            timestamp=time.time(),
            duration_ms=duration_ms
        )
    
    def _check_file_system_access(self) -> HealthCheck:
        """Check file system access capabilities."""
        start_time = time.time()
        
        try:
            import tempfile
            
            # Test temp directory access
            with tempfile.NamedTemporaryFile(mode='w', delete=True) as f:
                f.write("health check test")
                f.flush()
                
                # Test read access
                with open(f.name, 'r') as read_file:
                    content = read_file.read()
                
                if content == "health check test":
                    status = HealthStatus.HEALTHY
                    message = "File system access normal"
                else:
                    status = HealthStatus.WARNING
                    message = "File system read/write inconsistency"
            
            duration_ms = (time.time() - start_time) * 1000
            
            return HealthCheck(
                name="file_access",
                status=status,
                message=message,
                details={
                    'temp_dir': tempfile.gettempdir(),
                    'can_write': True,
                    'can_read': True
                },
                timestamp=time.time(),
                duration_ms=duration_ms
            )
            
        except Exception as e:
            return HealthCheck(
                name="file_access",
                status=HealthStatus.CRITICAL,
                message=f"File system access failed: {str(e)}",
                details={'error': str(e)},
                timestamp=time.time(),
                duration_ms=(time.time() - start_time) * 1000
            )
    
    def _check_network_connectivity(self) -> HealthCheck:
        """Check network connectivity for external resources."""
        start_time = time.time()
        
        try:
            import socket
            
            # Test DNS resolution and basic connectivity
            socket.create_connection(("8.8.8.8", 53), timeout=5)
            
            status = HealthStatus.HEALTHY
            message = "Network connectivity available"
            details = {'dns_resolution': True, 'connectivity': True}
            
        except Exception as e:
            status = HealthStatus.WARNING
            message = f"Network connectivity limited: {str(e)}"
            details = {'error': str(e), 'connectivity': False}
        
        duration_ms = (time.time() - start_time) * 1000
        
        return HealthCheck(
            name="network",
            status=status,
            message=message,
            details=details,
            timestamp=time.time(),
            duration_ms=duration_ms
        )
    
    def _check_performance_metrics(self) -> HealthCheck:
        """Check application performance metrics."""
        start_time = time.time()
        
        try:
            # Simulate small performance test
            import tempfile
            from pathlib import Path
            
            # Create small test file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write("# Test file for performance check\nprint('hello world')\n")
                test_file = Path(f.name)
            
            # Measure basic file operations
            file_start = time.time()
            
            # Read file
            content = test_file.read_text()
            
            # Basic pattern matching (simulate crypto detection)
            import re
            matches = re.findall(r'import\s+\w+', content)
            
            file_duration = time.time() - file_start
            
            # Cleanup
            test_file.unlink()
            
            # Assess performance
            if file_duration < 0.001:  # < 1ms
                status = HealthStatus.HEALTHY
                message = f"Performance normal: {file_duration*1000:.2f}ms"
            elif file_duration < 0.01:  # < 10ms
                status = HealthStatus.WARNING
                message = f"Performance slower than expected: {file_duration*1000:.2f}ms"
            else:
                status = HealthStatus.CRITICAL
                message = f"Performance degraded: {file_duration*1000:.2f}ms"
            
            duration_ms = (time.time() - start_time) * 1000
            
            return HealthCheck(
                name="performance",
                status=status,
                message=message,
                details={
                    'file_operation_ms': file_duration * 1000,
                    'pattern_matches': len(matches)
                },
                timestamp=time.time(),
                duration_ms=duration_ms
            )
            
        except Exception as e:
            return HealthCheck(
                name="performance",
                status=HealthStatus.UNKNOWN,
                message=f"Performance check failed: {str(e)}",
                details={'error': str(e)},
                timestamp=time.time(),
                duration_ms=(time.time() - start_time) * 1000
            )
    
    def get_overall_health_status(self, checks: Dict[str, HealthCheck]) -> HealthStatus:
        """Determine overall system health status."""
        status_counts = {status: 0 for status in HealthStatus}
        
        for check in checks.values():
            status_counts[check.status] += 1
        
        # Determine overall status based on individual checks
        if status_counts[HealthStatus.CRITICAL] > 0:
            return HealthStatus.CRITICAL
        elif status_counts[HealthStatus.WARNING] > 0:
            return HealthStatus.WARNING
        elif status_counts[HealthStatus.UNKNOWN] > 0:
            return HealthStatus.UNKNOWN
        else:
            return HealthStatus.HEALTHY