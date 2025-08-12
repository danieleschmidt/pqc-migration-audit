"""Auto-scaling system for dynamic resource management in PQC research operations."""

import time
import threading
import logging
import multiprocessing
import queue
from typing import Dict, List, Any, Optional, Callable, NamedTuple
from dataclasses import dataclass, field
from enum import Enum
import statistics
from datetime import datetime, timedelta


class ScaleDirection(Enum):
    """Scaling directions."""
    UP = "up"
    DOWN = "down"
    MAINTAIN = "maintain"


class ResourceType(Enum):
    """Types of resources that can be scaled."""
    CPU_WORKERS = "cpu_workers"
    MEMORY_ALLOCATION = "memory_allocation"
    CACHE_SIZE = "cache_size"
    BATCH_SIZE = "batch_size"
    CONCURRENT_OPERATIONS = "concurrent_operations"


@dataclass
class ScalingMetrics:
    """Metrics used for scaling decisions."""
    cpu_utilization: float
    memory_utilization: float
    queue_depth: int
    avg_response_time_ms: float
    throughput_ops_per_sec: float
    error_rate: float
    cache_hit_rate: float
    active_operations: int
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ScalingAction:
    """Represents a scaling action to be taken."""
    resource_type: ResourceType
    direction: ScaleDirection
    magnitude: float  # Percentage or absolute change
    reason: str
    confidence: float  # 0.0 to 1.0
    priority: int  # 1 (highest) to 10 (lowest)


class WorkloadPredictor:
    """Predicts future workload based on historical patterns."""
    
    def __init__(self, history_window_hours: int = 24):
        self.history_window = timedelta(hours=history_window_hours)
        self.metrics_history: List[ScalingMetrics] = []
        self.predictions: Dict[str, float] = {}
        self.logger = logging.getLogger(__name__)
    
    def add_metrics(self, metrics: ScalingMetrics):
        """Add new metrics to history."""
        self.metrics_history.append(metrics)
        
        # Clean old metrics
        cutoff_time = datetime.now() - self.history_window
        self.metrics_history = [
            m for m in self.metrics_history 
            if m.timestamp > cutoff_time
        ]
    
    def predict_workload_change(self, minutes_ahead: int = 30) -> Dict[str, float]:
        """Predict workload changes based on historical patterns."""
        if len(self.metrics_history) < 10:
            return {'confidence': 0.1, 'predicted_cpu': 50.0, 'predicted_queue': 0}
        
        # Simple trend analysis
        recent_metrics = self.metrics_history[-10:]  # Last 10 data points
        
        # Calculate trends
        cpu_trend = self._calculate_trend([m.cpu_utilization for m in recent_metrics])
        queue_trend = self._calculate_trend([m.queue_depth for m in recent_metrics])
        throughput_trend = self._calculate_trend([m.throughput_ops_per_sec for m in recent_metrics])
        
        # Predict future values
        current_cpu = recent_metrics[-1].cpu_utilization
        current_queue = recent_metrics[-1].queue_depth
        
        predicted_cpu = max(0, min(100, current_cpu + cpu_trend * minutes_ahead))
        predicted_queue = max(0, current_queue + queue_trend * minutes_ahead)
        
        confidence = self._calculate_prediction_confidence(recent_metrics)
        
        return {
            'confidence': confidence,
            'predicted_cpu': predicted_cpu,
            'predicted_queue': predicted_queue,
            'predicted_throughput_change': throughput_trend,
            'trend_strength': abs(cpu_trend) + abs(queue_trend)
        }
    
    def _calculate_trend(self, values: List[float]) -> float:
        """Calculate simple linear trend from values."""
        if len(values) < 2:
            return 0.0
        
        n = len(values)
        x_mean = (n - 1) / 2  # Index mean
        y_mean = statistics.mean(values)
        
        # Simple linear regression slope
        numerator = sum((i - x_mean) * (values[i] - y_mean) for i in range(n))
        denominator = sum((i - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            return 0.0
        
        return numerator / denominator
    
    def _calculate_prediction_confidence(self, recent_metrics: List[ScalingMetrics]) -> float:
        """Calculate confidence in predictions based on data quality."""
        if len(recent_metrics) < 5:
            return 0.3
        
        # Base confidence on data consistency
        cpu_values = [m.cpu_utilization for m in recent_metrics]
        cpu_variance = statistics.variance(cpu_values) if len(cpu_values) > 1 else 0
        
        # Lower variance = higher confidence
        base_confidence = max(0.1, min(0.9, 1.0 - (cpu_variance / 100)))
        
        # Adjust for data recency
        time_span = (recent_metrics[-1].timestamp - recent_metrics[0].timestamp).total_seconds()
        if time_span > 3600:  # More than 1 hour of data
            base_confidence = min(0.9, base_confidence * 1.2)
        
        return base_confidence


class AutoScaler:
    """Intelligent auto-scaling system for research operations."""
    
    def __init__(self, min_workers: int = 2, max_workers: int = None):
        self.min_workers = min_workers
        self.max_workers = max_workers or multiprocessing.cpu_count() * 2
        
        # Current resource allocations
        self.current_workers = min_workers
        self.current_cache_size = 1000
        self.current_batch_size = 50
        self.current_memory_limit_mb = 1024
        
        # Scaling parameters
        self.scale_up_threshold = 0.8    # CPU utilization threshold for scaling up
        self.scale_down_threshold = 0.3  # CPU utilization threshold for scaling down
        self.scale_cooldown_seconds = 300  # 5 minutes between scaling actions
        
        # Tracking
        self.last_scaling_action = datetime.min
        self.scaling_history: List[ScalingAction] = []
        self.workload_predictor = WorkloadPredictor()
        self.metrics_queue = queue.Queue(maxsize=100)
        
        # Monitoring
        self._monitoring = False
        self._monitor_thread = None
        self.logger = logging.getLogger(__name__)
    
    def start_monitoring(self):
        """Start auto-scaling monitoring."""
        if not self._monitoring:
            self._monitoring = True
            self._monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self._monitor_thread.start()
            self.logger.info("Auto-scaling monitoring started")
    
    def stop_monitoring(self):
        """Stop auto-scaling monitoring."""
        if self._monitoring:
            self._monitoring = False
            if self._monitor_thread:
                self._monitor_thread.join(timeout=5)
            self.logger.info("Auto-scaling monitoring stopped")
    
    def submit_metrics(self, metrics: ScalingMetrics):
        """Submit metrics for auto-scaling decisions."""
        try:
            self.metrics_queue.put(metrics, block=False)
            self.workload_predictor.add_metrics(metrics)
        except queue.Full:
            # Drop oldest metrics if queue is full
            try:
                self.metrics_queue.get(block=False)
                self.metrics_queue.put(metrics, block=False)
            except queue.Empty:
                pass
    
    def _monitoring_loop(self):
        """Main monitoring loop for auto-scaling decisions."""
        while self._monitoring:
            try:
                # Check if we have new metrics
                if not self.metrics_queue.empty():
                    latest_metrics = None
                    # Get the most recent metrics
                    while not self.metrics_queue.empty():
                        latest_metrics = self.metrics_queue.get(block=False)
                    
                    if latest_metrics:
                        scaling_actions = self._analyze_metrics_and_decide(latest_metrics)
                        for action in scaling_actions:
                            self._execute_scaling_action(action)
                
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Error in auto-scaling monitoring loop: {e}")
                time.sleep(60)  # Back off on error
    
    def _analyze_metrics_and_decide(self, metrics: ScalingMetrics) -> List[ScalingAction]:
        """Analyze metrics and decide on scaling actions."""
        actions = []
        
        # Check if we're in cooldown period
        if datetime.now() - self.last_scaling_action < timedelta(seconds=self.scale_cooldown_seconds):
            return actions
        
        # Get workload predictions
        predictions = self.workload_predictor.predict_workload_change()
        
        # Decide on worker scaling
        worker_action = self._decide_worker_scaling(metrics, predictions)
        if worker_action:
            actions.append(worker_action)
        
        # Decide on cache scaling
        cache_action = self._decide_cache_scaling(metrics, predictions)
        if cache_action:
            actions.append(cache_action)
        
        # Decide on batch size scaling
        batch_action = self._decide_batch_size_scaling(metrics, predictions)
        if batch_action:
            actions.append(batch_action)
        
        # Sort actions by priority
        actions.sort(key=lambda x: x.priority)
        
        return actions
    
    def _decide_worker_scaling(self, metrics: ScalingMetrics, predictions: Dict[str, float]) -> Optional[ScalingAction]:
        """Decide on worker count scaling."""
        current_cpu = metrics.cpu_utilization
        predicted_cpu = predictions.get('predicted_cpu', current_cpu)
        queue_depth = metrics.queue_depth
        
        # Scale up conditions
        if (current_cpu > self.scale_up_threshold * 100 or 
            predicted_cpu > self.scale_up_threshold * 100 or
            queue_depth > self.current_workers * 2):
            
            if self.current_workers < self.max_workers:
                scale_factor = min(2.0, 1.0 + (current_cpu - self.scale_up_threshold * 100) / 100)
                
                return ScalingAction(
                    resource_type=ResourceType.CPU_WORKERS,
                    direction=ScaleDirection.UP,
                    magnitude=scale_factor,
                    reason=f"High CPU ({current_cpu:.1f}%) or queue depth ({queue_depth})",
                    confidence=predictions.get('confidence', 0.7),
                    priority=1
                )
        
        # Scale down conditions
        elif (current_cpu < self.scale_down_threshold * 100 and 
              predicted_cpu < self.scale_down_threshold * 100 and
              queue_depth == 0):
            
            if self.current_workers > self.min_workers:
                return ScalingAction(
                    resource_type=ResourceType.CPU_WORKERS,
                    direction=ScaleDirection.DOWN,
                    magnitude=0.5,  # Scale down by half
                    reason=f"Low CPU ({current_cpu:.1f}%) and no queue",
                    confidence=predictions.get('confidence', 0.6),
                    priority=3
                )
        
        return None
    
    def _decide_cache_scaling(self, metrics: ScalingMetrics, predictions: Dict[str, float]) -> Optional[ScalingAction]:
        """Decide on cache size scaling."""
        cache_hit_rate = metrics.cache_hit_rate
        
        # Scale up cache if hit rate is low
        if cache_hit_rate < 0.6 and self.current_cache_size < 5000:
            return ScalingAction(
                resource_type=ResourceType.CACHE_SIZE,
                direction=ScaleDirection.UP,
                magnitude=1.5,
                reason=f"Low cache hit rate ({cache_hit_rate:.2f})",
                confidence=0.8,
                priority=2
            )
        
        # Scale down cache if hit rate is very high and we need memory
        elif (cache_hit_rate > 0.95 and 
              metrics.memory_utilization > 80 and 
              self.current_cache_size > 500):
            return ScalingAction(
                resource_type=ResourceType.CACHE_SIZE,
                direction=ScaleDirection.DOWN,
                magnitude=0.8,
                reason=f"High cache hit rate ({cache_hit_rate:.2f}) but memory pressure",
                confidence=0.6,
                priority=4
            )
        
        return None
    
    def _decide_batch_size_scaling(self, metrics: ScalingMetrics, predictions: Dict[str, float]) -> Optional[ScalingAction]:
        """Decide on batch size scaling."""
        response_time = metrics.avg_response_time_ms
        throughput = metrics.throughput_ops_per_sec
        
        # Increase batch size if throughput is low and response time is acceptable
        if throughput < 10 and response_time < 1000 and self.current_batch_size < 200:
            return ScalingAction(
                resource_type=ResourceType.BATCH_SIZE,
                direction=ScaleDirection.UP,
                magnitude=1.5,
                reason=f"Low throughput ({throughput:.1f} ops/sec) with acceptable response time",
                confidence=0.7,
                priority=5
            )
        
        # Decrease batch size if response time is high
        elif response_time > 2000 and self.current_batch_size > 10:
            return ScalingAction(
                resource_type=ResourceType.BATCH_SIZE,
                direction=ScaleDirection.DOWN,
                magnitude=0.7,
                reason=f"High response time ({response_time:.0f}ms)",
                confidence=0.8,
                priority=2
            )
        
        return None
    
    def _execute_scaling_action(self, action: ScalingAction):
        """Execute a scaling action."""
        if action.confidence < 0.5:
            self.logger.info(f"Skipping scaling action due to low confidence: {action.confidence}")
            return
        
        self.logger.info(f"Executing scaling action: {action.resource_type.value} {action.direction.value} "
                        f"by {action.magnitude} - {action.reason}")
        
        if action.resource_type == ResourceType.CPU_WORKERS:
            if action.direction == ScaleDirection.UP:
                new_workers = min(self.max_workers, int(self.current_workers * action.magnitude))
            else:
                new_workers = max(self.min_workers, int(self.current_workers * action.magnitude))
            
            if new_workers != self.current_workers:
                self.current_workers = new_workers
                self.logger.info(f"Scaled workers to {self.current_workers}")
        
        elif action.resource_type == ResourceType.CACHE_SIZE:
            if action.direction == ScaleDirection.UP:
                new_cache_size = min(10000, int(self.current_cache_size * action.magnitude))
            else:
                new_cache_size = max(100, int(self.current_cache_size * action.magnitude))
            
            if new_cache_size != self.current_cache_size:
                self.current_cache_size = new_cache_size
                self.logger.info(f"Scaled cache size to {self.current_cache_size}")
        
        elif action.resource_type == ResourceType.BATCH_SIZE:
            if action.direction == ScaleDirection.UP:
                new_batch_size = min(500, int(self.current_batch_size * action.magnitude))
            else:
                new_batch_size = max(5, int(self.current_batch_size * action.magnitude))
            
            if new_batch_size != self.current_batch_size:
                self.current_batch_size = new_batch_size
                self.logger.info(f"Scaled batch size to {self.current_batch_size}")
        
        # Record the action
        self.scaling_history.append(action)
        self.last_scaling_action = datetime.now()
        
        # Keep only recent history
        if len(self.scaling_history) > 100:
            self.scaling_history = self.scaling_history[-100:]
    
    def get_current_configuration(self) -> Dict[str, Any]:
        """Get current resource configuration."""
        return {
            'workers': self.current_workers,
            'cache_size': self.current_cache_size,
            'batch_size': self.current_batch_size,
            'memory_limit_mb': self.current_memory_limit_mb,
            'last_scaling_action': self.last_scaling_action.isoformat() if self.last_scaling_action != datetime.min else None,
            'total_scaling_actions': len(self.scaling_history)
        }
    
    def get_scaling_report(self) -> Dict[str, Any]:
        """Get comprehensive scaling report."""
        recent_actions = self.scaling_history[-10:] if self.scaling_history else []
        
        action_types = {}
        for action in recent_actions:
            resource = action.resource_type.value
            direction = action.direction.value
            key = f"{resource}_{direction}"
            action_types[key] = action_types.get(key, 0) + 1
        
        predictions = self.workload_predictor.predict_workload_change()
        
        return {
            'current_configuration': self.get_current_configuration(),
            'recent_actions': [
                {
                    'resource': a.resource_type.value,
                    'direction': a.direction.value,
                    'magnitude': a.magnitude,
                    'reason': a.reason,
                    'confidence': a.confidence
                }
                for a in recent_actions
            ],
            'action_summary': action_types,
            'workload_predictions': predictions,
            'monitoring_active': self._monitoring,
            'metrics_queue_size': self.metrics_queue.qsize()
        }


# Global auto-scaler instance
global_auto_scaler = AutoScaler()


def auto_scaled_operation(operation_name: str = "default"):
    """Decorator that provides auto-scaling context for operations."""
    def decorator(func):
        from functools import wraps
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                
                # Submit success metrics
                execution_time = time.time() - start_time
                metrics = ScalingMetrics(
                    cpu_utilization=50.0,  # Would need psutil for real values
                    memory_utilization=60.0,
                    queue_depth=0,
                    avg_response_time_ms=execution_time * 1000,
                    throughput_ops_per_sec=1.0 / execution_time if execution_time > 0 else 1.0,
                    error_rate=0.0,
                    cache_hit_rate=0.8,  # Default assumption
                    active_operations=1
                )
                
                global_auto_scaler.submit_metrics(metrics)
                
                return result
                
            except Exception as e:
                # Submit error metrics
                execution_time = time.time() - start_time
                metrics = ScalingMetrics(
                    cpu_utilization=50.0,
                    memory_utilization=60.0,
                    queue_depth=1,
                    avg_response_time_ms=execution_time * 1000,
                    throughput_ops_per_sec=0.0,
                    error_rate=1.0,
                    cache_hit_rate=0.8,
                    active_operations=1
                )
                
                global_auto_scaler.submit_metrics(metrics)
                raise
        
        return wrapper
    return decorator