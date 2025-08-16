"""
Scalability Engine for Generation 3: Make It Scale
Advanced scaling capabilities, load balancing, and performance optimization.
"""

import asyncio
import concurrent.futures
import multiprocessing
import threading
import time
import json
import hashlib
from typing import List, Dict, Any, Optional, Callable, Union, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import logging
import psutil
import queue

from .types import ScanResults, Vulnerability, Severity


class ScalingStrategy(Enum):
    """Scaling strategies for different workloads."""
    AUTO = "auto"
    VERTICAL = "vertical"  # More resources per worker
    HORIZONTAL = "horizontal"  # More workers
    HYBRID = "hybrid"  # Both approaches


@dataclass
class ScalingMetrics:
    """Metrics for scaling decisions."""
    cpu_utilization: float
    memory_utilization: float
    queue_depth: int
    throughput_files_per_second: float
    active_workers: int
    error_rate: float
    average_response_time: float


@dataclass
class WorkloadProfile:
    """Profile of current workload characteristics."""
    total_files: int
    average_file_size: int
    complexity_score: float  # Based on file types and patterns
    estimated_duration: float
    recommended_workers: int
    recommended_memory_mb: int


class AdaptiveLoadBalancer:
    """Adaptive load balancer that optimizes resource allocation."""
    
    def __init__(self, max_workers: Optional[int] = None):
        """Initialize adaptive load balancer."""
        self.max_workers = max_workers or multiprocessing.cpu_count()
        self.min_workers = max(1, self.max_workers // 4)
        self.current_workers = self.min_workers
        
        self.logger = logging.getLogger(__name__)
        self.metrics_history: List[ScalingMetrics] = []
        self.scaling_decisions: List[Dict[str, Any]] = []
        
        # Performance tracking
        self.start_time = time.time()
        self.files_processed = 0
        self.errors_encountered = 0
        
        # Worker pool management
        self.executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
        self.worker_queues: Dict[int, queue.Queue] = {}
        self.worker_stats: Dict[int, Dict[str, Any]] = {}
    
    def analyze_workload(self, scan_path: Path) -> WorkloadProfile:
        """Analyze workload to determine optimal scaling strategy."""
        try:
            # Count files and estimate complexity
            files = list(scan_path.rglob('*'))
            source_files = [f for f in files if f.is_file() and f.suffix in {'.py', '.java', '.go', '.js', '.ts', '.c', '.cpp'}]
            
            total_files = len(source_files)
            if total_files == 0:
                return WorkloadProfile(
                    total_files=0,
                    average_file_size=0,
                    complexity_score=0.0,
                    estimated_duration=0.0,
                    recommended_workers=1,
                    recommended_memory_mb=512
                )
            
            # Calculate file size statistics
            file_sizes = []
            complexity_factors = []
            
            for file_path in source_files[:100]:  # Sample first 100 files
                try:
                    stat = file_path.stat()
                    file_sizes.append(stat.st_size)
                    
                    # Complexity based on file extension and size
                    complexity = 1.0
                    if file_path.suffix == '.java':
                        complexity *= 1.3  # Java files typically more complex
                    elif file_path.suffix in ['.cpp', '.cc']:
                        complexity *= 1.2  # C++ complexity
                    elif file_path.suffix == '.py':
                        complexity *= 1.1  # Python complexity
                    
                    # Size factor
                    if stat.st_size > 100000:  # Large files
                        complexity *= 1.5
                    elif stat.st_size > 50000:
                        complexity *= 1.2
                    
                    complexity_factors.append(complexity)
                    
                except (OSError, IOError):
                    file_sizes.append(1000)  # Default size
                    complexity_factors.append(1.0)
            
            average_file_size = sum(file_sizes) // len(file_sizes) if file_sizes else 1000
            complexity_score = sum(complexity_factors) / len(complexity_factors) if complexity_factors else 1.0
            
            # Estimate processing time (empirical formula)
            base_time_per_file = 0.01  # 10ms base per file
            time_factor = complexity_score * (average_file_size / 10000)  # Size adjustment
            estimated_duration = total_files * base_time_per_file * time_factor
            
            # Recommend workers based on workload
            if total_files < 50:
                recommended_workers = 1
            elif total_files < 500:
                recommended_workers = min(4, self.max_workers)
            elif total_files < 2000:
                recommended_workers = min(8, self.max_workers)
            else:
                recommended_workers = self.max_workers
            
            # Adjust for complexity
            if complexity_score > 1.5:
                recommended_workers = min(recommended_workers + 2, self.max_workers)
            
            # Memory recommendation
            base_memory = 256  # MB
            memory_per_worker = 128
            file_memory_factor = min(average_file_size / 10000, 5.0)  # Cap the factor
            recommended_memory_mb = int(base_memory + (recommended_workers * memory_per_worker * file_memory_factor))
            
            profile = WorkloadProfile(
                total_files=total_files,
                average_file_size=average_file_size,
                complexity_score=complexity_score,
                estimated_duration=estimated_duration,
                recommended_workers=recommended_workers,
                recommended_memory_mb=recommended_memory_mb
            )
            
            self.logger.info(f"Workload analysis: {total_files} files, complexity {complexity_score:.2f}, "
                           f"recommended {recommended_workers} workers, {recommended_memory_mb}MB memory")
            
            return profile
            
        except Exception as e:
            self.logger.error(f"Workload analysis failed: {e}")
            return WorkloadProfile(
                total_files=0,
                average_file_size=1000,
                complexity_score=1.0,
                estimated_duration=0.0,
                recommended_workers=self.min_workers,
                recommended_memory_mb=512
            )
    
    def collect_metrics(self) -> ScalingMetrics:
        """Collect current performance metrics."""
        try:
            # System metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Calculate throughput
            elapsed_time = time.time() - self.start_time
            throughput = self.files_processed / max(elapsed_time, 0.1)
            
            # Error rate
            total_operations = self.files_processed + self.errors_encountered
            error_rate = self.errors_encountered / max(total_operations, 1)
            
            # Queue depth (simulated for thread pool)
            queue_depth = 0
            if self.executor and hasattr(self.executor, '_threads'):
                queue_depth = len(getattr(self.executor, '_work_queue', []))
            
            # Average response time (estimated)
            avg_response_time = 1.0 / max(throughput, 0.1)
            
            metrics = ScalingMetrics(
                cpu_utilization=cpu_percent,
                memory_utilization=memory_percent,
                queue_depth=queue_depth,
                throughput_files_per_second=throughput,
                active_workers=self.current_workers,
                error_rate=error_rate,
                average_response_time=avg_response_time
            )
            
            # Keep metrics history
            self.metrics_history.append(metrics)
            if len(self.metrics_history) > 100:  # Keep last 100 metrics
                self.metrics_history.pop(0)
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Metrics collection failed: {e}")
            return ScalingMetrics(
                cpu_utilization=50.0,
                memory_utilization=50.0,
                queue_depth=0,
                throughput_files_per_second=1.0,
                active_workers=self.current_workers,
                error_rate=0.0,
                average_response_time=1.0
            )
    
    def make_scaling_decision(self, metrics: ScalingMetrics, strategy: ScalingStrategy = ScalingStrategy.AUTO) -> bool:
        """Make intelligent scaling decisions based on metrics."""
        try:
            decision_made = False
            old_workers = self.current_workers
            
            if strategy == ScalingStrategy.AUTO:
                # Automatic scaling based on multiple factors
                
                # Scale up conditions
                if (metrics.cpu_utilization > 80 and 
                    metrics.queue_depth > 10 and 
                    self.current_workers < self.max_workers):
                    self.current_workers = min(self.current_workers + 2, self.max_workers)
                    decision_made = True
                    reason = "High CPU and queue depth"
                
                elif (metrics.throughput_files_per_second < 5 and 
                      metrics.queue_depth > 5 and 
                      self.current_workers < self.max_workers):
                    self.current_workers = min(self.current_workers + 1, self.max_workers)
                    decision_made = True
                    reason = "Low throughput"
                
                # Scale down conditions
                elif (metrics.cpu_utilization < 30 and 
                      metrics.queue_depth == 0 and 
                      self.current_workers > self.min_workers):
                    self.current_workers = max(self.current_workers - 1, self.min_workers)
                    decision_made = True
                    reason = "Low utilization"
                
                elif (metrics.memory_utilization > 85 and 
                      self.current_workers > self.min_workers):
                    self.current_workers = max(self.current_workers - 1, self.min_workers)
                    decision_made = True
                    reason = "High memory pressure"
                
                else:
                    reason = "No scaling needed"
            
            # Log scaling decision
            decision_info = {
                'timestamp': time.time(),
                'old_workers': old_workers,
                'new_workers': self.current_workers,
                'reason': reason if decision_made else 'No scaling needed',
                'metrics': {
                    'cpu': metrics.cpu_utilization,
                    'memory': metrics.memory_utilization,
                    'throughput': metrics.throughput_files_per_second,
                    'queue_depth': metrics.queue_depth
                }
            }
            
            self.scaling_decisions.append(decision_info)
            
            if decision_made:
                self.logger.info(f"Scaling decision: {old_workers} -> {self.current_workers} workers ({reason})")
                self._adjust_worker_pool()
            
            return decision_made
            
        except Exception as e:
            self.logger.error(f"Scaling decision failed: {e}")
            return False
    
    def _adjust_worker_pool(self):
        """Adjust the worker pool size based on current_workers."""
        try:
            if self.executor:
                # For ThreadPoolExecutor, we need to recreate it with new size
                old_executor = self.executor
                self.executor = concurrent.futures.ThreadPoolExecutor(
                    max_workers=self.current_workers,
                    thread_name_prefix="pqc_worker"
                )
                
                # Gracefully shutdown old executor
                threading.Thread(
                    target=lambda: old_executor.shutdown(wait=True),
                    daemon=True
                ).start()
            else:
                self.executor = concurrent.futures.ThreadPoolExecutor(
                    max_workers=self.current_workers,
                    thread_name_prefix="pqc_worker"
                )
                
        except Exception as e:
            self.logger.error(f"Worker pool adjustment failed: {e}")
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report."""
        if not self.metrics_history:
            return {'status': 'no_data', 'message': 'No metrics available'}
        
        recent_metrics = self.metrics_history[-10:]  # Last 10 metrics
        
        # Calculate averages
        avg_cpu = sum(m.cpu_utilization for m in recent_metrics) / len(recent_metrics)
        avg_memory = sum(m.memory_utilization for m in recent_metrics) / len(recent_metrics)
        avg_throughput = sum(m.throughput_files_per_second for m in recent_metrics) / len(recent_metrics)
        
        # Performance assessment
        performance_score = 100.0
        if avg_cpu > 90:
            performance_score -= 20
        elif avg_cpu > 70:
            performance_score -= 10
        
        if avg_memory > 90:
            performance_score -= 25
        elif avg_memory > 70:
            performance_score -= 10
        
        if avg_throughput < 1:
            performance_score -= 15
        
        # Scaling effectiveness
        scaling_effectiveness = "N/A"
        if len(self.scaling_decisions) > 0:
            successful_scalings = sum(1 for d in self.scaling_decisions if d['old_workers'] != d['new_workers'])
            scaling_effectiveness = f"{successful_scalings}/{len(self.scaling_decisions)} decisions"
        
        report = {
            'performance_score': max(0, performance_score),
            'current_workers': self.current_workers,
            'files_processed': self.files_processed,
            'errors_encountered': self.errors_encountered,
            'average_metrics': {
                'cpu_utilization': avg_cpu,
                'memory_utilization': avg_memory,
                'throughput_fps': avg_throughput
            },
            'scaling_effectiveness': scaling_effectiveness,
            'total_scaling_decisions': len(self.scaling_decisions),
            'uptime_seconds': time.time() - self.start_time,
            'recommendations': self._get_performance_recommendations(avg_cpu, avg_memory, avg_throughput)
        }
        
        return report
    
    def _get_performance_recommendations(self, cpu: float, memory: float, throughput: float) -> List[str]:
        """Get performance optimization recommendations."""
        recommendations = []
        
        if cpu > 85:
            recommendations.append("⚡ Consider reducing worker count or optimizing CPU-intensive operations")
        elif cpu < 30:
            recommendations.append("📈 System is underutilized - consider increasing workload or worker count")
        
        if memory > 85:
            recommendations.append("💾 High memory usage detected - consider reducing batch sizes or worker count")
        
        if throughput < 1:
            recommendations.append("🐌 Low throughput detected - check for I/O bottlenecks or increase workers")
        elif throughput > 50:
            recommendations.append("🚀 Excellent throughput - current configuration is optimal")
        
        if not recommendations:
            recommendations.append("✅ Performance is well-balanced")
        
        return recommendations
    
    def shutdown(self):
        """Gracefully shutdown the load balancer."""
        try:
            if self.executor:
                self.executor.shutdown(wait=True)
                self.executor = None
            
            self.logger.info("Load balancer shutdown completed")
            
        except Exception as e:
            self.logger.error(f"Shutdown error: {e}")


class HighThroughputScanner:
    """High-throughput scanner optimized for large-scale operations."""
    
    def __init__(self, load_balancer: AdaptiveLoadBalancer):
        """Initialize high-throughput scanner."""
        self.load_balancer = load_balancer
        self.logger = logging.getLogger(__name__)
        self.batch_size = 50
        
    async def scan_batch_async(self, file_paths: List[Path], scan_function: Callable) -> List[Vulnerability]:
        """Scan a batch of files asynchronously."""
        try:
            # Create tasks for concurrent processing
            tasks = []
            for file_path in file_paths:
                task = asyncio.create_task(self._scan_file_async(file_path, scan_function))
                tasks.append(task)
            
            # Wait for all tasks to complete
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Collect vulnerabilities
            vulnerabilities = []
            for result in results:
                if isinstance(result, list):
                    vulnerabilities.extend(result)
                elif isinstance(result, Exception):
                    self.logger.error(f"Async scan error: {result}")
                    self.load_balancer.errors_encountered += 1
            
            self.load_balancer.files_processed += len(file_paths)
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Batch async scan failed: {e}")
            return []
    
    async def _scan_file_async(self, file_path: Path, scan_function: Callable) -> List[Vulnerability]:
        """Scan a single file asynchronously."""
        try:
            # Run in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                self.load_balancer.executor,
                scan_function,
                file_path
            )
            return result
            
        except Exception as e:
            self.logger.error(f"Async file scan failed for {file_path}: {e}")
            return []


def main():
    """CLI for scalability engine testing."""
    print("⚡ PQC Migration Audit - Scalability Engine")
    
    # Initialize adaptive load balancer
    load_balancer = AdaptiveLoadBalancer()
    
    # Analyze workload
    test_path = Path("/tmp")
    profile = load_balancer.analyze_workload(test_path)
    
    print(f"\n📊 Workload Analysis:")
    print(f"Total files: {profile.total_files}")
    print(f"Average file size: {profile.average_file_size} bytes")
    print(f"Complexity score: {profile.complexity_score:.2f}")
    print(f"Recommended workers: {profile.recommended_workers}")
    print(f"Recommended memory: {profile.recommended_memory_mb} MB")
    
    # Collect and display metrics
    metrics = load_balancer.collect_metrics()
    print(f"\n🔍 Current Metrics:")
    print(f"CPU: {metrics.cpu_utilization:.1f}%")
    print(f"Memory: {metrics.memory_utilization:.1f}%")
    print(f"Throughput: {metrics.throughput_files_per_second:.2f} files/sec")
    print(f"Active workers: {metrics.active_workers}")
    
    # Test scaling decision
    scaling_made = load_balancer.make_scaling_decision(metrics)
    print(f"\n⚖️  Scaling decision made: {scaling_made}")
    
    # Performance report
    report = load_balancer.get_performance_report()
    print(f"\n📈 Performance Report:")
    print(f"Performance score: {report['performance_score']:.1f}/100")
    print(f"Recommendations:")
    for rec in report['recommendations']:
        print(f"  {rec}")
    
    # Shutdown
    load_balancer.shutdown()


if __name__ == "__main__":
    main()