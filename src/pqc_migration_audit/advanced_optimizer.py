"""Advanced performance optimization with adaptive algorithms and auto-scaling."""

import time
import threading
import multiprocessing
import concurrent.futures
import asyncio
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Iterator
from dataclasses import dataclass, field
import hashlib
import json
import logging
from collections import defaultdict, deque
from functools import lru_cache
import weakref

from .performance_optimizer import PerformanceConfig, AdaptiveScanner


@dataclass 
class AutoScalingMetrics:
    """Metrics for auto-scaling decisions."""
    files_per_second: float = 0.0
    cpu_utilization: float = 0.0
    memory_utilization: float = 0.0
    queue_depth: int = 0
    error_rate: float = 0.0
    cache_hit_rate: float = 0.0
    worker_efficiency: float = 0.0
    
    
class LoadBalancer:
    """Intelligent load balancer for distributing scan work."""
    
    def __init__(self, max_workers: int = None):
        self.max_workers = max_workers or multiprocessing.cpu_count() * 2
        self.worker_stats = defaultdict(lambda: {
            'tasks_completed': 0,
            'total_time': 0.0,
            'errors': 0,
            'current_load': 0
        })
        self.lock = threading.RLock()
        self.logger = logging.getLogger(__name__)
    
    def assign_work(self, tasks: List[Any], workers: List[str]) -> Dict[str, List[Any]]:
        """Intelligently assign work to workers based on performance history."""
        if not workers:
            return {}
        
        with self.lock:
            # Calculate worker efficiency scores
            worker_scores = {}
            for worker in workers:
                stats = self.worker_stats[worker]
                
                # Base efficiency (tasks per second)
                avg_time = stats['total_time'] / max(stats['tasks_completed'], 1)
                efficiency = 1.0 / max(avg_time, 0.001)
                
                # Penalty for errors
                error_penalty = 1.0 - min(stats['errors'] * 0.1, 0.5)
                
                # Penalty for current load
                load_penalty = 1.0 - min(stats['current_load'] * 0.1, 0.3)
                
                worker_scores[worker] = efficiency * error_penalty * load_penalty
            
            # Distribute tasks proportionally to worker scores
            total_score = sum(worker_scores.values())
            if total_score == 0:
                # No history, distribute evenly
                chunk_size = len(tasks) // len(workers)
                return {
                    worker: tasks[i*chunk_size:(i+1)*chunk_size] 
                    for i, worker in enumerate(workers)
                }
            
            # Proportional distribution
            assignments = {worker: [] for worker in workers}
            task_index = 0
            
            for worker in workers:
                proportion = worker_scores[worker] / total_score
                tasks_for_worker = int(len(tasks) * proportion)
                
                end_index = min(task_index + tasks_for_worker, len(tasks))
                assignments[worker] = tasks[task_index:end_index]
                task_index = end_index
                
                # Update current load
                self.worker_stats[worker]['current_load'] += len(assignments[worker])
            
            # Assign remaining tasks to best worker
            if task_index < len(tasks):
                best_worker = max(workers, key=lambda w: worker_scores[w])
                assignments[best_worker].extend(tasks[task_index:])
                self.worker_stats[best_worker]['current_load'] += len(tasks) - task_index
            
            self.logger.info(f"Load balancer assigned {len(tasks)} tasks across {len(workers)} workers")
            return assignments
    
    def report_completion(self, worker: str, tasks_completed: int, 
                         total_time: float, errors: int = 0):
        """Report task completion statistics."""
        with self.lock:
            stats = self.worker_stats[worker]
            stats['tasks_completed'] += tasks_completed
            stats['total_time'] += total_time
            stats['errors'] += errors
            stats['current_load'] = max(0, stats['current_load'] - tasks_completed)


class AutoScaler:
    """Auto-scaling system that adjusts resources based on performance."""
    
    def __init__(self, min_workers: int = 2, max_workers: int = None):
        self.min_workers = min_workers
        self.max_workers = max_workers or multiprocessing.cpu_count() * 4
        self.current_workers = self.min_workers
        
        self.metrics_history: deque = deque(maxlen=50)
        self.scaling_cooldown = 30  # seconds
        self.last_scale_time = 0
        
        self.logger = logging.getLogger(__name__)
    
    def should_scale_up(self, metrics: AutoScalingMetrics) -> bool:
        """Determine if we should scale up workers."""
        if self.current_workers >= self.max_workers:
            return False
        
        if time.time() - self.last_scale_time < self.scaling_cooldown:
            return False
        
        # Scale up conditions
        conditions = [
            metrics.cpu_utilization > 80.0,  # High CPU usage
            metrics.queue_depth > self.current_workers * 5,  # Large queue
            metrics.files_per_second < 10.0 and len(self.metrics_history) > 5,  # Low throughput
            metrics.cache_hit_rate > 0.7 and metrics.files_per_second < 20.0  # Good cache but low throughput
        ]
        
        return sum(conditions) >= 2  # At least 2 conditions must be met
    
    def should_scale_down(self, metrics: AutoScalingMetrics) -> bool:
        """Determine if we should scale down workers."""
        if self.current_workers <= self.min_workers:
            return False
        
        if time.time() - self.last_scale_time < self.scaling_cooldown * 2:  # Longer cooldown for scale down
            return False
        
        # Scale down conditions
        conditions = [
            metrics.cpu_utilization < 30.0,  # Low CPU usage
            metrics.queue_depth == 0,  # Empty queue
            metrics.files_per_second > 50.0,  # High throughput (don't need all workers)
            metrics.worker_efficiency < 0.5  # Workers are inefficient
        ]
        
        return sum(conditions) >= 3  # More conservative for scale down
    
    def scale(self, metrics: AutoScalingMetrics) -> int:
        """Make scaling decision and return new worker count."""
        old_workers = self.current_workers
        
        if self.should_scale_up(metrics):
            # Scale up by 50% or at least 1 worker
            scale_factor = max(1, int(self.current_workers * 0.5))
            self.current_workers = min(self.max_workers, self.current_workers + scale_factor)
            self.last_scale_time = time.time()
            self.logger.info(f"Scaled UP from {old_workers} to {self.current_workers} workers")
            
        elif self.should_scale_down(metrics):
            # Scale down by 25% or at least 1 worker
            scale_factor = max(1, int(self.current_workers * 0.25))
            self.current_workers = max(self.min_workers, self.current_workers - scale_factor)
            self.last_scale_time = time.time()
            self.logger.info(f"Scaled DOWN from {old_workers} to {self.current_workers} workers")
        
        self.metrics_history.append(metrics)
        return self.current_workers


class IntelligentBatchOptimizer:
    """Optimizes batch sizes based on file characteristics and performance."""
    
    def __init__(self):
        self.size_based_batches = {
            'tiny': {'max_size': 1024, 'batch_size': 200},       # < 1KB files
            'small': {'max_size': 10*1024, 'batch_size': 100},   # < 10KB files  
            'medium': {'max_size': 100*1024, 'batch_size': 50},  # < 100KB files
            'large': {'max_size': 1024*1024, 'batch_size': 20},  # < 1MB files
            'huge': {'max_size': float('inf'), 'batch_size': 5}  # >= 1MB files
        }
        
        self.performance_history = defaultdict(list)
        self.logger = logging.getLogger(__name__)
    
    def optimize_batches(self, file_paths: List[Path]) -> List[List[Path]]:
        """Create optimized batches based on file sizes and performance history."""
        # Group files by size category
        size_groups = defaultdict(list)
        
        for file_path in file_paths:
            try:
                file_size = file_path.stat().st_size
                category = self._categorize_file_size(file_size)
                size_groups[category].append(file_path)
            except OSError:
                size_groups['small'].append(file_path)  # Default for inaccessible files
        
        # Create batches for each size category
        all_batches = []
        
        for category, files in size_groups.items():
            batch_config = self.size_based_batches[category]
            batch_size = self._adaptive_batch_size(category, batch_config['batch_size'])
            
            # Create batches
            for i in range(0, len(files), batch_size):
                batch = files[i:i + batch_size]
                all_batches.append(batch)
        
        self.logger.info(f"Created {len(all_batches)} optimized batches from {len(file_paths)} files")
        return all_batches
    
    def _categorize_file_size(self, size: int) -> str:
        """Categorize file by size."""
        for category, config in self.size_based_batches.items():
            if size <= config['max_size']:
                return category
        return 'huge'
    
    def _adaptive_batch_size(self, category: str, base_batch_size: int) -> int:
        """Adapt batch size based on performance history."""
        history = self.performance_history[category]
        
        if len(history) < 3:
            return base_batch_size
        
        # Calculate average performance (files per second) for last few batches
        recent_performance = sum(h['files_per_second'] for h in history[-3:]) / 3
        
        # Adjust batch size based on performance
        if recent_performance > 50:  # High performance, can handle larger batches
            return min(base_batch_size * 2, 500)
        elif recent_performance < 10:  # Low performance, use smaller batches
            return max(base_batch_size // 2, 5)
        else:
            return base_batch_size
    
    def record_batch_performance(self, category: str, batch_size: int, 
                                files_per_second: float, error_count: int):
        """Record batch performance for future optimization."""
        self.performance_history[category].append({
            'batch_size': batch_size,
            'files_per_second': files_per_second,
            'error_count': error_count,
            'timestamp': time.time()
        })
        
        # Keep only recent history
        if len(self.performance_history[category]) > 20:
            self.performance_history[category] = self.performance_history[category][-20:]


class PredictiveCache:
    """Predictive caching system that preloads likely-to-be-accessed files."""
    
    def __init__(self, cache_size: int = 5000):
        self.cache_size = cache_size
        self.cache: Dict[str, Any] = {}
        self.access_patterns = defaultdict(int)
        self.prediction_model = {}
        
        self.lock = threading.RLock()
        self.logger = logging.getLogger(__name__)
    
    def predict_next_files(self, current_file: Path, n: int = 5) -> List[Path]:
        """Predict which files are likely to be accessed next."""
        current_dir = current_file.parent
        current_name = current_file.name
        
        # Simple prediction: files in same directory or with similar names
        predictions = []
        
        try:
            # Files in same directory
            for sibling in current_dir.iterdir():
                if sibling.is_file() and sibling != current_file:
                    predictions.append(sibling)
            
            # Sort by similarity to current file name
            predictions.sort(key=lambda p: self._name_similarity(current_name, p.name), reverse=True)
            
        except OSError:
            pass
        
        return predictions[:n]
    
    def _name_similarity(self, name1: str, name2: str) -> float:
        """Calculate similarity between file names."""
        # Simple similarity based on common prefixes and extensions
        
        # Same extension gets bonus
        similarity = 0.0
        if Path(name1).suffix == Path(name2).suffix:
            similarity += 0.3
        
        # Common prefix length
        prefix_len = 0
        for c1, c2 in zip(name1, name2):
            if c1 == c2:
                prefix_len += 1
            else:
                break
        
        similarity += min(prefix_len / max(len(name1), len(name2)), 0.7)
        
        return similarity
    
    def preload_predictions(self, file_path: Path, loader_func):
        """Preload predicted files into cache."""
        predictions = self.predict_next_files(file_path)
        
        for predicted_file in predictions:
            cache_key = str(predicted_file)
            
            with self.lock:
                if cache_key not in self.cache and len(self.cache) < self.cache_size:
                    try:
                        # Load in background thread
                        def load_async():
                            try:
                                result = loader_func(predicted_file)
                                with self.lock:
                                    if len(self.cache) < self.cache_size:
                                        self.cache[cache_key] = result
                            except Exception as e:
                                self.logger.debug(f"Preload failed for {predicted_file}: {e}")
                        
                        threading.Thread(target=load_async, daemon=True).start()
                        
                    except Exception as e:
                        self.logger.debug(f"Preload error for {predicted_file}: {e}")


class AdvancedPerformanceOrchestrator:
    """Orchestrates all advanced performance optimization components."""
    
    def __init__(self, config: Optional[PerformanceConfig] = None):
        self.config = config or PerformanceConfig()
        
        # Initialize optimization components
        self.load_balancer = LoadBalancer(self.config.max_workers)
        self.auto_scaler = AutoScaler(min_workers=2, max_workers=self.config.max_workers)
        self.batch_optimizer = IntelligentBatchOptimizer()
        self.predictive_cache = PredictiveCache(self.config.cache_size)
        
        self.logger = logging.getLogger(__name__)
        
        # Performance tracking
        self.scan_history: deque = deque(maxlen=100)
        self.optimization_stats = {
            'total_scans': 0,
            'auto_scaling_events': 0,
            'cache_predictions': 0,
            'load_balancing_decisions': 0
        }
    
    def scan_with_advanced_optimization(self, file_paths: List[Path], 
                                      scanner_func) -> Tuple[List[Any], Dict[str, Any]]:
        """Perform scan with all advanced optimizations enabled."""
        scan_start_time = time.time()
        
        # Step 1: Create optimized batches
        batches = self.batch_optimizer.optimize_batches(file_paths)
        self.logger.info(f"Created {len(batches)} optimized batches")
        
        # Step 2: Initial metrics collection
        initial_metrics = self._collect_metrics()
        
        # Step 3: Auto-scaling decision
        optimal_workers = self.auto_scaler.scale(initial_metrics)
        
        # Step 4: Load balancing
        worker_ids = [f"worker_{i}" for i in range(optimal_workers)]
        work_assignments = self.load_balancer.assign_work(batches, worker_ids)
        
        # Step 5: Execute with concurrent processing and predictive caching
        all_results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=optimal_workers) as executor:
            future_to_worker = {}
            
            for worker_id, worker_batches in work_assignments.items():
                if worker_batches:  # Only submit if there's work
                    future = executor.submit(
                        self._process_worker_batches, 
                        worker_id, worker_batches, scanner_func
                    )
                    future_to_worker[future] = worker_id
            
            # Collect results
            for future in concurrent.futures.as_completed(future_to_worker):
                worker_id = future_to_worker[future]
                try:
                    worker_results, worker_stats = future.result()
                    all_results.extend(worker_results)
                    
                    # Report completion to load balancer
                    self.load_balancer.report_completion(
                        worker_id,
                        worker_stats['tasks_completed'],
                        worker_stats['total_time'],
                        worker_stats['errors']
                    )
                    
                except Exception as e:
                    self.logger.error(f"Worker {worker_id} failed: {e}")
        
        # Step 6: Final metrics and performance report
        scan_duration = time.time() - scan_start_time
        final_metrics = self._collect_metrics()
        
        performance_report = {
            'scan_duration': scan_duration,
            'files_processed': len(file_paths),
            'files_per_second': len(file_paths) / scan_duration if scan_duration > 0 else 0,
            'batches_created': len(batches),
            'workers_used': optimal_workers,
            'results_found': len(all_results),
            'initial_metrics': initial_metrics,
            'final_metrics': final_metrics,
            'optimization_stats': self.optimization_stats
        }
        
        # Update history
        self.scan_history.append(performance_report)
        self.optimization_stats['total_scans'] += 1
        
        self.logger.info(f"Advanced scan completed: {len(file_paths)} files in {scan_duration:.2f}s "
                        f"({performance_report['files_per_second']:.1f} files/sec)")
        
        return all_results, performance_report
    
    def _process_worker_batches(self, worker_id: str, batches: List[List[Path]], 
                              scanner_func) -> Tuple[List[Any], Dict[str, Any]]:
        """Process batches assigned to a worker."""
        worker_start_time = time.time()
        worker_results = []
        errors = 0
        
        for batch in batches:
            try:
                # Process batch
                batch_start_time = time.time()
                
                batch_results = []
                for file_path in batch:
                    try:
                        # Predictive caching
                        self.predictive_cache.preload_predictions(file_path, scanner_func)
                        
                        # Scan file
                        result = scanner_func(file_path)
                        batch_results.append(result)
                        
                    except Exception as e:
                        self.logger.error(f"Error scanning {file_path}: {e}")
                        errors += 1
                
                worker_results.extend(batch_results)
                
                # Record batch performance
                batch_duration = time.time() - batch_start_time
                files_per_second = len(batch) / batch_duration if batch_duration > 0 else 0
                
                # Determine file size category for the batch
                avg_size = sum(f.stat().st_size for f in batch if f.exists()) / len(batch)
                category = self.batch_optimizer._categorize_file_size(avg_size)
                
                self.batch_optimizer.record_batch_performance(
                    category, len(batch), files_per_second, errors
                )
                
            except Exception as e:
                self.logger.error(f"Batch processing error for worker {worker_id}: {e}")
                errors += 1
        
        worker_stats = {
            'tasks_completed': len(batches),
            'total_time': time.time() - worker_start_time,
            'errors': errors
        }
        
        return worker_results, worker_stats
    
    def _collect_metrics(self) -> AutoScalingMetrics:
        """Collect current performance metrics."""
        import psutil
        
        # CPU and memory metrics
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory_percent = psutil.virtual_memory().percent
        
        # Application-specific metrics (simplified)
        recent_scans = list(self.scan_history)[-5:] if self.scan_history else []
        avg_fps = sum(s['files_per_second'] for s in recent_scans) / len(recent_scans) if recent_scans else 0
        
        return AutoScalingMetrics(
            files_per_second=avg_fps,
            cpu_utilization=cpu_percent,
            memory_utilization=memory_percent,
            queue_depth=0,  # Would need actual queue implementation
            error_rate=0.0,  # Would track from worker stats
            cache_hit_rate=0.8,  # Placeholder
            worker_efficiency=0.75  # Placeholder
        )
    
    def get_comprehensive_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance optimization report."""
        return {
            'optimization_stats': self.optimization_stats,
            'recent_performance': list(self.scan_history)[-10:],
            'auto_scaler_status': {
                'current_workers': self.auto_scaler.current_workers,
                'min_workers': self.auto_scaler.min_workers,
                'max_workers': self.auto_scaler.max_workers,
                'metrics_history_size': len(self.auto_scaler.metrics_history)
            },
            'load_balancer_stats': dict(self.load_balancer.worker_stats),
            'batch_optimizer_history': dict(self.batch_optimizer.performance_history),
            'predictive_cache_stats': {
                'cache_size': len(self.predictive_cache.cache),
                'max_cache_size': self.predictive_cache.cache_size
            }
        }