"""Advanced performance optimization engine with adaptive algorithms and intelligent caching."""

import time
import threading
import logging
import multiprocessing
import hashlib
import pickle
import zlib
import mmap
import queue
from typing import Dict, List, Any, Optional, Callable, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from functools import wraps, lru_cache
import asyncio
import weakref
import gc
import os
import sys
from pathlib import Path
import statistics
import psutil


class OptimizationStrategy(Enum):
    """Performance optimization strategies."""
    CACHING = "caching"
    PARALLEL_PROCESSING = "parallel_processing"
    MEMORY_OPTIMIZATION = "memory_optimization"
    BATCH_PROCESSING = "batch_processing"
    LAZY_LOADING = "lazy_loading"
    COMPRESSION = "compression"
    MEMORY_MAPPING = "memory_mapping"
    ADAPTIVE_ALGORITHMS = "adaptive_algorithms"


class CacheStrategy(Enum):
    """Caching strategies."""
    LRU = "lru"
    LFU = "lfu"
    TTL = "ttl"
    ADAPTIVE = "adaptive"
    WRITE_THROUGH = "write_through"
    WRITE_BACK = "write_back"


class ProcessingMode(Enum):
    """Processing modes for different workloads."""
    SINGLE_THREADED = "single_threaded"
    MULTI_THREADED = "multi_threaded"
    MULTI_PROCESS = "multi_process"
    ASYNC = "async"
    HYBRID = "hybrid"


@dataclass
class PerformanceMetrics:
    """Performance metrics for optimization decisions."""
    execution_time_ms: float
    memory_usage_mb: float
    cpu_utilization: float
    cache_hit_rate: float
    throughput_ops_per_sec: float
    latency_p95_ms: float
    error_rate: float
    resource_efficiency: float
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class OptimizationConfig:
    """Configuration for performance optimization."""
    enabled: bool = True
    cache_size_mb: int = 256
    max_workers: int = None
    batch_size: int = 100
    compression_enabled: bool = True
    memory_mapping_enabled: bool = True
    adaptive_optimization: bool = True
    performance_target_ms: float = 1000.0
    memory_limit_mb: int = 2048
    cache_strategy: CacheStrategy = CacheStrategy.ADAPTIVE
    processing_mode: ProcessingMode = ProcessingMode.HYBRID


class AdaptiveCache:
    """Intelligent cache with multiple strategies and adaptive behavior."""
    
    def __init__(self, max_size_mb: int = 256, strategy: CacheStrategy = CacheStrategy.ADAPTIVE):
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.strategy = strategy
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.access_count: Dict[str, int] = {}
        self.access_time: Dict[str, datetime] = {}
        self.size_tracker: Dict[str, int] = {}
        self.total_size = 0
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self._lock = threading.RLock()
        self.logger = logging.getLogger(f"{__name__}.cache")
        
        # Adaptive strategy parameters
        self.performance_history: List[Tuple[str, float]] = []  # (strategy, hit_rate)
        self.strategy_weights = {
            CacheStrategy.LRU: 0.25,
            CacheStrategy.LFU: 0.25,
            CacheStrategy.TTL: 0.25,
            CacheStrategy.ADAPTIVE: 0.25
        }
    
    def get(self, key: str, default=None) -> Any:
        """Get value from cache with strategy-specific logic."""
        with self._lock:
            if key in self.cache:
                entry = self.cache[key]
                
                # Check TTL expiration
                if entry.get('expires_at') and entry['expires_at'] < datetime.now():
                    self._remove_entry(key)
                    self.misses += 1
                    return default
                
                # Update access patterns
                self.access_count[key] = self.access_count.get(key, 0) + 1
                self.access_time[key] = datetime.now()
                
                self.hits += 1
                return entry['value']
            else:
                self.misses += 1
                return default
    
    def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> bool:
        """Set value in cache with intelligent eviction."""
        with self._lock:
            # Calculate size of new entry
            try:
                serialized = pickle.dumps(value)
                compressed = zlib.compress(serialized)
                entry_size = len(compressed)
            except Exception:
                # Fallback size estimation
                entry_size = sys.getsizeof(value)
            
            # Check if entry is too large for cache
            if entry_size > self.max_size_bytes * 0.5:  # No single entry > 50% of cache
                self.logger.warning(f"Entry too large for cache: {entry_size} bytes")
                return False
            
            # Ensure space for new entry
            while self.total_size + entry_size > self.max_size_bytes and self.cache:
                self._evict_entry()
            
            # Remove existing entry if updating
            if key in self.cache:
                self._remove_entry(key)
            
            # Add new entry
            expires_at = None
            if ttl_seconds:
                expires_at = datetime.now() + timedelta(seconds=ttl_seconds)
            
            self.cache[key] = {
                'value': value,
                'compressed_data': compressed,
                'created_at': datetime.now(),
                'expires_at': expires_at,
                'access_count': 0
            }
            
            self.size_tracker[key] = entry_size
            self.total_size += entry_size
            self.access_count[key] = 1
            self.access_time[key] = datetime.now()
            
            return True
    
    def _evict_entry(self):
        """Evict entry based on current strategy."""
        if not self.cache:
            return
        
        eviction_key = None
        
        if self.strategy == CacheStrategy.LRU:
            # Least Recently Used
            eviction_key = min(self.access_time.keys(), key=lambda k: self.access_time[k])
        
        elif self.strategy == CacheStrategy.LFU:
            # Least Frequently Used
            eviction_key = min(self.access_count.keys(), key=lambda k: self.access_count[k])
        
        elif self.strategy == CacheStrategy.TTL:
            # Shortest TTL first, then LRU
            ttl_entries = [
                (k, v['expires_at']) for k, v in self.cache.items() 
                if v.get('expires_at')
            ]
            if ttl_entries:
                eviction_key = min(ttl_entries, key=lambda x: x[1])[0]
            else:
                eviction_key = min(self.access_time.keys(), key=lambda k: self.access_time[k])
        
        elif self.strategy == CacheStrategy.ADAPTIVE:
            # Adaptive strategy based on performance
            eviction_key = self._adaptive_eviction()
        
        if eviction_key:
            self._remove_entry(eviction_key)
            self.evictions += 1
    
    def _adaptive_eviction(self) -> Optional[str]:
        """Adaptive eviction based on performance patterns."""
        if not self.cache:
            return None
        
        # Score entries based on multiple factors
        scores = {}
        now = datetime.now()
        
        for key in self.cache.keys():
            access_count = self.access_count.get(key, 1)
            last_access = self.access_time.get(key, now)
            time_since_access = (now - last_access).total_seconds()
            
            # Size factor (larger entries more likely to be evicted)
            size_factor = self.size_tracker.get(key, 0) / self.max_size_bytes
            
            # Recency factor (older accesses more likely to be evicted)
            recency_factor = min(1.0, time_since_access / 3600)  # Normalize by 1 hour
            
            # Frequency factor (less accessed more likely to be evicted)
            max_access = max(self.access_count.values()) if self.access_count else 1
            frequency_factor = 1.0 - (access_count / max_access)
            
            # Combined score (higher score = more likely to evict)
            scores[key] = (size_factor * 0.3 + recency_factor * 0.4 + frequency_factor * 0.3)
        
        # Return key with highest eviction score
        return max(scores.keys(), key=lambda k: scores[k])
    
    def _remove_entry(self, key: str):
        """Remove entry from cache and update tracking."""
        if key in self.cache:
            self.total_size -= self.size_tracker.get(key, 0)
            del self.cache[key]
            del self.size_tracker[key]
            del self.access_count[key]
            del self.access_time[key]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total_requests = self.hits + self.misses
        hit_rate = self.hits / max(1, total_requests) * 100
        
        return {
            'size_mb': self.total_size / (1024 * 1024),
            'max_size_mb': self.max_size_bytes / (1024 * 1024),
            'utilization_percent': (self.total_size / self.max_size_bytes) * 100,
            'entries': len(self.cache),
            'hits': self.hits,
            'misses': self.misses,
            'evictions': self.evictions,
            'hit_rate_percent': hit_rate,
            'strategy': self.strategy.value
        }
    
    def clear(self):
        """Clear all cache entries."""
        with self._lock:
            self.cache.clear()
            self.access_count.clear()
            self.access_time.clear()
            self.size_tracker.clear()
            self.total_size = 0
    
    def optimize_strategy(self):
        """Optimize cache strategy based on performance history."""
        if self.strategy != CacheStrategy.ADAPTIVE:
            return
        
        # Analyze recent performance
        recent_performance = self.performance_history[-100:]  # Last 100 measurements
        if len(recent_performance) < 10:
            return
        
        # Group by strategy and calculate average hit rates
        strategy_performance = {}
        for strategy_name, hit_rate in recent_performance:
            if strategy_name not in strategy_performance:
                strategy_performance[strategy_name] = []
            strategy_performance[strategy_name].append(hit_rate)
        
        # Update strategy weights based on performance
        for strategy_name, hit_rates in strategy_performance.items():
            avg_hit_rate = statistics.mean(hit_rates)
            try:
                strategy_enum = CacheStrategy(strategy_name)
                # Increase weight for better performing strategies
                self.strategy_weights[strategy_enum] = avg_hit_rate / 100.0
            except ValueError:
                continue
        
        # Normalize weights
        total_weight = sum(self.strategy_weights.values())
        if total_weight > 0:
            for strategy in self.strategy_weights:
                self.strategy_weights[strategy] /= total_weight


class PerformanceOptimizer:
    """Advanced performance optimization engine."""
    
    def __init__(self, config: OptimizationConfig = None):
        self.config = config or OptimizationConfig()
        self.cache = AdaptiveCache(
            max_size_mb=self.config.cache_size_mb,
            strategy=self.config.cache_strategy
        )
        self.metrics_history: List[PerformanceMetrics] = []
        self.optimization_history: List[Dict[str, Any]] = []
        self.active_optimizations: Dict[str, Any] = {}
        
        # Thread pools for different processing modes
        self.thread_pool = ThreadPoolExecutor(
            max_workers=self.config.max_workers or multiprocessing.cpu_count()
        )
        self.process_pool = ProcessPoolExecutor(
            max_workers=min(4, multiprocessing.cpu_count())
        )
        
        # Memory management
        self.memory_pool = {}
        self.memory_usage = 0
        
        # Performance monitoring
        self._monitoring = False
        self._monitor_thread = None
        self.logger = logging.getLogger(__name__)
        
        # Adaptive algorithm parameters
        self.algorithm_performance: Dict[str, List[float]] = {}
        self.current_algorithms: Dict[str, str] = {}
        
        self._lock = threading.RLock()
    
    def start_monitoring(self):
        """Start performance monitoring."""
        if not self._monitoring:
            self._monitoring = True
            self._monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self._monitor_thread.start()
            self.logger.info("Performance monitoring started")
    
    def stop_monitoring(self):
        """Stop performance monitoring."""
        if self._monitoring:
            self._monitoring = False
            if self._monitor_thread:
                self._monitor_thread.join(timeout=5)
            self.logger.info("Performance monitoring stopped")
    
    def _monitoring_loop(self):
        """Performance monitoring loop."""
        while self._monitoring:
            try:
                # Collect system metrics
                process = psutil.Process()
                
                metrics = PerformanceMetrics(
                    execution_time_ms=0.0,  # Set by operations
                    memory_usage_mb=process.memory_info().rss / 1024 / 1024,
                    cpu_utilization=process.cpu_percent(),
                    cache_hit_rate=self._calculate_cache_hit_rate(),
                    throughput_ops_per_sec=self._calculate_throughput(),
                    latency_p95_ms=self._calculate_p95_latency(),
                    error_rate=0.0,  # Set by operations
                    resource_efficiency=self._calculate_resource_efficiency()
                )
                
                self.record_metrics(metrics)
                
                # Perform automatic optimizations
                if self.config.adaptive_optimization:
                    self._perform_adaptive_optimizations(metrics)
                
                time.sleep(30)  # Monitor every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Error in performance monitoring: {e}")
                time.sleep(60)
    
    def record_metrics(self, metrics: PerformanceMetrics):
        """Record performance metrics."""
        with self._lock:
            self.metrics_history.append(metrics)
            
            # Keep only recent metrics
            if len(self.metrics_history) > 1000:
                self.metrics_history = self.metrics_history[-1000:]
    
    def optimize_function(self, func: Callable, optimization_strategies: List[OptimizationStrategy] = None):
        """Optimize a function with specified strategies."""
        if optimization_strategies is None:
            optimization_strategies = [
                OptimizationStrategy.CACHING,
                OptimizationStrategy.PARALLEL_PROCESSING,
                OptimizationStrategy.BATCH_PROCESSING
            ]
        
        @wraps(func)
        def optimized_wrapper(*args, **kwargs):
            start_time = time.time()
            
            try:
                # Apply optimizations
                result = self._apply_optimizations(
                    func, args, kwargs, optimization_strategies
                )
                
                # Record success metrics
                execution_time = (time.time() - start_time) * 1000
                self._record_operation_metrics(func.__name__, execution_time, True)
                
                return result
                
            except Exception as e:
                # Record failure metrics
                execution_time = (time.time() - start_time) * 1000
                self._record_operation_metrics(func.__name__, execution_time, False)
                raise
        
        return optimized_wrapper
    
    def _apply_optimizations(self, func: Callable, args: tuple, kwargs: dict, 
                           strategies: List[OptimizationStrategy]) -> Any:
        """Apply optimization strategies to function execution."""
        
        # Check cache first if caching is enabled
        if OptimizationStrategy.CACHING in strategies:
            cache_key = self._generate_cache_key(func, args, kwargs)
            cached_result = self.cache.get(cache_key)
            if cached_result is not None:
                return cached_result
        
        # Determine best processing mode
        processing_mode = self._determine_processing_mode(func, args, kwargs, strategies)
        
        # Execute with optimizations
        if processing_mode == ProcessingMode.MULTI_PROCESS:
            result = self._execute_multiprocess(func, args, kwargs)
        elif processing_mode == ProcessingMode.MULTI_THREADED:
            result = self._execute_multithreaded(func, args, kwargs)
        elif processing_mode == ProcessingMode.ASYNC:
            result = self._execute_async(func, args, kwargs)
        else:
            result = func(*args, **kwargs)
        
        # Cache result if caching is enabled
        if OptimizationStrategy.CACHING in strategies:
            cache_key = self._generate_cache_key(func, args, kwargs)
            self.cache.set(cache_key, result)
        
        return result
    
    def _generate_cache_key(self, func: Callable, args: tuple, kwargs: dict) -> str:
        """Generate cache key for function call."""
        key_parts = [func.__name__]
        
        # Add args to key
        for arg in args:
            if isinstance(arg, (str, int, float, bool)):
                key_parts.append(str(arg))
            else:
                # Hash complex objects
                key_parts.append(hashlib.md5(str(arg).encode()).hexdigest()[:8])
        
        # Add kwargs to key
        for k, v in sorted(kwargs.items()):
            if isinstance(v, (str, int, float, bool)):
                key_parts.append(f"{k}={v}")
            else:
                key_parts.append(f"{k}={hashlib.md5(str(v).encode()).hexdigest()[:8]}")
        
        return "|".join(key_parts)
    
    def _determine_processing_mode(self, func: Callable, args: tuple, kwargs: dict,
                                 strategies: List[OptimizationStrategy]) -> ProcessingMode:
        """Determine optimal processing mode for function."""
        
        # Check if function is async
        if asyncio.iscoroutinefunction(func):
            return ProcessingMode.ASYNC
        
        # Check for parallel processing optimization
        if OptimizationStrategy.PARALLEL_PROCESSING not in strategies:
            return ProcessingMode.SINGLE_THREADED
        
        # Analyze function characteristics
        arg_size = sum(sys.getsizeof(arg) for arg in args)
        kwarg_size = sum(sys.getsizeof(v) for v in kwargs.values())
        total_data_size = arg_size + kwarg_size
        
        # Check CPU vs I/O bound heuristics
        if total_data_size > 1024 * 1024:  # > 1MB of data
            return ProcessingMode.MULTI_PROCESS
        elif hasattr(func, '__name__') and any(
            keyword in func.__name__.lower() 
            for keyword in ['scan', 'analyze', 'process', 'compute']
        ):
            return ProcessingMode.MULTI_THREADED
        else:
            return ProcessingMode.SINGLE_THREADED
    
    def _execute_multiprocess(self, func: Callable, args: tuple, kwargs: dict) -> Any:
        """Execute function using multiprocessing."""
        try:
            future = self.process_pool.submit(func, *args, **kwargs)
            return future.result(timeout=self.config.performance_target_ms / 1000)
        except Exception as e:
            self.logger.warning(f"Multiprocess execution failed, falling back: {e}")
            return func(*args, **kwargs)
    
    def _execute_multithreaded(self, func: Callable, args: tuple, kwargs: dict) -> Any:
        """Execute function using multithreading."""
        try:
            future = self.thread_pool.submit(func, *args, **kwargs)
            return future.result(timeout=self.config.performance_target_ms / 1000)
        except Exception as e:
            self.logger.warning(f"Multithreaded execution failed, falling back: {e}")
            return func(*args, **kwargs)
    
    def _execute_async(self, func: Callable, args: tuple, kwargs: dict) -> Any:
        """Execute async function."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(func(*args, **kwargs))
    
    def _record_operation_metrics(self, operation_name: str, execution_time_ms: float, success: bool):
        """Record metrics for a specific operation."""
        if operation_name not in self.algorithm_performance:
            self.algorithm_performance[operation_name] = []
        
        # Record performance (higher is better, so use 1/time for successful operations)
        performance_score = (1000.0 / execution_time_ms) if success and execution_time_ms > 0 else 0.0
        self.algorithm_performance[operation_name].append(performance_score)
        
        # Keep only recent performance data
        if len(self.algorithm_performance[operation_name]) > 100:
            self.algorithm_performance[operation_name] = self.algorithm_performance[operation_name][-100:]
    
    def _perform_adaptive_optimizations(self, metrics: PerformanceMetrics):
        """Perform adaptive optimizations based on current metrics."""
        
        # Adaptive cache strategy optimization
        if metrics.cache_hit_rate < 0.6:
            self.cache.optimize_strategy()
        
        # Memory optimization
        if metrics.memory_usage_mb > self.config.memory_limit_mb * 0.8:
            self._optimize_memory_usage()
        
        # Performance target adjustment
        if metrics.latency_p95_ms > self.config.performance_target_ms:
            self._adjust_performance_targets(metrics)
    
    def _optimize_memory_usage(self):
        """Optimize memory usage when approaching limits."""
        # Force garbage collection
        gc.collect()
        
        # Reduce cache size temporarily
        current_size = self.cache.max_size_bytes
        new_size = int(current_size * 0.8)
        self.cache.max_size_bytes = new_size
        
        # Trigger cache cleanup
        while self.cache.total_size > new_size and self.cache.cache:
            self.cache._evict_entry()
        
        self.logger.info(f"Reduced cache size from {current_size/1024/1024:.1f}MB to {new_size/1024/1024:.1f}MB")
    
    def _adjust_performance_targets(self, metrics: PerformanceMetrics):
        """Adjust performance targets based on current system performance."""
        # Increase target if consistently missing it
        if metrics.latency_p95_ms > self.config.performance_target_ms * 1.5:
            self.config.performance_target_ms *= 1.2
            self.logger.info(f"Adjusted performance target to {self.config.performance_target_ms:.0f}ms")
    
    def _calculate_cache_hit_rate(self) -> float:
        """Calculate current cache hit rate."""
        stats = self.cache.get_stats()
        return stats['hit_rate_percent'] / 100.0
    
    def _calculate_throughput(self) -> float:
        """Calculate current throughput."""
        if len(self.metrics_history) < 2:
            return 0.0
        
        recent_metrics = self.metrics_history[-10:]
        time_span = (recent_metrics[-1].timestamp - recent_metrics[0].timestamp).total_seconds()
        
        if time_span > 0:
            return len(recent_metrics) / time_span
        return 0.0
    
    def _calculate_p95_latency(self) -> float:
        """Calculate 95th percentile latency."""
        if not self.metrics_history:
            return 0.0
        
        recent_times = [m.execution_time_ms for m in self.metrics_history[-100:] if m.execution_time_ms > 0]
        if recent_times:
            return statistics.quantiles(recent_times, n=20)[18]  # 95th percentile
        return 0.0
    
    def _calculate_resource_efficiency(self) -> float:
        """Calculate resource efficiency score."""
        if not self.metrics_history:
            return 0.5
        
        recent_metrics = self.metrics_history[-10:]
        
        # Calculate average metrics
        avg_cpu = statistics.mean([m.cpu_utilization for m in recent_metrics])
        avg_memory = statistics.mean([m.memory_usage_mb for m in recent_metrics])
        avg_throughput = statistics.mean([m.throughput_ops_per_sec for m in recent_metrics])
        
        # Efficiency = throughput / (cpu_usage * memory_usage)
        resource_usage = (avg_cpu / 100.0) * (avg_memory / self.config.memory_limit_mb)
        if resource_usage > 0:
            return min(1.0, avg_throughput / resource_usage)
        return 0.5
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Get comprehensive performance report."""
        cache_stats = self.cache.get_stats()
        
        recent_metrics = self.metrics_history[-10:] if self.metrics_history else []
        
        avg_metrics = {}
        if recent_metrics:
            avg_metrics = {
                'avg_execution_time_ms': statistics.mean([m.execution_time_ms for m in recent_metrics if m.execution_time_ms > 0]),
                'avg_memory_usage_mb': statistics.mean([m.memory_usage_mb for m in recent_metrics]),
                'avg_cpu_utilization': statistics.mean([m.cpu_utilization for m in recent_metrics]),
                'avg_throughput': statistics.mean([m.throughput_ops_per_sec for m in recent_metrics]),
                'avg_resource_efficiency': statistics.mean([m.resource_efficiency for m in recent_metrics])
            }
        
        return {
            'config': {
                'cache_size_mb': self.config.cache_size_mb,
                'max_workers': self.config.max_workers,
                'performance_target_ms': self.config.performance_target_ms,
                'adaptive_optimization': self.config.adaptive_optimization
            },
            'cache_stats': cache_stats,
            'average_metrics': avg_metrics,
            'optimization_history': len(self.optimization_history),
            'active_optimizations': len(self.active_optimizations),
            'algorithm_performance': {
                name: {
                    'average_score': statistics.mean(scores) if scores else 0.0,
                    'measurements': len(scores)
                }
                for name, scores in self.algorithm_performance.items()
            },
            'monitoring_active': self._monitoring,
            'thread_pool_active': not self.thread_pool._shutdown,
            'process_pool_active': not self.process_pool._shutdown
        }
    
    def shutdown(self):
        """Shutdown performance optimizer."""
        self.stop_monitoring()
        self.thread_pool.shutdown(wait=True)
        self.process_pool.shutdown(wait=True)
        self.cache.clear()


# Global performance optimizer instance
global_performance_optimizer = PerformanceOptimizer()


# Decorators for easy optimization
def optimized(strategies: List[OptimizationStrategy] = None):
    """Decorator to optimize function performance."""
    def decorator(func):
        return global_performance_optimizer.optimize_function(func, strategies)
    return decorator


def cached(ttl_seconds: Optional[int] = None):
    """Decorator for function-level caching."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            cache_key = global_performance_optimizer._generate_cache_key(func, args, kwargs)
            
            # Try to get from cache
            result = global_performance_optimizer.cache.get(cache_key)
            if result is not None:
                return result
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            global_performance_optimizer.cache.set(cache_key, result, ttl_seconds)
            
            return result
        return wrapper
    return decorator


def memory_optimized(func):
    """Decorator for memory optimization."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Force garbage collection before execution
        gc.collect()
        
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            # Clean up after execution
            gc.collect()
    
    return wrapper


def batch_processed(batch_size: int = None):
    """Decorator for batch processing optimization."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Use configured batch size if not specified
            effective_batch_size = batch_size or global_performance_optimizer.config.batch_size
            
            # Check if first argument is a list/iterable that can be batched
            if args and hasattr(args[0], '__iter__') and not isinstance(args[0], (str, bytes)):
                items = list(args[0])
                
                if len(items) > effective_batch_size:
                    # Process in batches
                    results = []
                    for i in range(0, len(items), effective_batch_size):
                        batch = items[i:i + effective_batch_size]
                        batch_result = func(batch, *args[1:], **kwargs)
                        if isinstance(batch_result, list):
                            results.extend(batch_result)
                        else:
                            results.append(batch_result)
                    return results
            
            # Normal execution for small datasets or non-iterable inputs
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


# Initialize global optimizer
def initialize_performance_optimization():
    """Initialize global performance optimization."""
    global_performance_optimizer.start_monitoring()
    
    # Register shutdown handler
    import atexit
    atexit.register(global_performance_optimizer.shutdown)


# Auto-initialize if imported
initialize_performance_optimization()