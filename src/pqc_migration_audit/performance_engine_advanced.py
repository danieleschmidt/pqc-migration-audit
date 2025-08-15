"""Advanced performance optimization engine for PQC Migration Audit."""

import time
import threading
import multiprocessing
import concurrent.futures
import psutil
import hashlib
import pickle
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import logging
import json
from contextlib import contextmanager
import weakref
import gc

from .logging_config import get_logger


class CacheStrategy(Enum):
    """Cache strategy options."""
    LRU = "lru"
    LFU = "lfu"
    TTL = "ttl"
    ADAPTIVE = "adaptive"


class ProcessingMode(Enum):
    """Processing mode options."""
    SEQUENTIAL = "sequential"
    THREADED = "threaded"
    MULTIPROCESS = "multiprocess"
    ADAPTIVE = "adaptive"


@dataclass
class PerformanceMetrics:
    """Performance metrics tracking."""
    scan_duration: float = 0.0
    files_per_second: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    cache_hit_rate: float = 0.0
    concurrent_workers: int = 1
    optimization_level: str = "basic"
    bottlenecks: List[str] = field(default_factory=list)


@dataclass
class CacheEntry:
    """Cache entry with metadata."""
    value: Any
    timestamp: float
    access_count: int = 0
    last_access: float = field(default_factory=time.time)
    size_bytes: int = 0


class AdaptiveCache:
    """High-performance adaptive cache with multiple strategies."""
    
    def __init__(self, max_size: int = 10000, strategy: CacheStrategy = CacheStrategy.ADAPTIVE):
        """Initialize adaptive cache.
        
        Args:
            max_size: Maximum number of cache entries
            strategy: Cache eviction strategy
        """
        self.max_size = max_size
        self.strategy = strategy
        self.cache: Dict[str, CacheEntry] = {}
        self.access_order: List[str] = []
        self.frequency_map: Dict[str, int] = {}
        self.total_size_bytes = 0
        self.hits = 0
        self.misses = 0
        self._lock = threading.RLock()
        
        # TTL settings
        self.default_ttl = 3600  # 1 hour
        
        # Adaptive settings
        self.adaptive_threshold = 0.7  # Switch strategies at 70% hit rate
        self.current_strategy = CacheStrategy.LRU
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found
        """
        with self._lock:
            if key in self.cache:
                entry = self.cache[key]
                
                # Check TTL if using TTL strategy
                if self.strategy == CacheStrategy.TTL:
                    if time.time() - entry.timestamp > self.default_ttl:
                        self._remove_entry(key)
                        self.misses += 1
                        return None
                
                # Update access metadata
                entry.access_count += 1
                entry.last_access = time.time()
                self.frequency_map[key] = self.frequency_map.get(key, 0) + 1
                
                # Update LRU order
                if key in self.access_order:
                    self.access_order.remove(key)
                self.access_order.append(key)
                
                self.hits += 1
                return entry.value
            else:
                self.misses += 1
                return None
    
    def put(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """Put value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live (for TTL strategy)
        """
        with self._lock:
            # Calculate size estimate
            try:
                size_bytes = len(pickle.dumps(value))
            except:
                size_bytes = 1024  # Fallback estimate
            
            # Remove existing entry if present
            if key in self.cache:
                self._remove_entry(key)
            
            # Evict if necessary
            while len(self.cache) >= self.max_size:
                self._evict_one()
            
            # Create new entry
            entry = CacheEntry(
                value=value,
                timestamp=time.time(),
                size_bytes=size_bytes
            )
            
            self.cache[key] = entry
            self.access_order.append(key)
            self.frequency_map[key] = 1
            self.total_size_bytes += size_bytes
            
            # Adaptive strategy adjustment
            if self.strategy == CacheStrategy.ADAPTIVE:
                self._adjust_strategy()
    
    def _remove_entry(self, key: str) -> None:
        """Remove entry from cache.
        
        Args:
            key: Cache key to remove
        """
        if key in self.cache:
            entry = self.cache[key]
            del self.cache[key]
            self.total_size_bytes -= entry.size_bytes
            
            if key in self.access_order:
                self.access_order.remove(key)
            
            if key in self.frequency_map:
                del self.frequency_map[key]
    
    def _evict_one(self) -> None:
        """Evict one entry based on current strategy."""
        if not self.cache:
            return
        
        if self.current_strategy == CacheStrategy.LRU:
            # Remove least recently used
            key_to_remove = self.access_order[0]
        elif self.current_strategy == CacheStrategy.LFU:
            # Remove least frequently used
            key_to_remove = min(self.frequency_map.keys(), key=lambda k: self.frequency_map[k])
        elif self.current_strategy == CacheStrategy.TTL:
            # Remove oldest
            key_to_remove = min(self.cache.keys(), key=lambda k: self.cache[k].timestamp)
        else:
            # Default to LRU
            key_to_remove = self.access_order[0]
        
        self._remove_entry(key_to_remove)
    
    def _adjust_strategy(self) -> None:
        """Adjust caching strategy based on performance."""
        if self.hits + self.misses < 100:  # Need enough data
            return
        
        hit_rate = self.hits / (self.hits + self.misses)
        
        if hit_rate < self.adaptive_threshold:
            # Switch strategy to improve performance
            if self.current_strategy == CacheStrategy.LRU:
                self.current_strategy = CacheStrategy.LFU
            elif self.current_strategy == CacheStrategy.LFU:
                self.current_strategy = CacheStrategy.TTL
            else:
                self.current_strategy = CacheStrategy.LRU
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics.
        
        Returns:
            Cache statistics
        """
        total_requests = self.hits + self.misses
        hit_rate = (self.hits / total_requests) if total_requests > 0 else 0
        
        return {
            'hits': self.hits,
            'misses': self.misses,
            'hit_rate': round(hit_rate, 3),
            'size': len(self.cache),
            'max_size': self.max_size,
            'total_size_mb': round(self.total_size_bytes / 1024 / 1024, 2),
            'strategy': self.current_strategy.value,
            'utilization': round(len(self.cache) / self.max_size, 3)
        }
    
    def clear(self) -> None:
        """Clear cache."""
        with self._lock:
            self.cache.clear()
            self.access_order.clear()
            self.frequency_map.clear()
            self.total_size_bytes = 0
            self.hits = 0
            self.misses = 0


class ResourceMonitor:
    """Real-time resource monitoring and optimization."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize resource monitor.
        
        Args:
            config: Monitor configuration
        """
        self.config = config or {}
        self.logger = get_logger('pqc_audit.performance')
        
        # Monitoring settings
        self.monitor_interval = self.config.get('monitor_interval', 1.0)
        self.memory_threshold = self.config.get('memory_threshold_mb', 1000)
        self.cpu_threshold = self.config.get('cpu_threshold_percent', 80)
        
        # State
        self.monitoring = False
        self.monitor_thread = None
        self.metrics_history: List[Dict[str, Any]] = []
        self.optimization_actions: List[str] = []
        
    def start_monitoring(self) -> None:
        """Start resource monitoring."""
        if not self.monitoring:
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
    
    def stop_monitoring(self) -> None:
        """Stop resource monitoring."""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2.0)
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while self.monitoring:
            try:
                metrics = self._collect_metrics()
                self.metrics_history.append(metrics)
                
                # Limit history size
                if len(self.metrics_history) > 1000:
                    self.metrics_history = self.metrics_history[-500:]
                
                # Check for optimization opportunities
                self._check_optimization_triggers(metrics)
                
                time.sleep(self.monitor_interval)
                
            except Exception as e:
                self.logger.log_error(e, {'context': 'resource_monitoring'})
                time.sleep(self.monitor_interval)
    
    def _collect_metrics(self) -> Dict[str, Any]:
        """Collect current system metrics.
        
        Returns:
            Current metrics
        """
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            
            metrics = {
                'timestamp': time.time(),
                'memory_mb': round(memory_info.rss / 1024 / 1024, 2),
                'memory_percent': round(process.memory_percent(), 2),
                'cpu_percent': round(process.cpu_percent(), 2),
                'num_threads': process.num_threads(),
                'open_files': len(process.open_files()),
                'system_memory_percent': round(psutil.virtual_memory().percent, 2),
                'system_cpu_percent': round(psutil.cpu_percent(), 2)
            }
            
            return metrics
            
        except Exception as e:
            self.logger.log_error(e, {'context': 'metrics_collection'})
            return {'timestamp': time.time(), 'error': str(e)}
    
    def _check_optimization_triggers(self, metrics: Dict[str, Any]) -> None:
        """Check if optimization is needed.
        
        Args:
            metrics: Current metrics
        """
        memory_mb = metrics.get('memory_mb', 0)
        cpu_percent = metrics.get('cpu_percent', 0)
        
        # Memory optimization
        if memory_mb > self.memory_threshold:
            action = f"High memory usage: {memory_mb}MB > {self.memory_threshold}MB"
            if action not in self.optimization_actions:
                self.optimization_actions.append(action)
                self._trigger_memory_optimization()
        
        # CPU optimization
        if cpu_percent > self.cpu_threshold:
            action = f"High CPU usage: {cpu_percent}% > {self.cpu_threshold}%"
            if action not in self.optimization_actions:
                self.optimization_actions.append(action)
                self._trigger_cpu_optimization()
    
    def _trigger_memory_optimization(self) -> None:
        """Trigger memory optimization."""
        try:
            # Force garbage collection
            gc.collect()
            
            # Log optimization action
            self.logger.log_performance_metric('memory_optimization_triggered', 1, 'count')
            
        except Exception as e:
            self.logger.log_error(e, {'context': 'memory_optimization'})
    
    def _trigger_cpu_optimization(self) -> None:
        """Trigger CPU optimization."""
        try:
            # Log optimization action
            self.logger.log_performance_metric('cpu_optimization_triggered', 1, 'count')
            
        except Exception as e:
            self.logger.log_error(e, {'context': 'cpu_optimization'})
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """Get current resource metrics.
        
        Returns:
            Current metrics
        """
        return self._collect_metrics()
    
    def get_optimization_report(self) -> Dict[str, Any]:
        """Get optimization report.
        
        Returns:
            Optimization report
        """
        if not self.metrics_history:
            return {'status': 'no_data'}
        
        recent_metrics = self.metrics_history[-10:]  # Last 10 samples
        
        avg_memory = sum(m.get('memory_mb', 0) for m in recent_metrics) / len(recent_metrics)
        avg_cpu = sum(m.get('cpu_percent', 0) for m in recent_metrics) / len(recent_metrics)
        
        return {
            'average_memory_mb': round(avg_memory, 2),
            'average_cpu_percent': round(avg_cpu, 2),
            'memory_threshold_mb': self.memory_threshold,
            'cpu_threshold_percent': self.cpu_threshold,
            'optimization_actions': self.optimization_actions,
            'samples_collected': len(self.metrics_history),
            'monitoring_active': self.monitoring
        }


class ConcurrentProcessor:
    """High-performance concurrent processing engine."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize concurrent processor.
        
        Args:
            config: Processor configuration
        """
        self.config = config or {}
        self.logger = get_logger('pqc_audit.performance')
        
        # Processing configuration
        self.mode = ProcessingMode(self.config.get('mode', 'adaptive'))
        self.max_workers = self.config.get('max_workers', self._calculate_optimal_workers())
        self.chunk_size = self.config.get('chunk_size', 100)
        self.enable_load_balancing = self.config.get('enable_load_balancing', True)
        
        # State
        self.active_workers = 0
        self.processed_items = 0
        self.processing_times: List[float] = []
    
    def _calculate_optimal_workers(self) -> int:
        """Calculate optimal number of workers.
        
        Returns:
            Optimal worker count
        """
        cpu_count = multiprocessing.cpu_count()
        
        # For I/O bound tasks (file scanning), use more workers
        return min(cpu_count * 2, 16)  # Cap at 16 to avoid overhead
    
    def process_files_concurrent(self, files: List[Path], 
                                processor_func: Callable, 
                                *args, **kwargs) -> List[Any]:
        """Process files concurrently.
        
        Args:
            files: List of files to process
            processor_func: Function to process each file
            *args: Additional arguments for processor function
            **kwargs: Additional keyword arguments
            
        Returns:
            List of processing results
        """
        if not files:
            return []
        
        # Determine processing mode
        mode = self._select_processing_mode(len(files))
        
        if mode == ProcessingMode.SEQUENTIAL:
            return self._process_sequential(files, processor_func, *args, **kwargs)
        elif mode == ProcessingMode.THREADED:
            return self._process_threaded(files, processor_func, *args, **kwargs)
        elif mode == ProcessingMode.MULTIPROCESS:
            return self._process_multiprocess(files, processor_func, *args, **kwargs)
        else:
            # Default to threaded
            return self._process_threaded(files, processor_func, *args, **kwargs)
    
    def _select_processing_mode(self, file_count: int) -> ProcessingMode:
        """Select optimal processing mode.
        
        Args:
            file_count: Number of files to process
            
        Returns:
            Selected processing mode
        """
        if self.mode != ProcessingMode.ADAPTIVE:
            return self.mode
        
        # Adaptive mode selection
        if file_count < 10:
            return ProcessingMode.SEQUENTIAL
        elif file_count < 100:
            return ProcessingMode.THREADED
        else:
            return ProcessingMode.MULTIPROCESS
    
    def _process_sequential(self, files: List[Path], 
                           processor_func: Callable, 
                           *args, **kwargs) -> List[Any]:
        """Process files sequentially.
        
        Args:
            files: Files to process
            processor_func: Processing function
            *args, **kwargs: Additional arguments
            
        Returns:
            Processing results
        """
        results = []
        start_time = time.time()
        
        for file_path in files:
            try:
                result = processor_func(file_path, *args, **kwargs)
                results.append(result)
                self.processed_items += 1
            except Exception as e:
                self.logger.log_error(e, {'context': 'sequential_processing', 'file': str(file_path)})
                results.append(None)
        
        duration = time.time() - start_time
        self.processing_times.append(duration)
        
        return results
    
    def _process_threaded(self, files: List[Path], 
                         processor_func: Callable, 
                         *args, **kwargs) -> List[Any]:
        """Process files using thread pool.
        
        Args:
            files: Files to process
            processor_func: Processing function
            *args, **kwargs: Additional arguments
            
        Returns:
            Processing results
        """
        results = [None] * len(files)
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_index = {
                executor.submit(processor_func, file_path, *args, **kwargs): i
                for i, file_path in enumerate(files)
            }
            
            # Collect results
            for future in concurrent.futures.as_completed(future_to_index):
                index = future_to_index[future]
                try:
                    result = future.result()
                    results[index] = result
                    self.processed_items += 1
                except Exception as e:
                    self.logger.log_error(e, {
                        'context': 'threaded_processing', 
                        'file': str(files[index])
                    })
                    results[index] = None
        
        duration = time.time() - start_time
        self.processing_times.append(duration)
        
        return results
    
    def _process_multiprocess(self, files: List[Path], 
                             processor_func: Callable, 
                             *args, **kwargs) -> List[Any]:
        """Process files using process pool.
        
        Args:
            files: Files to process
            processor_func: Processing function
            *args, **kwargs: Additional arguments
            
        Returns:
            Processing results
        """
        results = []
        start_time = time.time()
        
        # Create chunks for better load balancing
        file_chunks = [files[i:i + self.chunk_size] for i in range(0, len(files), self.chunk_size)]
        
        with concurrent.futures.ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            # Process chunks
            chunk_futures = []
            for chunk in file_chunks:
                future = executor.submit(self._process_chunk, chunk, processor_func, *args, **kwargs)
                chunk_futures.append(future)
            
            # Collect results
            for future in concurrent.futures.as_completed(chunk_futures):
                try:
                    chunk_results = future.result()
                    results.extend(chunk_results)
                    self.processed_items += len(chunk_results)
                except Exception as e:
                    self.logger.log_error(e, {'context': 'multiprocess_processing'})
                    results.extend([None] * self.chunk_size)
        
        duration = time.time() - start_time
        self.processing_times.append(duration)
        
        return results
    
    @staticmethod
    def _process_chunk(files: List[Path], processor_func: Callable, *args, **kwargs) -> List[Any]:
        """Process a chunk of files (for multiprocessing).
        
        Args:
            files: Files to process
            processor_func: Processing function
            *args, **kwargs: Additional arguments
            
        Returns:
            Chunk processing results
        """
        results = []
        for file_path in files:
            try:
                result = processor_func(file_path, *args, **kwargs)
                results.append(result)
            except Exception:
                results.append(None)
        return results
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get processing performance statistics.
        
        Returns:
            Performance statistics
        """
        if not self.processing_times:
            return {'status': 'no_data'}
        
        avg_time = sum(self.processing_times) / len(self.processing_times)
        files_per_second = self.processed_items / sum(self.processing_times) if self.processing_times else 0
        
        return {
            'total_processed': self.processed_items,
            'average_time_seconds': round(avg_time, 3),
            'files_per_second': round(files_per_second, 2),
            'max_workers': self.max_workers,
            'processing_mode': self.mode.value,
            'chunk_size': self.chunk_size,
            'batches_processed': len(self.processing_times)
        }


class PerformanceOptimizer:
    """Main performance optimization engine."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize performance optimizer.
        
        Args:
            config: Optimizer configuration
        """
        self.config = config or {}
        self.logger = get_logger('pqc_audit.performance')
        
        # Initialize components
        cache_config = self.config.get('cache', {})
        self.cache = AdaptiveCache(
            max_size=cache_config.get('max_size', 10000),
            strategy=CacheStrategy(cache_config.get('strategy', 'adaptive'))
        )
        
        monitor_config = self.config.get('monitor', {})
        self.resource_monitor = ResourceMonitor(monitor_config)
        
        processor_config = self.config.get('processor', {})
        self.concurrent_processor = ConcurrentProcessor(processor_config)
        
        # Start monitoring
        if self.config.get('enable_monitoring', True):
            self.resource_monitor.start_monitoring()
    
    @contextmanager
    def optimized_scan_context(self, scan_path: str):
        """Context manager for optimized scanning.
        
        Args:
            scan_path: Path being scanned
        """
        start_time = time.time()
        initial_metrics = self.resource_monitor.get_current_metrics()
        
        try:
            yield self
            
            # Log performance metrics
            duration = time.time() - start_time
            final_metrics = self.resource_monitor.get_current_metrics()
            
            self.logger.log_performance_metric('scan_duration', duration, 'seconds')
            self.logger.log_performance_metric(
                'memory_delta', 
                final_metrics.get('memory_mb', 0) - initial_metrics.get('memory_mb', 0),
                'MB'
            )
            
        except Exception as e:
            self.logger.log_error(e, {'context': 'optimized_scan'})
            raise
    
    def process_files_optimized(self, files: List[Path], 
                               processor_func: Callable,
                               use_cache: bool = True,
                               *args, **kwargs) -> List[Any]:
        """Process files with full optimization.
        
        Args:
            files: Files to process
            processor_func: Processing function
            use_cache: Whether to use caching
            *args, **kwargs: Additional arguments
            
        Returns:
            Processing results
        """
        if use_cache:
            return self._process_with_cache(files, processor_func, *args, **kwargs)
        else:
            return self.concurrent_processor.process_files_concurrent(
                files, processor_func, *args, **kwargs
            )
    
    def _process_with_cache(self, files: List[Path], 
                           processor_func: Callable,
                           *args, **kwargs) -> List[Any]:
        """Process files with caching enabled.
        
        Args:
            files: Files to process
            processor_func: Processing function
            *args, **kwargs: Additional arguments
            
        Returns:
            Processing results
        """
        results = []
        uncached_files = []
        uncached_indices = []
        
        # Check cache first
        for i, file_path in enumerate(files):
            cache_key = self._generate_cache_key(file_path, *args, **kwargs)
            cached_result = self.cache.get(cache_key)
            
            if cached_result is not None:
                results.append(cached_result)
            else:
                results.append(None)  # Placeholder
                uncached_files.append(file_path)
                uncached_indices.append(i)
        
        # Process uncached files
        if uncached_files:
            uncached_results = self.concurrent_processor.process_files_concurrent(
                uncached_files, processor_func, *args, **kwargs
            )
            
            # Store results in cache and update final results
            for i, (file_path, result) in enumerate(zip(uncached_files, uncached_results)):
                if result is not None:
                    cache_key = self._generate_cache_key(file_path, *args, **kwargs)
                    self.cache.put(cache_key, result)
                
                # Update final results
                results[uncached_indices[i]] = result
        
        return results
    
    def _generate_cache_key(self, file_path: Path, *args, **kwargs) -> str:
        """Generate cache key for file processing.
        
        Args:
            file_path: File path
            *args, **kwargs: Additional arguments
            
        Returns:
            Cache key
        """
        try:
            # Include file modification time and size in key
            stat = file_path.stat()
            key_data = {
                'path': str(file_path),
                'mtime': stat.st_mtime,
                'size': stat.st_size,
                'args': args,
                'kwargs': sorted(kwargs.items())
            }
            
            key_str = json.dumps(key_data, sort_keys=True)
            return hashlib.sha256(key_str.encode()).hexdigest()[:16]
            
        except Exception:
            # Fallback to simple path-based key
            return hashlib.sha256(str(file_path).encode()).hexdigest()[:16]
    
    def get_comprehensive_metrics(self) -> PerformanceMetrics:
        """Get comprehensive performance metrics.
        
        Returns:
            Performance metrics
        """
        cache_stats = self.cache.get_stats()
        processor_stats = self.concurrent_processor.get_performance_stats()
        resource_stats = self.resource_monitor.get_current_metrics()
        
        return PerformanceMetrics(
            scan_duration=processor_stats.get('average_time_seconds', 0),
            files_per_second=processor_stats.get('files_per_second', 0),
            memory_usage_mb=resource_stats.get('memory_mb', 0),
            cpu_usage_percent=resource_stats.get('cpu_percent', 0),
            cache_hit_rate=cache_stats.get('hit_rate', 0),
            concurrent_workers=processor_stats.get('max_workers', 1),
            optimization_level="advanced"
        )
    
    def cleanup(self) -> None:
        """Cleanup optimizer resources."""
        self.resource_monitor.stop_monitoring()
        self.cache.clear()