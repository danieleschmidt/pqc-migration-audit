"""Performance optimization and caching for PQC Migration Audit."""

import time
import hashlib
import pickle
import threading
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import multiprocessing as mp
from functools import lru_cache, wraps
import psutil
import json
from datetime import datetime, timedelta

from .types import ScanResults, Vulnerability
from .exceptions import ResourceExhaustedException


@dataclass
class PerformanceMetrics:
    """Performance metrics for scan operations."""
    scan_start_time: float
    scan_end_time: float
    files_processed: int
    vulnerabilities_found: int
    cache_hits: int = 0
    cache_misses: int = 0
    memory_peak_mb: float = 0.0
    cpu_utilization: float = 0.0
    parallel_workers: int = 1
    
    @property
    def scan_duration(self) -> float:
        """Calculate scan duration in seconds."""
        return self.scan_end_time - self.scan_start_time
    
    @property
    def files_per_second(self) -> float:
        """Calculate processing rate."""
        if self.scan_duration > 0:
            return self.files_processed / self.scan_duration
        return 0.0
    
    @property
    def cache_hit_ratio(self) -> float:
        """Calculate cache hit ratio."""
        total_requests = self.cache_hits + self.cache_misses
        if total_requests > 0:
            return self.cache_hits / total_requests
        return 0.0


class ScanCache:
    """Intelligent caching system for scan results."""
    
    def __init__(self, cache_dir: Optional[Path] = None, max_cache_size_mb: int = 100):
        """Initialize scan cache.
        
        Args:
            cache_dir: Directory for cache storage
            max_cache_size_mb: Maximum cache size in MB
        """
        self.cache_dir = cache_dir or Path.home() / ".pqc_audit_cache"
        self.cache_dir.mkdir(exist_ok=True)
        self.max_cache_size = max_cache_size_mb * 1024 * 1024  # Convert to bytes
        self.memory_cache = {}
        self.cache_stats = {"hits": 0, "misses": 0}
        self._lock = threading.RLock()
    
    def _get_file_hash(self, file_path: Path) -> str:
        """Calculate hash for file caching."""
        try:
            stat = file_path.stat()
            # Hash based on path, size, and modification time
            content = f"{file_path}:{stat.st_size}:{stat.st_mtime}"
            return hashlib.sha256(content.encode()).hexdigest()[:16]
        except OSError:
            return hashlib.sha256(str(file_path).encode()).hexdigest()[:16]
    
    def get_file_scan_result(self, file_path: Path) -> Optional[List[Vulnerability]]:
        """Get cached scan result for file.
        
        Args:
            file_path: Path to file
            
        Returns:
            Cached vulnerabilities or None if not cached
        """
        with self._lock:
            file_hash = self._get_file_hash(file_path)
            
            # Check memory cache first
            if file_hash in self.memory_cache:
                self.cache_stats["hits"] += 1
                return self.memory_cache[file_hash]
            
            # Check disk cache
            cache_file = self.cache_dir / f"{file_hash}.cache"
            if cache_file.exists():
                try:
                    with open(cache_file, 'rb') as f:
                        vulnerabilities = pickle.load(f)
                    
                    # Load into memory cache for faster access
                    self.memory_cache[file_hash] = vulnerabilities
                    self.cache_stats["hits"] += 1
                    return vulnerabilities
                    
                except Exception:
                    # Remove corrupted cache file
                    cache_file.unlink(missing_ok=True)
            
            self.cache_stats["misses"] += 1
            return None
    
    def store_file_scan_result(self, file_path: Path, vulnerabilities: List[Vulnerability]):
        """Store scan result in cache.
        
        Args:
            file_path: Path to file
            vulnerabilities: List of vulnerabilities found
        """
        with self._lock:
            file_hash = self._get_file_hash(file_path)
            
            # Store in memory cache
            self.memory_cache[file_hash] = vulnerabilities
            
            # Store in disk cache
            cache_file = self.cache_dir / f"{file_hash}.cache"
            try:
                with open(cache_file, 'wb') as f:
                    pickle.dump(vulnerabilities, f)
                
                # Clean up cache if too large
                self._cleanup_cache_if_needed()
                
            except Exception:
                # If we can't write to disk, just keep in memory
                pass
    
    def _cleanup_cache_if_needed(self):
        """Clean up cache if it exceeds size limit."""
        total_size = sum(f.stat().st_size for f in self.cache_dir.glob("*.cache"))
        
        if total_size > self.max_cache_size:
            # Remove oldest cache files
            cache_files = [(f, f.stat().st_mtime) for f in self.cache_dir.glob("*.cache")]
            cache_files.sort(key=lambda x: x[1])  # Sort by modification time
            
            # Remove oldest files until under limit
            for cache_file, _ in cache_files:
                if total_size <= self.max_cache_size * 0.8:  # Keep 20% buffer
                    break
                
                file_size = cache_file.stat().st_size
                cache_file.unlink(missing_ok=True)
                total_size -= file_size
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            total_requests = self.cache_stats["hits"] + self.cache_stats["misses"]
            hit_ratio = self.cache_stats["hits"] / total_requests if total_requests > 0 else 0
            
            return {
                "hits": self.cache_stats["hits"],
                "misses": self.cache_stats["misses"], 
                "hit_ratio": hit_ratio,
                "memory_cache_size": len(self.memory_cache),
                "disk_cache_files": len(list(self.cache_dir.glob("*.cache")))
            }
    
    def clear(self):
        """Clear all caches."""
        with self._lock:
            self.memory_cache.clear()
            for cache_file in self.cache_dir.glob("*.cache"):
                cache_file.unlink(missing_ok=True)
            self.cache_stats = {"hits": 0, "misses": 0}


class ResourceMonitor:
    """Monitor system resources during scanning."""
    
    def __init__(self):
        """Initialize resource monitor."""
        self.process = psutil.Process()
        self.monitoring = False
        self.metrics = {
            "memory_peak_mb": 0.0,
            "cpu_samples": [],
            "start_time": None
        }
        self._monitor_thread = None
    
    def start_monitoring(self):
        """Start resource monitoring."""
        self.monitoring = True
        self.metrics["start_time"] = time.time()
        self.metrics["memory_peak_mb"] = 0.0
        self.metrics["cpu_samples"] = []
        
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
    
    def stop_monitoring(self) -> Dict[str, float]:
        """Stop monitoring and return metrics."""
        self.monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=1.0)
        
        # Calculate average CPU utilization
        cpu_avg = sum(self.metrics["cpu_samples"]) / len(self.metrics["cpu_samples"]) \
                 if self.metrics["cpu_samples"] else 0.0
        
        return {
            "memory_peak_mb": self.metrics["memory_peak_mb"],
            "cpu_utilization": cpu_avg,
            "monitoring_duration": time.time() - self.metrics["start_time"]
        }
    
    def _monitor_loop(self):
        """Resource monitoring loop."""
        while self.monitoring:
            try:
                # Monitor memory usage
                memory_mb = self.process.memory_info().rss / 1024 / 1024
                self.metrics["memory_peak_mb"] = max(self.metrics["memory_peak_mb"], memory_mb)
                
                # Monitor CPU usage
                cpu_percent = self.process.cpu_percent()
                self.metrics["cpu_samples"].append(cpu_percent)
                
                # Keep only recent samples (last 60 seconds)
                if len(self.metrics["cpu_samples"]) > 60:
                    self.metrics["cpu_samples"] = self.metrics["cpu_samples"][-60:]
                
                time.sleep(1.0)
                
            except Exception:
                # Continue monitoring even if we can't get metrics
                time.sleep(1.0)


class ParallelScanner:
    """Parallel scanning with optimal resource utilization."""
    
    def __init__(self, max_workers: Optional[int] = None, 
                 use_processes: bool = False,
                 chunk_size: int = 10):
        """Initialize parallel scanner.
        
        Args:
            max_workers: Maximum number of workers (auto-detect if None)
            use_processes: Use processes instead of threads
            chunk_size: Number of files per chunk for processing
        """
        self.max_workers = max_workers or self._get_optimal_worker_count()
        self.use_processes = use_processes
        self.chunk_size = chunk_size
        self.cache = ScanCache()
    
    def _get_optimal_worker_count(self) -> int:
        """Determine optimal worker count based on system resources."""
        cpu_count = mp.cpu_count()
        
        # For I/O-bound scanning, use more workers than CPU count
        # For CPU-bound processing, limit to CPU count
        if self.use_processes:
            return min(cpu_count, 8)  # Limit process count
        else:
            return min(cpu_count * 2, 16)  # More threads for I/O
    
    def scan_files_parallel(self, file_paths: List[Path], 
                           scan_function: Callable[[Path], List[Vulnerability]]) -> List[Vulnerability]:
        """Scan files in parallel with caching.
        
        Args:
            file_paths: List of file paths to scan
            scan_function: Function to scan individual files
            
        Returns:
            Combined list of vulnerabilities from all files
        """
        if not file_paths:
            return []
        
        all_vulnerabilities = []
        files_to_scan = []
        
        # Check cache first
        for file_path in file_paths:
            cached_result = self.cache.get_file_scan_result(file_path)
            if cached_result is not None:
                all_vulnerabilities.extend(cached_result)
            else:
                files_to_scan.append(file_path)
        
        if not files_to_scan:
            return all_vulnerabilities
        
        # Process uncached files in parallel
        executor_class = ProcessPoolExecutor if self.use_processes else ThreadPoolExecutor
        
        with executor_class(max_workers=self.max_workers) as executor:
            # Submit file chunks for processing
            future_to_files = {}
            
            for i in range(0, len(files_to_scan), self.chunk_size):
                chunk = files_to_scan[i:i + self.chunk_size]
                future = executor.submit(self._scan_file_chunk, chunk, scan_function)
                future_to_files[future] = chunk
            
            # Collect results
            for future in as_completed(future_to_files):
                try:
                    chunk_results = future.result()
                    for file_path, vulnerabilities in chunk_results:
                        # Cache the result
                        self.cache.store_file_scan_result(file_path, vulnerabilities)
                        all_vulnerabilities.extend(vulnerabilities)
                        
                except Exception as e:
                    # Log error but continue with other files
                    print(f"Warning: Error processing file chunk: {e}")
        
        return all_vulnerabilities
    
    def _scan_file_chunk(self, file_paths: List[Path], 
                        scan_function: Callable[[Path], List[Vulnerability]]) -> List[Tuple[Path, List[Vulnerability]]]:
        """Scan a chunk of files.
        
        Args:
            file_paths: List of file paths in chunk
            scan_function: Function to scan individual files
            
        Returns:
            List of (file_path, vulnerabilities) tuples
        """
        results = []
        for file_path in file_paths:
            try:
                vulnerabilities = scan_function(file_path)
                results.append((file_path, vulnerabilities))
            except Exception:
                # Return empty results for failed files
                results.append((file_path, []))
        return results
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get caching statistics."""
        return self.cache.get_stats()


class AdaptiveScanner:
    """Adaptive scanner that optimizes performance based on workload."""
    
    def __init__(self):
        """Initialize adaptive scanner."""
        self.performance_history = {}
        self.current_strategy = "balanced"
        self.monitor = ResourceMonitor()
        
    def scan_with_adaptive_optimization(self, file_paths: List[Path],
                                      scan_function: Callable[[Path], List[Vulnerability]]) -> Tuple[List[Vulnerability], PerformanceMetrics]:
        """Scan files with adaptive performance optimization.
        
        Args:
            file_paths: List of file paths to scan
            scan_function: Function to scan individual files
            
        Returns:
            Tuple of (vulnerabilities, performance_metrics)
        """
        start_time = time.time()
        self.monitor.start_monitoring()
        
        # Determine optimal strategy based on workload
        strategy = self._select_strategy(len(file_paths))
        
        # Configure scanner based on strategy
        if strategy == "fast":
            scanner = ParallelScanner(max_workers=16, use_processes=False, chunk_size=5)
        elif strategy == "memory_efficient":
            scanner = ParallelScanner(max_workers=4, use_processes=True, chunk_size=20)
        else:  # balanced
            scanner = ParallelScanner(max_workers=8, use_processes=False, chunk_size=10)
        
        # Perform scan
        vulnerabilities = scanner.scan_files_parallel(file_paths, scan_function)
        
        # Stop monitoring and collect metrics
        resource_metrics = self.monitor.stop_monitoring()
        cache_stats = scanner.get_cache_stats()
        
        end_time = time.time()
        
        # Create performance metrics
        metrics = PerformanceMetrics(
            scan_start_time=start_time,
            scan_end_time=end_time,
            files_processed=len(file_paths),
            vulnerabilities_found=len(vulnerabilities),
            cache_hits=cache_stats["hits"],
            cache_misses=cache_stats["misses"],
            memory_peak_mb=resource_metrics["memory_peak_mb"],
            cpu_utilization=resource_metrics["cpu_utilization"],
            parallel_workers=scanner.max_workers
        )
        
        # Store performance data for future optimization
        self._update_performance_history(strategy, metrics)
        
        return vulnerabilities, metrics
    
    def _select_strategy(self, file_count: int) -> str:
        """Select optimal scanning strategy based on workload.
        
        Args:
            file_count: Number of files to scan
            
        Returns:
            Strategy name: 'fast', 'memory_efficient', or 'balanced'
        """
        # Get system resources
        memory_gb = psutil.virtual_memory().total / (1024**3)
        cpu_count = mp.cpu_count()
        
        # Strategy selection logic
        if file_count < 50:
            return "fast"  # Small workload, prioritize speed
        elif file_count > 1000 or memory_gb < 4:
            return "memory_efficient"  # Large workload or limited memory
        else:
            return "balanced"  # Medium workload
    
    def _update_performance_history(self, strategy: str, metrics: PerformanceMetrics):
        """Update performance history for strategy optimization.
        
        Args:
            strategy: Strategy used
            metrics: Performance metrics achieved
        """
        if strategy not in self.performance_history:
            self.performance_history[strategy] = []
        
        # Keep only recent history (last 10 runs)
        self.performance_history[strategy].append({
            "files_per_second": metrics.files_per_second,
            "memory_peak_mb": metrics.memory_peak_mb,
            "cache_hit_ratio": metrics.cache_hit_ratio,
            "timestamp": datetime.now().isoformat()
        })
        
        if len(self.performance_history[strategy]) > 10:
            self.performance_history[strategy] = self.performance_history[strategy][-10:]
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Generate performance optimization report.
        
        Returns:
            Performance analysis and recommendations
        """
        report = {
            "current_strategy": self.current_strategy,
            "system_info": {
                "cpu_count": mp.cpu_count(),
                "memory_gb": round(psutil.virtual_memory().total / (1024**3), 1),
                "disk_io": "SSD" if self._is_ssd() else "HDD"
            },
            "strategy_performance": {}
        }
        
        # Analyze performance for each strategy
        for strategy, history in self.performance_history.items():
            if history:
                avg_fps = sum(h["files_per_second"] for h in history) / len(history)
                avg_memory = sum(h["memory_peak_mb"] for h in history) / len(history)
                avg_cache_ratio = sum(h["cache_hit_ratio"] for h in history) / len(history)
                
                report["strategy_performance"][strategy] = {
                    "avg_files_per_second": round(avg_fps, 2),
                    "avg_memory_mb": round(avg_memory, 1),
                    "avg_cache_hit_ratio": round(avg_cache_ratio, 3),
                    "sample_count": len(history)
                }
        
        # Generate recommendations
        report["recommendations"] = self._generate_recommendations(report)
        
        return report
    
    def _is_ssd(self) -> bool:
        """Detect if primary disk is SSD (simplified heuristic)."""
        try:
            # This is a simplified check - in production, you'd use more sophisticated detection
            import subprocess
            result = subprocess.run(['lsblk', '-d', '-o', 'name,rota'], 
                                  capture_output=True, text=True)
            return '0' in result.stdout  # 0 indicates SSD
        except Exception:
            return True  # Assume SSD if detection fails
    
    def _generate_recommendations(self, report: Dict[str, Any]) -> List[str]:
        """Generate performance optimization recommendations.
        
        Args:
            report: Performance report data
            
        Returns:
            List of optimization recommendations
        """
        recommendations = []
        
        system_info = report["system_info"]
        
        # Memory recommendations
        if system_info["memory_gb"] < 4:
            recommendations.append("Consider using process-based parallelism for better memory management")
        elif system_info["memory_gb"] > 8:
            recommendations.append("Increase cache size to improve performance on large codebases")
        
        # CPU recommendations
        if system_info["cpu_count"] > 8:
            recommendations.append("Increase max_workers to utilize all CPU cores effectively")
        
        # Storage recommendations
        if system_info["disk_io"] == "HDD":
            recommendations.append("Consider enabling more aggressive caching for HDD storage")
        
        # Performance-based recommendations
        strategy_perf = report["strategy_performance"]
        if strategy_perf:
            best_strategy = max(strategy_perf.keys(), 
                              key=lambda k: strategy_perf[k]["avg_files_per_second"])
            recommendations.append(f"'{best_strategy}' strategy shows best performance for your workload")
        
        return recommendations


@lru_cache(maxsize=1000)
def cached_file_hash(file_path: str, file_size: int, mtime: float) -> str:
    """Cached function to compute file hashes for change detection."""
    return hashlib.sha256(f"{file_path}:{file_size}:{mtime}".encode()).hexdigest()


def performance_timer(func):
    """Decorator to measure function execution time."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        
        # Store timing information
        if not hasattr(wrapper, 'timing_history'):
            wrapper.timing_history = []
        
        wrapper.timing_history.append(end_time - start_time)
        
        # Keep only recent timing data
        if len(wrapper.timing_history) > 100:
            wrapper.timing_history = wrapper.timing_history[-100:]
        
        return result
    
    return wrapper


class BatchProcessor:
    """Efficient batch processing for large-scale operations."""
    
    def __init__(self, batch_size: int = 100, max_memory_mb: int = 500):
        """Initialize batch processor.
        
        Args:
            batch_size: Number of items per batch
            max_memory_mb: Maximum memory usage before forcing batch processing
        """
        self.batch_size = batch_size
        self.max_memory_mb = max_memory_mb
        self.process = psutil.Process()
    
    def process_in_batches(self, items: List[Any], 
                          process_func: Callable[[List[Any]], Any]) -> List[Any]:
        """Process items in memory-efficient batches.
        
        Args:
            items: List of items to process
            process_func: Function to process each batch
            
        Returns:
            Combined results from all batches
        """
        results = []
        
        for i in range(0, len(items), self.batch_size):
            batch = items[i:i + self.batch_size]
            
            # Check memory usage
            memory_mb = self.process.memory_info().rss / 1024 / 1024
            if memory_mb > self.max_memory_mb:
                # Force garbage collection
                import gc
                gc.collect()
                
                # If still over limit, reduce batch size
                if memory_mb > self.max_memory_mb:
                    self.batch_size = max(10, self.batch_size // 2)
            
            # Process batch
            batch_result = process_func(batch)
            if isinstance(batch_result, list):
                results.extend(batch_result)
            else:
                results.append(batch_result)
        
        return results