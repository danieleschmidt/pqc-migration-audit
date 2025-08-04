"""Simplified performance optimization without external dependencies."""

import time
import hashlib
import threading
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import multiprocessing as mp
from functools import lru_cache, wraps
import json
from datetime import datetime, timedelta

from .types import ScanResults, Vulnerability


@dataclass
class PerformanceMetrics:
    """Performance metrics for scan operations."""
    scan_start_time: float
    scan_end_time: float
    files_processed: int
    vulnerabilities_found: int
    cache_hits: int = 0
    cache_misses: int = 0
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


class SimpleScanCache:
    """Simplified caching system for scan results."""
    
    def __init__(self, max_memory_entries: int = 1000):
        """Initialize scan cache.
        
        Args:
            max_memory_entries: Maximum entries in memory cache
        """
        self.max_memory_entries = max_memory_entries
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
            
            if file_hash in self.memory_cache:
                self.cache_stats["hits"] += 1
                return self.memory_cache[file_hash]
            
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
            
            # Simple LRU eviction
            if len(self.memory_cache) >= self.max_memory_entries:
                # Remove oldest entry (simplified)
                oldest_key = next(iter(self.memory_cache))
                del self.memory_cache[oldest_key]
            
            self.memory_cache[file_hash] = vulnerabilities
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            total_requests = self.cache_stats["hits"] + self.cache_stats["misses"]
            hit_ratio = self.cache_stats["hits"] / total_requests if total_requests > 0 else 0
            
            return {
                "hits": self.cache_stats["hits"],
                "misses": self.cache_stats["misses"], 
                "hit_ratio": hit_ratio,
                "memory_cache_size": len(self.memory_cache)
            }
    
    def clear(self):
        """Clear all caches."""
        with self._lock:
            self.memory_cache.clear()
            self.cache_stats = {"hits": 0, "misses": 0}


class SimpleParallelScanner:
    """Simplified parallel scanning."""
    
    def __init__(self, max_workers: Optional[int] = None, chunk_size: int = 10):
        """Initialize parallel scanner.
        
        Args:
            max_workers: Maximum number of workers (auto-detect if None)
            chunk_size: Number of files per chunk for processing
        """
        self.max_workers = max_workers or min(mp.cpu_count(), 8)
        self.chunk_size = chunk_size
        self.cache = SimpleScanCache()
    
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
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit individual files for processing
            future_to_file = {
                executor.submit(scan_function, file_path): file_path 
                for file_path in files_to_scan
            }
            
            # Collect results
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    vulnerabilities = future.result()
                    # Cache the result
                    self.cache.store_file_scan_result(file_path, vulnerabilities)
                    all_vulnerabilities.extend(vulnerabilities)
                        
                except Exception as e:
                    # Log error but continue with other files
                    print(f"Warning: Error processing file {file_path}: {e}")
        
        return all_vulnerabilities
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get caching statistics."""
        return self.cache.get_stats()


class SimpleAdaptiveScanner:
    """Simplified adaptive scanner."""
    
    def __init__(self):
        """Initialize adaptive scanner."""
        self.performance_history = {}
        self.current_strategy = "balanced"
        
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
        
        # Determine optimal strategy based on workload
        strategy = self._select_strategy(len(file_paths))
        
        # Configure scanner based on strategy
        if strategy == "fast":
            scanner = SimpleParallelScanner(max_workers=8, chunk_size=5)
        elif strategy == "memory_efficient":
            scanner = SimpleParallelScanner(max_workers=2, chunk_size=20)
        else:  # balanced
            scanner = SimpleParallelScanner(max_workers=4, chunk_size=10)
        
        # Perform scan
        vulnerabilities = scanner.scan_files_parallel(file_paths, scan_function)
        
        end_time = time.time()
        cache_stats = scanner.get_cache_stats()
        
        # Create performance metrics
        metrics = PerformanceMetrics(
            scan_start_time=start_time,
            scan_end_time=end_time,
            files_processed=len(file_paths),
            vulnerabilities_found=len(vulnerabilities),
            cache_hits=cache_stats["hits"],
            cache_misses=cache_stats["misses"],
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
        # Simple strategy selection logic
        if file_count < 20:
            return "fast"  # Small workload, prioritize speed
        elif file_count > 100:
            return "memory_efficient"  # Large workload
        else:
            return "balanced"  # Medium workload
    
    def _update_performance_history(self, strategy: str, metrics: PerformanceMetrics):
        """Update performance history for strategy optimization."""
        if strategy not in self.performance_history:
            self.performance_history[strategy] = []
        
        # Keep only recent history (last 5 runs)
        self.performance_history[strategy].append({
            "files_per_second": metrics.files_per_second,
            "cache_hit_ratio": metrics.cache_hit_ratio,
            "timestamp": datetime.now().isoformat()
        })
        
        if len(self.performance_history[strategy]) > 5:
            self.performance_history[strategy] = self.performance_history[strategy][-5:]
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Generate performance optimization report."""
        report = {
            "current_strategy": self.current_strategy,
            "system_info": {
                "cpu_count": mp.cpu_count(),
                "memory_estimate": "Unknown (simplified mode)"
            },
            "strategy_performance": {}
        }
        
        # Analyze performance for each strategy
        for strategy, history in self.performance_history.items():
            if history:
                avg_fps = sum(h["files_per_second"] for h in history) / len(history)
                avg_cache_ratio = sum(h["cache_hit_ratio"] for h in history) / len(history)
                
                report["strategy_performance"][strategy] = {
                    "avg_files_per_second": round(avg_fps, 2),
                    "avg_cache_hit_ratio": round(avg_cache_ratio, 3),
                    "sample_count": len(history)
                }
        
        # Generate simple recommendations
        report["recommendations"] = self._generate_simple_recommendations(report)
        
        return report
    
    def _generate_simple_recommendations(self, report: Dict[str, Any]) -> List[str]:
        """Generate simple performance optimization recommendations."""
        recommendations = []
        
        cpu_count = report["system_info"]["cpu_count"]
        
        if cpu_count > 4:
            recommendations.append("Consider increasing max_workers for better CPU utilization")
        
        strategy_perf = report["strategy_performance"]
        if strategy_perf:
            best_strategy = max(strategy_perf.keys(), 
                              key=lambda k: strategy_perf[k]["avg_files_per_second"])
            recommendations.append(f"'{best_strategy}' strategy shows best performance for your workload")
        
        recommendations.append("Enable caching for repeated scans of the same codebase")
        
        return recommendations


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
        if len(wrapper.timing_history) > 50:
            wrapper.timing_history = wrapper.timing_history[-50:]
        
        return result
    
    return wrapper


@lru_cache(maxsize=1000)
def cached_file_hash(file_path: str, file_size: int, mtime: float) -> str:
    """Cached function to compute file hashes for change detection."""
    return hashlib.sha256(f"{file_path}:{file_size}:{mtime}".encode()).hexdigest()


class SimpleBatchProcessor:
    """Simplified batch processing for large-scale operations."""
    
    def __init__(self, batch_size: int = 100):
        """Initialize batch processor.
        
        Args:
            batch_size: Number of items per batch
        """
        self.batch_size = batch_size
    
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
            
            # Process batch
            batch_result = process_func(batch)
            if isinstance(batch_result, list):
                results.extend(batch_result)
            else:
                results.append(batch_result)
        
        return results