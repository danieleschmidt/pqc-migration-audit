"""Performance optimization and scaling for PQC Migration Audit."""

import asyncio
import concurrent.futures
import multiprocessing
import threading
import queue
import time
import gc
from typing import List, Dict, Any, Optional, Callable, Iterator, Tuple
from pathlib import Path
from dataclasses import dataclass, field
import logging
import cachetools
import functools
import weakref
from contextlib import contextmanager
import psutil
import mmap

from .types import ScanResults, Vulnerability
from .exceptions import ResourceExhaustedException, PerformanceException


@dataclass
class PerformanceConfig:
    """Configuration for performance optimization."""
    max_workers: int = multiprocessing.cpu_count()
    chunk_size: int = 100
    cache_size: int = 1000
    cache_ttl: int = 3600  # 1 hour
    memory_limit_mb: int = 2048
    enable_memory_mapping: bool = True
    enable_async_io: bool = True
    batch_size: int = 50
    prefetch_size: int = 10


class MemoryOptimizer:
    """Optimizes memory usage during scanning."""
    
    def __init__(self, memory_limit_mb: int = 2048):
        self.memory_limit = memory_limit_mb * 1024 * 1024  # Convert to bytes
        self.logger = logging.getLogger(__name__)
        self._monitoring = False
        self._monitor_thread = None
    
    def start_monitoring(self):
        """Start memory monitoring."""
        if not self._monitoring:
            self._monitoring = True
            self._monitor_thread = threading.Thread(target=self._monitor_memory, daemon=True)
            self._monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop memory monitoring."""
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=1)
    
    def _monitor_memory(self):
        """Monitor memory usage and trigger GC when needed."""
        while self._monitoring:
            try:
                process = psutil.Process()
                memory_usage = process.memory_info().rss
                
                if memory_usage > self.memory_limit:
                    self.logger.warning(f"Memory usage high: {memory_usage/1024/1024:.1f}MB")
                    gc.collect()
                    
                    # If still high after GC, raise exception
                    memory_usage = process.memory_info().rss
                    if memory_usage > self.memory_limit:
                        raise ResourceExhaustedException(
                            "memory", self.memory_limit, memory_usage
                        )
                
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                if self._monitoring:  # Only log if still monitoring
                    self.logger.error(f"Memory monitoring error: {e}")
                break
    
    @contextmanager
    def memory_context(self):
        """Context manager for memory-optimized operations."""
        self.start_monitoring()
        try:
            yield
        finally:
            self.stop_monitoring()
            gc.collect()


class CacheManager:
    """Manages intelligent caching for performance."""
    
    def __init__(self, max_size: int = 1000, ttl: int = 3600):
        self.cache = cachetools.TTLCache(maxsize=max_size, ttl=ttl)
        self.stats = {"hits": 0, "misses": 0, "evictions": 0}
        self.lock = threading.RLock()
        self.logger = logging.getLogger(__name__)
    
    def get(self, key: str) -> Optional[Any]:
        """Get item from cache."""
        with self.lock:
            try:
                value = self.cache[key]
                self.stats["hits"] += 1
                return value
            except KeyError:
                self.stats["misses"] += 1
                return None
    
    def set(self, key: str, value: Any) -> None:
        """Set item in cache."""
        with self.lock:
            old_size = len(self.cache)
            self.cache[key] = value
            if len(self.cache) < old_size:
                self.stats["evictions"] += 1
    
    def invalidate_pattern(self, pattern: str) -> int:
        """Invalidate cache entries matching pattern."""
        with self.lock:
            keys_to_remove = [k for k in self.cache.keys() if pattern in k]
            for key in keys_to_remove:
                del self.cache[key]
            return len(keys_to_remove)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self.lock:
            total_requests = self.stats["hits"] + self.stats["misses"]
            hit_rate = self.stats["hits"] / total_requests if total_requests > 0 else 0
            
            return {
                "size": len(self.cache),
                "max_size": self.cache.maxsize,
                "hit_rate": hit_rate,
                "hits": self.stats["hits"],
                "misses": self.stats["misses"],
                "evictions": self.stats["evictions"]
            }


class ParallelFileProcessor:
    """Processes files in parallel for improved performance."""
    
    def __init__(self, config: PerformanceConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.cache = CacheManager(config.cache_size, config.cache_ttl)
        self.memory_optimizer = MemoryOptimizer(config.memory_limit_mb)
    
    def process_files_parallel(self, file_paths: List[Path], 
                             processor: Callable[[Path], List[Vulnerability]]) -> List[Vulnerability]:
        """Process files in parallel using ThreadPoolExecutor."""
        all_vulnerabilities = []
        
        with self.memory_optimizer.memory_context():
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
                # Submit files in chunks
                for chunk in self._chunk_files(file_paths, self.config.chunk_size):
                    # Submit chunk for processing
                    future_to_file = {
                        executor.submit(self._process_file_cached, file_path, processor): file_path
                        for file_path in chunk
                    }
                    
                    # Collect results
                    for future in concurrent.futures.as_completed(future_to_file):
                        file_path = future_to_file[future]
                        try:
                            vulnerabilities = future.result(timeout=30)
                            all_vulnerabilities.extend(vulnerabilities)
                        except Exception as e:
                            self.logger.error(f"Error processing {file_path}: {e}")
        
        return all_vulnerabilities
    
    def _chunk_files(self, file_paths: List[Path], chunk_size: int) -> Iterator[List[Path]]:
        """Split file list into chunks."""
        for i in range(0, len(file_paths), chunk_size):
            yield file_paths[i:i + chunk_size]
    
    def _process_file_cached(self, file_path: Path, 
                           processor: Callable[[Path], List[Vulnerability]]) -> List[Vulnerability]:
        """Process file with caching."""
        # Generate cache key based on file path and modification time
        try:
            mtime = file_path.stat().st_mtime
            cache_key = f"{file_path}:{mtime}"
            
            # Check cache first
            cached_result = self.cache.get(cache_key)
            if cached_result is not None:
                return cached_result
            
            # Process file
            vulnerabilities = processor(file_path)
            
            # Cache result
            self.cache.set(cache_key, vulnerabilities)
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Error in cached file processing: {e}")
            # Fallback to direct processing
            return processor(file_path)


class AsyncFileScanner:
    """Asynchronous file scanning for better I/O performance."""
    
    def __init__(self, config: PerformanceConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.semaphore = asyncio.Semaphore(config.max_workers)
    
    async def scan_files_async(self, file_paths: List[Path],
                             scanner: Callable[[Path], List[Vulnerability]]) -> List[Vulnerability]:
        """Scan files asynchronously."""
        tasks = []
        
        for file_path in file_paths:
            task = self._scan_file_with_semaphore(file_path, scanner)
            tasks.append(task)
        
        # Execute all tasks and collect results
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_vulnerabilities = []
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"Async scan error: {result}")
            else:
                all_vulnerabilities.extend(result)
        
        return all_vulnerabilities
    
    async def _scan_file_with_semaphore(self, file_path: Path,
                                      scanner: Callable[[Path], List[Vulnerability]]) -> List[Vulnerability]:
        """Scan file with semaphore to limit concurrency."""
        async with self.semaphore:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, scanner, file_path)


class StreamingProcessor:
    """Processes large files using streaming to reduce memory usage."""
    
    def __init__(self, chunk_size: int = 8192):
        self.chunk_size = chunk_size
        self.logger = logging.getLogger(__name__)
    
    def process_file_streaming(self, file_path: Path, 
                             pattern_matcher: Callable[[str], List[Vulnerability]]) -> List[Vulnerability]:
        """Process large file in streaming fashion."""
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                line_number = 1
                buffer = ""
                
                while True:
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break
                    
                    buffer += chunk
                    lines = buffer.split('\n')
                    
                    # Process complete lines
                    for line in lines[:-1]:
                        line_vulns = pattern_matcher(line)
                        for vuln in line_vulns:
                            vuln.line_number = line_number
                            vuln.file_path = str(file_path)
                        vulnerabilities.extend(line_vulns)
                        line_number += 1
                    
                    # Keep incomplete line in buffer
                    buffer = lines[-1]
                
                # Process final line if any
                if buffer:
                    line_vulns = pattern_matcher(buffer)
                    for vuln in line_vulns:
                        vuln.line_number = line_number
                        vuln.file_path = str(file_path)
                    vulnerabilities.extend(line_vulns)
        
        except Exception as e:
            self.logger.error(f"Streaming processing error for {file_path}: {e}")
        
        return vulnerabilities


class MemoryMappedFileProcessor:
    """Uses memory mapping for efficient large file processing."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def process_with_mmap(self, file_path: Path,
                         processor: Callable[[bytes], List[Vulnerability]]) -> List[Vulnerability]:
        """Process file using memory mapping."""
        try:
            with open(file_path, 'rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
                    return processor(mmapped_file)
        except Exception as e:
            self.logger.error(f"Memory mapping error for {file_path}: {e}")
            # Fallback to regular file reading
            with open(file_path, 'rb') as f:
                return processor(f.read())


class AdaptiveScanner:
    """Adapts scanning strategy based on file characteristics and system resources."""
    
    def __init__(self, config: PerformanceConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.parallel_processor = ParallelFileProcessor(config)
        self.async_scanner = AsyncFileScanner(config)
        self.streaming_processor = StreamingProcessor()
        self.mmap_processor = MemoryMappedFileProcessor()
        self.performance_metrics = {}
    
    def scan_adaptively(self, file_paths: List[Path],
                       scanner: Callable[[Path], List[Vulnerability]]) -> List[Vulnerability]:
        """Scan files using adaptive strategy based on file sizes and system resources."""
        # Categorize files by size
        small_files = []
        medium_files = []
        large_files = []
        
        for file_path in file_paths:
            try:
                file_size = file_path.stat().st_size
                if file_size < 1024 * 1024:  # < 1MB
                    small_files.append(file_path)
                elif file_size < 10 * 1024 * 1024:  # < 10MB
                    medium_files.append(file_path)
                else:  # >= 10MB
                    large_files.append(file_path)
            except Exception:
                small_files.append(file_path)  # Default to small if can't get size
        
        self.logger.info(f"File categorization: {len(small_files)} small, "
                        f"{len(medium_files)} medium, {len(large_files)} large")
        
        all_vulnerabilities = []
        
        # Process small files in parallel
        if small_files:
            start_time = time.time()
            vulns = self.parallel_processor.process_files_parallel(small_files, scanner)
            all_vulnerabilities.extend(vulns)
            self.performance_metrics['small_files_time'] = time.time() - start_time
        
        # Process medium files with async I/O
        if medium_files:
            start_time = time.time()
            if self.config.enable_async_io:
                vulns = asyncio.run(self.async_scanner.scan_files_async(medium_files, scanner))
            else:
                vulns = self.parallel_processor.process_files_parallel(medium_files, scanner)
            all_vulnerabilities.extend(vulns)
            self.performance_metrics['medium_files_time'] = time.time() - start_time
        
        # Process large files with streaming or memory mapping
        if large_files:
            start_time = time.time()
            for large_file in large_files:
                try:
                    if self.config.enable_memory_mapping:
                        # Try memory mapping first
                        vulns = self._scan_large_file_mmap(large_file, scanner)
                    else:
                        # Fall back to streaming
                        vulns = self._scan_large_file_streaming(large_file, scanner)
                    all_vulnerabilities.extend(vulns)
                except Exception as e:
                    self.logger.error(f"Error processing large file {large_file}: {e}")
            self.performance_metrics['large_files_time'] = time.time() - start_time
        
        return all_vulnerabilities
    
    def _scan_large_file_mmap(self, file_path: Path, 
                            scanner: Callable[[Path], List[Vulnerability]]) -> List[Vulnerability]:
        """Scan large file using memory mapping."""
        # For simplicity, fallback to regular scanner for now
        # In a full implementation, this would use memory mapping
        return scanner(file_path)
    
    def _scan_large_file_streaming(self, file_path: Path,
                                 scanner: Callable[[Path], List[Vulnerability]]) -> List[Vulnerability]:
        """Scan large file using streaming."""
        # For simplicity, fallback to regular scanner for now
        # In a full implementation, this would use streaming
        return scanner(file_path)
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics."""
        cache_stats = self.parallel_processor.cache.get_stats()
        
        return {
            "performance_metrics": self.performance_metrics,
            "cache_stats": cache_stats,
            "config": {
                "max_workers": self.config.max_workers,
                "chunk_size": self.config.chunk_size,
                "memory_limit_mb": self.config.memory_limit_mb,
                "cache_size": self.config.cache_size
            }
        }


class DatabaseOptimizer:
    """Optimizes database operations for better performance."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.connection_pool = None
        self.prepared_statements = {}
    
    def batch_insert_vulnerabilities(self, vulnerabilities: List[Vulnerability], 
                                   batch_size: int = 1000) -> None:
        """Insert vulnerabilities in batches for better performance."""
        # Placeholder - in full implementation would use actual database
        for i in range(0, len(vulnerabilities), batch_size):
            batch = vulnerabilities[i:i + batch_size]
            self._insert_batch(batch)
    
    def _insert_batch(self, batch: List[Vulnerability]) -> None:
        """Insert a batch of vulnerabilities."""
        # Placeholder for actual database insertion
        self.logger.debug(f"Would insert batch of {len(batch)} vulnerabilities")


class ResultsAggregator:
    """Aggregates and optimizes scan results."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def aggregate_results(self, result_batches: List[List[Vulnerability]]) -> ScanResults:
        """Aggregate multiple result batches efficiently."""
        start_time = time.time()
        
        # Flatten results
        all_vulnerabilities = []
        for batch in result_batches:
            all_vulnerabilities.extend(batch)
        
        # Remove duplicates based on file_path + line_number + algorithm
        seen = set()
        unique_vulnerabilities = []
        
        for vuln in all_vulnerabilities:
            key = (vuln.file_path, vuln.line_number, vuln.algorithm.value)
            if key not in seen:
                seen.add(key)
                unique_vulnerabilities.append(vuln)
        
        # Count files and lines
        files = set(vuln.file_path for vuln in unique_vulnerabilities)
        
        results = ScanResults(
            scan_path="",  # Will be set by caller
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
            vulnerabilities=unique_vulnerabilities,
            scanned_files=len(files),
            total_lines=0,  # Would need to calculate if needed
            languages_detected=[],  # Would need to detect if needed
            scan_time=time.time() - start_time
        )
        
        self.logger.info(f"Aggregated {len(all_vulnerabilities)} vulnerabilities into "
                        f"{len(unique_vulnerabilities)} unique items from {len(files)} files")
        
        return results


class PerformanceProfiler:
    """Profiles performance of scanning operations."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.profiles = {}
        self.current_profile = None
        self.start_time = None
    
    @contextmanager
    def profile(self, name: str):
        """Context manager for profiling operations."""
        self.start_time = time.time()
        self.current_profile = {
            'name': name,
            'start_time': self.start_time,
            'memory_start': psutil.Process().memory_info().rss,
            'cpu_start': psutil.Process().cpu_percent()
        }
        
        try:
            yield self
        finally:
            end_time = time.time()
            self.current_profile.update({
                'end_time': end_time,
                'duration': end_time - self.start_time,
                'memory_end': psutil.Process().memory_info().rss,
                'cpu_end': psutil.Process().cpu_percent()
            })
            
            self.current_profile['memory_delta'] = (
                self.current_profile['memory_end'] - self.current_profile['memory_start']
            )
            
            self.profiles[name] = self.current_profile
            self.logger.info(f"Profile {name}: {self.current_profile['duration']:.2f}s, "
                           f"memory delta: {self.current_profile['memory_delta']/1024/1024:.1f}MB")
    
    def get_profile_summary(self) -> Dict[str, Any]:
        """Get summary of all profiles."""
        if not self.profiles:
            return {}
        
        total_time = sum(p['duration'] for p in self.profiles.values())
        
        return {
            'total_profiles': len(self.profiles),
            'total_time': total_time,
            'profiles': self.profiles,
            'average_duration': total_time / len(self.profiles)
        }


class ScalabilityManager:
    """Manages scaling strategies for different workload sizes."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.scaling_thresholds = {
            'small': 100,      # < 100 files
            'medium': 1000,    # < 1000 files
            'large': 10000,    # < 10000 files
            'xlarge': 100000   # >= 10000 files
        }
    
    def get_optimal_config(self, file_count: int, total_size_bytes: int) -> PerformanceConfig:
        """Get optimal configuration based on workload characteristics."""
        # Determine workload size
        if file_count < self.scaling_thresholds['small']:
            workload_size = 'small'
        elif file_count < self.scaling_thresholds['medium']:
            workload_size = 'medium'
        elif file_count < self.scaling_thresholds['large']:
            workload_size = 'large'
        else:
            workload_size = 'xlarge'
        
        # Get system resources
        cpu_count = multiprocessing.cpu_count()
        memory_mb = psutil.virtual_memory().total // (1024 * 1024)
        
        # Configure based on workload and resources
        configs = {
            'small': PerformanceConfig(
                max_workers=min(4, cpu_count),
                chunk_size=50,
                cache_size=500,
                memory_limit_mb=min(512, memory_mb // 4),
                batch_size=25
            ),
            'medium': PerformanceConfig(
                max_workers=min(8, cpu_count),
                chunk_size=100,
                cache_size=1000,
                memory_limit_mb=min(1024, memory_mb // 2),
                batch_size=50
            ),
            'large': PerformanceConfig(
                max_workers=cpu_count,
                chunk_size=200,
                cache_size=2000,
                memory_limit_mb=min(2048, memory_mb * 3 // 4),
                batch_size=100
            ),
            'xlarge': PerformanceConfig(
                max_workers=cpu_count * 2,  # Oversubscribe for I/O bound work
                chunk_size=500,
                cache_size=5000,
                memory_limit_mb=memory_mb * 3 // 4,
                batch_size=200,
                enable_async_io=True,
                enable_memory_mapping=True
            )
        }
        
        config = configs[workload_size]
        
        self.logger.info(f"Selected {workload_size} workload config for {file_count} files "
                        f"({total_size_bytes/1024/1024:.1f}MB total)")
        
        return config


def create_performance_optimized_scanner(file_count: int = 1000, 
                                       total_size_bytes: int = 100*1024*1024) -> AdaptiveScanner:
    """Create optimally configured scanner based on workload characteristics."""
    scaling_manager = ScalabilityManager()
    config = scaling_manager.get_optimal_config(file_count, total_size_bytes)
    return AdaptiveScanner(config)