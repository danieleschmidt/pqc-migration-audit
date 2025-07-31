# Performance Optimization Guide

## Overview

This guide provides comprehensive performance optimization strategies for the PQC Migration Audit tool, focusing on scan performance, memory efficiency, and scalability considerations.

## Performance Baseline Metrics

### Target Performance Goals
- **Scan Speed**: 100+ files per second for typical Python codebases
- **Memory Usage**: < 256MB for repositories up to 10,000 files
- **Response Time**: < 5 seconds for API responses
- **Throughput**: Support 10+ concurrent scans
- **Startup Time**: < 3 seconds for CLI initialization

### Current Benchmarks
```bash
# Benchmark test command
pytest tests/performance/ -v --benchmark-only
```

## Scan Performance Optimization

### 1. File Processing Optimization

#### Parallel File Processing
```python
# Optimized file scanning with multiprocessing
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor
from functools import partial

def scan_files_parallel(file_paths, max_workers=None):
    """Scan files in parallel for better performance."""
    if max_workers is None:
        max_workers = min(mp.cpu_count(), len(file_paths))
    
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        scan_func = partial(scan_single_file, config=scan_config)
        results = list(executor.map(scan_func, file_paths))
    
    return merge_scan_results(results)
```

#### Smart File Filtering
```python
# Pre-filter files to avoid unnecessary processing
SKIP_PATTERNS = {
    '.git/', '__pycache__/', '.pytest_cache/',
    '*.pyc', '*.pyo', '*.egg-info/',
    'node_modules/', '.venv/', 'venv/'
}

def should_scan_file(file_path: Path) -> bool:
    """Determine if file should be scanned based on patterns."""
    # Size check - skip very large files
    if file_path.stat().st_size > 10 * 1024 * 1024:  # 10MB
        return False
    
    # Extension check - only scan relevant file types
    if file_path.suffix not in SCANNABLE_EXTENSIONS:
        return False
    
    # Pattern check - skip common build/cache directories
    for pattern in SKIP_PATTERNS:
        if pattern in str(file_path):
            return False
    
    return True
```

### 2. Pattern Matching Optimization

#### Compiled Regular Expressions
```python
import re
from functools import lru_cache

# Pre-compile regex patterns for better performance
CRYPTO_PATTERNS = {
    'rsa_keygen': re.compile(r'rsa\.generate_private_key\s*\(.*?\)', re.IGNORECASE),
    'ecdsa_usage': re.compile(r'ecdsa\.(SigningKey|VerifyingKey)', re.IGNORECASE),
    'weak_hash': re.compile(r'hashlib\.(md5|sha1)\s*\(', re.IGNORECASE)
}

@lru_cache(maxsize=1000)
def get_pattern_matches(content: str, pattern_name: str) -> list:
    """Cache pattern matches for repeated content."""
    pattern = CRYPTO_PATTERNS.get(pattern_name)
    return pattern.findall(content) if pattern else []
```

#### Optimized String Search
```python
# Use Boyer-Moore or similar fast string search algorithms
from re2 import compile as re2_compile  # Google's RE2 library for fast regex

# Alternative: Use simple string operations when possible
def quick_crypto_check(content: str) -> bool:
    """Fast preliminary check before detailed regex analysis."""
    crypto_keywords = ['rsa', 'ecdsa', 'md5', 'sha1', 'crypto', 'cipher']
    content_lower = content.lower()
    
    return any(keyword in content_lower for keyword in crypto_keywords)
```

### 3. Memory Management

#### Streaming File Processing
```python
def scan_large_file(file_path: Path, chunk_size: int = 8192) -> Iterator[ScanResult]:
    """Process large files in chunks to minimize memory usage."""
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        buffer = ""
        line_number = 1
        
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
                
            buffer += chunk
            lines = buffer.split('\n')
            buffer = lines[-1]  # Keep incomplete line
            
            for line in lines[:-1]:
                yield from scan_line(line, line_number, file_path)
                line_number += 1
        
        # Process final buffer
        if buffer:
            yield from scan_line(buffer, line_number, file_path)
```

#### Memory-Efficient Data Structures
```python
from dataclasses import dataclass
from typing import Optional
import sys

@dataclass(slots=True)  # Reduce memory overhead
class CompactScanResult:
    """Memory-efficient scan result structure."""
    file_path: str
    line_number: int
    severity: int  # Use int instead of string
    pattern_id: int  # Use int instead of string
    
    def __post_init__(self):
        # Intern strings to save memory for repeated values
        self.file_path = sys.intern(self.file_path)
```

## Database and Storage Optimization

### 1. Caching Strategies

#### Result Caching
```python
import hashlib
from functools import lru_cache
from pathlib import Path

class ScanCache:
    """Intelligent caching for scan results."""
    
    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(exist_ok=True)
    
    def get_file_hash(self, file_path: Path) -> str:
        """Generate cache key based on file content and metadata."""
        stat = file_path.stat()
        content_hash = hashlib.sha256()
        content_hash.update(f"{stat.st_mtime}:{stat.st_size}".encode())
        
        # Sample file content for hash (first and last 1KB)
        with open(file_path, 'rb') as f:
            content_hash.update(f.read(1024))
            f.seek(-min(1024, stat.st_size), 2)
            content_hash.update(f.read())
        
        return content_hash.hexdigest()
    
    @lru_cache(maxsize=10000)
    def get_cached_result(self, file_path: str, file_hash: str) -> Optional[ScanResult]:
        """Get cached scan result if available and valid."""
        cache_file = self.cache_dir / f"{file_hash}.json"
        if cache_file.exists():
            return ScanResult.from_json(cache_file.read_text())
        return None
```

#### Repository-Level Caching
```python
def get_repo_scan_cache_key(repo_path: Path) -> str:
    """Generate cache key for entire repository scan."""
    # Use git commit hash if available
    try:
        import git
        repo = git.Repo(repo_path)
        return repo.head.commit.hexsha
    except:
        # Fallback to directory modification time
        return str(int(repo_path.stat().st_mtime))
```

### 2. Incremental Scanning

#### Change Detection
```python
def get_changed_files(repo_path: Path, last_scan_time: float) -> List[Path]:
    """Get files changed since last scan."""
    changed_files = []
    
    for file_path in repo_path.rglob('*'):
        if file_path.is_file() and file_path.stat().st_mtime > last_scan_time:
            changed_files.append(file_path)
    
    return changed_files

def incremental_scan(repo_path: Path, last_results: ScanResults) -> ScanResults:
    """Perform incremental scan of only changed files."""
    last_scan_time = last_results.scan_timestamp
    changed_files = get_changed_files(repo_path, last_scan_time)
    
    if not changed_files:
        return last_results  # No changes
    
    # Scan only changed files
    new_results = scan_files(changed_files)
    
    # Merge with previous results
    return merge_scan_results(last_results, new_results, changed_files)
```

## Scalability Improvements

### 1. Horizontal Scaling

#### Worker Pool Architecture
```python
import asyncio
import aiofiles
from concurrent.futures import ThreadPoolExecutor

class ScalableScanEngine:
    """Scalable scan engine with worker pools."""
    
    def __init__(self, max_workers: int = None):
        self.max_workers = max_workers or mp.cpu_count()
        self.thread_pool = ThreadPoolExecutor(max_workers=self.max_workers)
    
    async def scan_repository_async(self, repo_path: Path) -> ScanResults:
        """Asynchronous repository scanning."""
        file_paths = list(self.get_scannable_files(repo_path))
        
        # Split work across workers
        chunk_size = max(1, len(file_paths) // self.max_workers)
        file_chunks = [file_paths[i:i + chunk_size] 
                      for i in range(0, len(file_paths), chunk_size)]
        
        # Process chunks in parallel
        tasks = [self.scan_file_chunk_async(chunk) for chunk in file_chunks]
        chunk_results = await asyncio.gather(*tasks)
        
        return self.merge_results(chunk_results)
    
    async def scan_file_chunk_async(self, file_paths: List[Path]) -> List[ScanResult]:
        """Scan a chunk of files asynchronously."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self.thread_pool, 
            self.scan_files_sync, 
            file_paths
        )
```

### 2. Resource Management

#### Memory Monitoring
```python
import psutil
import gc
from contextlib import contextmanager

@contextmanager
def memory_monitor(max_memory_mb: int = 512):
    """Monitor and limit memory usage during scanning."""
    process = psutil.Process()
    initial_memory = process.memory_info().rss / 1024 / 1024
    
    try:
        yield
    finally:
        current_memory = process.memory_info().rss / 1024 / 1024
        memory_used = current_memory - initial_memory
        
        if memory_used > max_memory_mb:
            print(f"Warning: High memory usage detected: {memory_used:.1f}MB")
            gc.collect()  # Force garbage collection
```

#### CPU Usage Optimization
```python
import time
import threading

class CPUThrottler:
    """Throttle CPU usage to prevent system overload."""
    
    def __init__(self, max_cpu_percent: float = 80.0):
        self.max_cpu_percent = max_cpu_percent
        self._last_check = time.time()
        self._cpu_samples = []
    
    def should_throttle(self) -> bool:
        """Check if we should throttle based on CPU usage."""
        current_time = time.time()
        if current_time - self._last_check < 1.0:  # Check every second
            return False
        
        cpu_percent = psutil.cpu_percent(interval=0.1)
        self._cpu_samples.append(cpu_percent)
        
        # Keep only last 10 samples
        self._cpu_samples = self._cpu_samples[-10:]
        avg_cpu = sum(self._cpu_samples) / len(self._cpu_samples)
        
        self._last_check = current_time
        return avg_cpu > self.max_cpu_percent
    
    def throttle_if_needed(self, sleep_duration: float = 0.1):
        """Sleep if CPU usage is too high."""
        if self.should_throttle():
            time.sleep(sleep_duration)
```

## API Performance Optimization

### 1. Response Optimization

#### Pagination and Filtering
```python
from fastapi import Query
from typing import Optional

@app.get("/scan-results/")
async def get_scan_results(
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=1000),
    severity: Optional[str] = None,
    file_pattern: Optional[str] = None
) -> PaginatedScanResults:
    """Get paginated and filtered scan results."""
    
    # Build efficient database query
    query = ScanResult.query()
    
    if severity:
        query = query.filter(ScanResult.severity == severity)
    
    if file_pattern:
        query = query.filter(ScanResult.file_path.like(f"%{file_pattern}%"))
    
    # Get total count for pagination
    total = query.count()
    
    # Apply pagination
    offset = (page - 1) * size
    results = query.offset(offset).limit(size).all()
    
    return PaginatedScanResults(
        results=results,
        total=total,
        page=page,
        size=size,
        pages=(total + size - 1) // size
    )
```

#### Response Compression
```python
from fastapi.middleware.gzip import GZipMiddleware

# Add compression middleware
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Custom response optimization
class OptimizedJSONResponse(JSONResponse):
    """Optimized JSON response with minimal serialization."""
    
    def render(self, content: Any) -> bytes:
        # Use faster JSON serialization
        import orjson
        return orjson.dumps(content, option=orjson.OPT_SERIALIZE_NUMPY)
```

## Monitoring and Profiling

### 1. Performance Metrics Collection

#### Custom Metrics
```python
from prometheus_client import Histogram, Counter
import time

# Performance metrics
SCAN_DURATION = Histogram('pqc_audit_scan_duration_seconds', 
                         'Time spent scanning files',
                         buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0])

FILES_PER_SECOND = Histogram('pqc_audit_files_per_second',
                            'Files processed per second',
                            buckets=[10, 25, 50, 100, 200, 500])

MEMORY_PEAK = Histogram('pqc_audit_memory_peak_mb',
                       'Peak memory usage during scan',
                       buckets=[64, 128, 256, 512, 1024])

def measure_scan_performance(func):
    """Decorator to measure scan performance."""
    def wrapper(*args, **kwargs):
        start_time = time.time()
        start_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        try:
            result = func(*args, **kwargs)
            
            # Record metrics
            duration = time.time() - start_time
            SCAN_DURATION.observe(duration)
            
            if hasattr(result, 'files_processed'):
                files_per_sec = result.files_processed / duration
                FILES_PER_SECOND.observe(files_per_sec)
            
            peak_memory = psutil.Process().memory_info().rss / 1024 / 1024
            MEMORY_PEAK.observe(peak_memory - start_memory)
            
            return result
            
        except Exception as e:
            # Record error metrics
            SCAN_ERRORS.labels(error_type=type(e).__name__).inc()
            raise
    
    return wrapper
```

### 2. Profiling Integration

#### Memory Profiling
```python
from memory_profiler import profile
import tracemalloc

@profile
def memory_intensive_scan(repo_path: Path):
    """Memory profiling for scan operations."""
    # Start memory tracing
    tracemalloc.start()
    
    try:
        results = perform_scan(repo_path)
        
        # Get memory usage snapshot
        current, peak = tracemalloc.get_traced_memory()
        print(f"Current memory usage: {current / 1024 / 1024:.1f} MB")
        print(f"Peak memory usage: {peak / 1024 / 1024:.1f} MB")
        
        return results
    
    finally:
        tracemalloc.stop()
```

#### CPU Profiling
```python
import cProfile
import pstats
from contextlib import contextmanager

@contextmanager
def cpu_profile(output_file: str = "scan_profile.prof"):
    """Context manager for CPU profiling."""
    profiler = cProfile.Profile()
    profiler.enable()
    
    try:
        yield profiler
    finally:
        profiler.disable()
        profiler.dump_stats(output_file)
        
        # Print top time consumers
        stats = pstats.Stats(output_file)
        stats.sort_stats('cumulative')
        stats.print_stats(20)
```

## Configuration Optimization

### 1. Performance Tuning Parameters

#### Configuration Template
```yaml
# performance-config.yml
performance:
  # Scanning configuration
  max_workers: 8  # CPU cores for parallel processing
  chunk_size: 1000  # Files per processing chunk
  max_file_size_mb: 10  # Skip files larger than this
  
  # Memory management
  max_memory_mb: 512  # Memory limit for scanning
  cache_size_mb: 128  # Cache size for results
  gc_threshold: 1000  # Garbage collection frequency
  
  # Caching configuration
  enable_cache: true
  cache_ttl_hours: 24
  incremental_scan: true
  
  # API performance
  response_timeout_seconds: 30
  max_concurrent_requests: 100
  enable_compression: true
  
  # Database optimization
  connection_pool_size: 20
  query_timeout_seconds: 10
  bulk_insert_size: 1000
```

### 2. Environment-Specific Tuning

#### Development Environment
```yaml
performance:
  max_workers: 2  # Reduced for development
  max_memory_mb: 128
  enable_cache: false  # Disable for fresh results
  debug_profiling: true
```

#### Production Environment
```yaml
performance:
  max_workers: 16  # Full CPU utilization
  max_memory_mb: 2048
  enable_cache: true
  cache_ttl_hours: 168  # 1 week
  monitoring_enabled: true
```

## Troubleshooting Performance Issues

### 1. Common Performance Problems

#### Slow File Processing
```bash
# Profile file processing performance
python -m cProfile -o scan_profile.prof -m pqc_audit scan /path/to/repo
python -c "import pstats; pstats.Stats('scan_profile.prof').sort_stats('cumulative').print_stats(20)"
```

#### Memory Leaks
```bash
# Monitor memory usage over time
python -m memory_profiler scripts/scan_large_repo.py

# Use memory tracking in code
import tracemalloc
tracemalloc.start()
# ... perform operations ...
snapshot = tracemalloc.take_snapshot()
top_stats = snapshot.statistics('lineno')
for stat in top_stats[:10]:
    print(stat)
```

#### High CPU Usage
```bash
# Monitor CPU usage
python -m py_spy top --pid <process_id>

# Profile CPU hot spots
python -m py_spy record -o profile.svg --pid <process_id>
```

### 2. Performance Testing

#### Load Testing Script
```python
import asyncio
import time
from concurrent.futures import ThreadPoolExecutor

async def load_test_scan_api(concurrent_requests: int = 10):
    """Load test the scan API endpoint."""
    
    async def single_request():
        # Simulate API request
        start_time = time.time()
        # Make actual API call here
        duration = time.time() - start_time
        return duration
    
    # Run concurrent requests
    tasks = [single_request() for _ in range(concurrent_requests)]
    durations = await asyncio.gather(*tasks)
    
    # Analyze results
    avg_duration = sum(durations) / len(durations)
    max_duration = max(durations)
    
    print(f"Average response time: {avg_duration:.2f}s")
    print(f"Maximum response time: {max_duration:.2f}s")
    print(f"Requests per second: {concurrent_requests / max_duration:.1f}")
```

## Best Practices Summary

### 1. Development Best Practices
- Profile early and often during development
- Use appropriate data structures for memory efficiency
- Implement caching strategically
- Monitor resource usage in tests

### 2. Deployment Best Practices
- Configure resource limits appropriately
- Enable monitoring and alerting
- Use horizontal scaling when possible
- Optimize for the target environment

### 3. Maintenance Best Practices
- Regular performance regression testing
- Monitor and tune based on real usage patterns
- Update dependencies for performance improvements
- Document performance characteristics and limits

## References

- [Python Performance Tips](https://wiki.python.org/moin/PythonSpeed/PerformanceTips)
- [Prometheus Python Client](https://github.com/prometheus/client_python)
- [Memory Profiler Documentation](https://pypi.org/project/memory-profiler/)
- [FastAPI Performance Guide](https://fastapi.tiangolo.com/advanced/)