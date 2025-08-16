"""
Advanced Caching for Generation 3: Make It Scale
Intelligent caching strategies, memoization, and performance optimization.
"""

import hashlib
import json
import pickle
import time
import os
import threading
from typing import Any, Dict, Optional, Callable, Union, Tuple, List
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import functools
import weakref
import logging

from .types import ScanResults, Vulnerability


class CacheStrategy(Enum):
    """Caching strategies for different scenarios."""
    LRU = "lru"  # Least Recently Used
    LFU = "lfu"  # Least Frequently Used
    TTL = "ttl"  # Time To Live
    ADAPTIVE = "adaptive"  # Adaptive based on access patterns


@dataclass
class CacheEntry:
    """Cache entry with metadata."""
    value: Any
    timestamp: float
    access_count: int = 0
    last_access: float = field(default_factory=time.time)
    size_bytes: int = 0
    
    def __post_init__(self):
        """Calculate entry size after initialization."""
        try:
            self.size_bytes = len(pickle.dumps(self.value))
        except:
            self.size_bytes = 1024  # Default size estimate


class SmartCache:
    """Intelligent caching system with multiple strategies."""
    
    def __init__(self, 
                 max_size: int = 1000,
                 max_memory_mb: int = 100,
                 default_ttl: int = 3600,
                 strategy: CacheStrategy = CacheStrategy.ADAPTIVE):
        """Initialize smart cache."""
        self.max_size = max_size
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        self.default_ttl = default_ttl
        self.strategy = strategy
        
        self.cache: Dict[str, CacheEntry] = {}
        self.access_order: List[str] = []  # For LRU
        self.size_bytes = 0
        self.hit_count = 0
        self.miss_count = 0
        
        self.logger = logging.getLogger(__name__)
        self._lock = threading.RLock()
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        with self._lock:
            if key in self.cache:
                entry = self.cache[key]
                
                # Check TTL
                if self._is_expired(entry):
                    self._remove_entry(key)
                    self.miss_count += 1
                    return None
                
                # Update access information
                entry.access_count += 1
                entry.last_access = time.time()
                
                # Update access order for LRU
                if key in self.access_order:
                    self.access_order.remove(key)
                self.access_order.append(key)
                
                self.hit_count += 1
                return entry.value
            else:
                self.miss_count += 1
                return None
    
    def put(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Put value in cache."""
        with self._lock:
            try:
                # Create cache entry
                entry = CacheEntry(
                    value=value,
                    timestamp=time.time()
                )
                
                # Check if we need to make space
                if key not in self.cache:
                    if len(self.cache) >= self.max_size:
                        self._evict_entries()
                    
                    # Check memory limit
                    if self.size_bytes + entry.size_bytes > self.max_memory_bytes:
                        self._evict_by_size(entry.size_bytes)
                
                # Remove old entry if exists
                if key in self.cache:
                    self._remove_entry(key)
                
                # Add new entry
                self.cache[key] = entry
                self.size_bytes += entry.size_bytes
                
                # Update access order
                if key in self.access_order:
                    self.access_order.remove(key)
                self.access_order.append(key)
                
                return True
                
            except Exception as e:
                self.logger.error(f"Cache put failed for key {key}: {e}")
                return False
    
    def invalidate(self, key: str) -> bool:
        """Invalidate specific cache entry."""
        with self._lock:
            if key in self.cache:
                self._remove_entry(key)
                return True
            return False
    
    def clear(self):
        """Clear all cache entries."""
        with self._lock:
            self.cache.clear()
            self.access_order.clear()
            self.size_bytes = 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            total_requests = self.hit_count + self.miss_count
            hit_rate = (self.hit_count / total_requests) if total_requests > 0 else 0.0
            
            return {
                'size': len(self.cache),
                'max_size': self.max_size,
                'memory_usage_mb': self.size_bytes / (1024 * 1024),
                'max_memory_mb': self.max_memory_bytes / (1024 * 1024),
                'hit_count': self.hit_count,
                'miss_count': self.miss_count,
                'hit_rate': hit_rate,
                'strategy': self.strategy.value
            }
    
    def _is_expired(self, entry: CacheEntry) -> bool:
        """Check if cache entry is expired."""
        return (time.time() - entry.timestamp) > self.default_ttl
    
    def _remove_entry(self, key: str):
        """Remove entry from cache."""
        if key in self.cache:
            entry = self.cache[key]
            self.size_bytes -= entry.size_bytes
            del self.cache[key]
            
            if key in self.access_order:
                self.access_order.remove(key)
    
    def _evict_entries(self):
        """Evict entries based on strategy."""
        if self.strategy == CacheStrategy.LRU:
            self._evict_lru()
        elif self.strategy == CacheStrategy.LFU:
            self._evict_lfu()
        elif self.strategy == CacheStrategy.TTL:
            self._evict_expired()
        elif self.strategy == CacheStrategy.ADAPTIVE:
            self._evict_adaptive()
    
    def _evict_lru(self):
        """Evict least recently used entries."""
        while len(self.cache) >= self.max_size and self.access_order:
            oldest_key = self.access_order[0]
            self._remove_entry(oldest_key)
    
    def _evict_lfu(self):
        """Evict least frequently used entries."""
        if not self.cache:
            return
        
        # Find entry with lowest access count
        lfu_key = min(self.cache.keys(), key=lambda k: self.cache[k].access_count)
        self._remove_entry(lfu_key)
    
    def _evict_expired(self):
        """Evict expired entries."""
        current_time = time.time()
        expired_keys = [
            key for key, entry in self.cache.items()
            if (current_time - entry.timestamp) > self.default_ttl
        ]
        
        for key in expired_keys:
            self._remove_entry(key)
    
    def _evict_adaptive(self):
        """Adaptive eviction based on access patterns."""
        # First try to evict expired entries
        self._evict_expired()
        
        # If still need space, use LRU
        if len(self.cache) >= self.max_size:
            self._evict_lru()
    
    def _evict_by_size(self, needed_bytes: int):
        """Evict entries to free up memory."""
        while self.size_bytes + needed_bytes > self.max_memory_bytes and self.cache:
            if self.access_order:
                oldest_key = self.access_order[0]
                self._remove_entry(oldest_key)
            else:
                # Remove arbitrary entry if access_order is empty
                key = next(iter(self.cache))
                self._remove_entry(key)


class FileScanCache:
    """Specialized cache for file scanning results."""
    
    def __init__(self, cache_dir: Optional[Path] = None):
        """Initialize file scan cache."""
        self.cache_dir = cache_dir or Path("/tmp/pqc_scan_cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.memory_cache = SmartCache(max_size=500, max_memory_mb=50)
        self.logger = logging.getLogger(__name__)
    
    def get_file_hash(self, file_path: Path) -> str:
        """Generate hash for file based on path and modification time."""
        try:
            stat = file_path.stat()
            content = f"{file_path}:{stat.st_mtime}:{stat.st_size}"
            return hashlib.sha256(content.encode()).hexdigest()
        except:
            return hashlib.sha256(str(file_path).encode()).hexdigest()
    
    def get_scan_result(self, file_path: Path) -> Optional[List[Vulnerability]]:
        """Get cached scan result for file."""
        file_hash = self.get_file_hash(file_path)
        
        # Try memory cache first
        result = self.memory_cache.get(file_hash)
        if result is not None:
            return result
        
        # Try disk cache
        cache_file = self.cache_dir / f"{file_hash}.json"
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                
                # Reconstruct vulnerabilities
                vulnerabilities = []
                for vuln_data in data.get('vulnerabilities', []):
                    vuln = Vulnerability(**vuln_data)
                    vulnerabilities.append(vuln)
                
                # Store in memory cache
                self.memory_cache.put(file_hash, vulnerabilities)
                
                return vulnerabilities
                
            except Exception as e:
                self.logger.error(f"Failed to load cached result for {file_path}: {e}")
                cache_file.unlink(missing_ok=True)
        
        return None
    
    def store_scan_result(self, file_path: Path, vulnerabilities: List[Vulnerability]):
        """Store scan result in cache."""
        file_hash = self.get_file_hash(file_path)
        
        # Store in memory cache
        self.memory_cache.put(file_hash, vulnerabilities)
        
        # Store in disk cache
        try:
            cache_file = self.cache_dir / f"{file_hash}.json"
            
            # Convert vulnerabilities to serializable format
            vuln_data = []
            for vuln in vulnerabilities:
                vuln_dict = {
                    'file_path': vuln.file_path,
                    'line_number': vuln.line_number,
                    'algorithm': vuln.algorithm.value if hasattr(vuln.algorithm, 'value') else str(vuln.algorithm),
                    'severity': vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity),
                    'description': vuln.description,
                    'code_snippet': vuln.code_snippet,
                    'recommendation': vuln.recommendation,
                    'cwe_id': vuln.cwe_id
                }
                vuln_data.append(vuln_dict)
            
            data = {
                'file_path': str(file_path),
                'cached_at': time.time(),
                'vulnerabilities': vuln_data
            }
            
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to cache result for {file_path}: {e}")
    
    def cleanup_expired(self, max_age_hours: int = 24):
        """Clean up expired cache entries."""
        max_age_seconds = max_age_hours * 3600
        current_time = time.time()
        
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                if cache_file.stat().st_mtime < (current_time - max_age_seconds):
                    cache_file.unlink()
                    self.logger.debug(f"Removed expired cache file: {cache_file}")
            except Exception as e:
                self.logger.error(f"Failed to remove expired cache file {cache_file}: {e}")


def memoize_scan_result(cache: Optional[SmartCache] = None):
    """Decorator to memoize scan results."""
    if cache is None:
        cache = SmartCache(max_size=200, max_memory_mb=20)
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(file_path: Union[str, Path], *args, **kwargs):
            # Create cache key
            key_data = f"{file_path}:{args}:{sorted(kwargs.items())}"
            cache_key = hashlib.md5(key_data.encode()).hexdigest()
            
            # Try to get from cache
            result = cache.get(cache_key)
            if result is not None:
                return result
            
            # Execute function and cache result
            result = func(file_path, *args, **kwargs)
            cache.put(cache_key, result)
            
            return result
        
        wrapper.cache = cache
        return wrapper
    
    return decorator


def main():
    """Test advanced caching functionality."""
    print("🗃️  Advanced Caching System Test")
    
    # Test SmartCache
    cache = SmartCache(max_size=5, max_memory_mb=1)
    
    # Add test data
    test_data = {
        'key1': {'data': 'test1', 'size': 100},
        'key2': {'data': 'test2', 'size': 200},
        'key3': {'data': 'test3', 'size': 300},
    }
    
    for key, value in test_data.items():
        cache.put(key, value)
        print(f"Added {key} to cache")
    
    # Test retrieval
    for key in test_data.keys():
        result = cache.get(key)
        print(f"Retrieved {key}: {'Found' if result else 'Not found'}")
    
    # Test cache stats
    stats = cache.get_stats()
    print(f"\n📊 Cache Statistics:")
    print(f"Size: {stats['size']}/{stats['max_size']}")
    print(f"Memory: {stats['memory_usage_mb']:.2f}/{stats['max_memory_mb']:.2f} MB")
    print(f"Hit rate: {stats['hit_rate']:.2%}")
    
    # Test FileScanCache
    file_cache = FileScanCache()
    test_file = Path("/tmp/test_file.py")
    
    # Create test file
    test_file.write_text("print('Hello, world!')")
    
    # Test caching
    vulnerabilities = []  # Empty list for test
    file_cache.store_scan_result(test_file, vulnerabilities)
    
    cached_result = file_cache.get_scan_result(test_file)
    print(f"\n📁 File cache test: {'Success' if cached_result is not None else 'Failed'}")
    
    # Cleanup
    test_file.unlink(missing_ok=True)
    
    print("✅ Caching tests completed")


if __name__ == "__main__":
    main()