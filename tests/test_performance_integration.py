"""Integration tests for performance optimizations."""

import pytest
import tempfile
import time
from pathlib import Path
from unittest.mock import Mock, patch
import asyncio
import threading

from src.pqc_migration_audit.performance_optimizer import (
    PerformanceConfig, MemoryOptimizer, CacheManager, 
    ParallelFileProcessor, AsyncFileScanner, AdaptiveScanner,
    create_performance_optimized_scanner
)
from src.pqc_migration_audit.types import Vulnerability, Severity, CryptoAlgorithm


class TestMemoryOptimizer:
    """Test memory optimization functionality."""
    
    def test_memory_optimizer_init(self):
        """Test memory optimizer initialization."""
        optimizer = MemoryOptimizer(memory_limit_mb=1024)
        assert optimizer.memory_limit == 1024 * 1024 * 1024
        assert not optimizer._monitoring
    
    def test_memory_context_manager(self):
        """Test memory context manager."""
        optimizer = MemoryOptimizer(memory_limit_mb=1024)
        
        with optimizer.memory_context():
            assert optimizer._monitoring
        
        assert not optimizer._monitoring


class TestCacheManager:
    """Test cache management functionality."""
    
    def test_cache_basic_operations(self):
        """Test basic cache operations."""
        cache = CacheManager(max_size=10, ttl=60)
        
        # Test set and get
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"
        
        # Test miss
        assert cache.get("nonexistent") is None
        
        # Test stats
        stats = cache.get_stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 1
    
    def test_cache_invalidation(self):
        """Test cache pattern invalidation."""
        cache = CacheManager(max_size=10, ttl=60)
        
        cache.set("test_key_1", "value1")
        cache.set("test_key_2", "value2")
        cache.set("other_key", "value3")
        
        # Invalidate pattern
        invalidated = cache.invalidate_pattern("test_key")
        assert invalidated == 2
        
        # Check keys are gone
        assert cache.get("test_key_1") is None
        assert cache.get("test_key_2") is None
        assert cache.get("other_key") == "value3"


class TestParallelFileProcessor:
    """Test parallel file processing."""
    
    def test_file_chunking(self):
        """Test file list chunking."""
        config = PerformanceConfig(chunk_size=3)
        processor = ParallelFileProcessor(config)
        
        files = [Path(f"file_{i}") for i in range(10)]
        chunks = list(processor._chunk_files(files, 3))
        
        assert len(chunks) == 4  # 10 files in chunks of 3
        assert len(chunks[0]) == 3
        assert len(chunks[1]) == 3
        assert len(chunks[2]) == 3
        assert len(chunks[3]) == 1
    
    @pytest.fixture
    def temp_files(self):
        """Create temporary files for testing."""
        temp_dir = Path(tempfile.mkdtemp())
        
        # Create test files with different content
        files = []
        for i in range(5):
            file_path = temp_dir / f"test_file_{i}.py"
            with open(file_path, 'w') as f:
                f.write(f"""
import rsa
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
print("File {i}")
""")
            files.append(file_path)
        
        yield files
        
        # Cleanup
        import shutil
        shutil.rmtree(temp_dir)
    
    def test_parallel_processing(self, temp_files):
        """Test parallel file processing."""
        config = PerformanceConfig(max_workers=2, chunk_size=2)
        processor = ParallelFileProcessor(config)
        
        def mock_scanner(file_path):
            # Simulate finding vulnerabilities
            return [
                Vulnerability(
                    file_path=str(file_path),
                    line_number=3,
                    algorithm=CryptoAlgorithm.RSA,
                    severity=Severity.HIGH,
                    description="RSA detected",
                    code_snippet="rsa.generate_private_key"
                )
            ]
        
        vulnerabilities = processor.process_files_parallel(temp_files, mock_scanner)
        
        # Should find one vulnerability per file
        assert len(vulnerabilities) == len(temp_files)
        
        # Check cache stats
        cache_stats = processor.cache.get_stats()
        assert cache_stats["size"] == len(temp_files)


class TestAsyncFileScanner:
    """Test asynchronous file scanning."""
    
    @pytest.mark.asyncio
    async def test_async_scanning(self):
        """Test asynchronous file scanning."""
        config = PerformanceConfig(max_workers=3)
        scanner = AsyncFileScanner(config)
        
        # Create mock files
        files = [Path(f"mock_file_{i}.py") for i in range(5)]
        
        def mock_scanner(file_path):
            # Simulate processing time
            time.sleep(0.1)
            return [
                Vulnerability(
                    file_path=str(file_path),
                    line_number=1,
                    algorithm=CryptoAlgorithm.RSA,
                    severity=Severity.HIGH,
                    description="Mock vulnerability"
                )
            ]
        
        start_time = time.time()
        with patch('builtins.open'), patch('pathlib.Path.stat'):
            vulnerabilities = await scanner.scan_files_async(files, mock_scanner)
        duration = time.time() - start_time
        
        # Should process in parallel, taking less time than sequential
        assert len(vulnerabilities) == len(files)
        # With 3 workers and 0.1s per file, should take ~0.2s instead of 0.5s
        assert duration < 0.4


class TestAdaptiveScanner:
    """Test adaptive scanning strategy."""
    
    def test_file_categorization(self):
        """Test file categorization by size."""
        config = PerformanceConfig()
        scanner = AdaptiveScanner(config)
        
        # Mock files with different sizes
        with patch('pathlib.Path.stat') as mock_stat:
            # Set up different file sizes
            def side_effect(self):
                file_name = str(self)
                if 'small' in file_name:
                    mock_stat_result = Mock()
                    mock_stat_result.st_size = 500 * 1024  # 500KB
                    return mock_stat_result
                elif 'medium' in file_name:
                    mock_stat_result = Mock()
                    mock_stat_result.st_size = 5 * 1024 * 1024  # 5MB
                    return mock_stat_result
                else:  # large
                    mock_stat_result = Mock()
                    mock_stat_result.st_size = 50 * 1024 * 1024  # 50MB
                    return mock_stat_result
            
            mock_stat.side_effect = side_effect
            
            files = [
                Path("small_file1.py"),
                Path("small_file2.py"),
                Path("medium_file1.py"),
                Path("large_file1.py")
            ]
            
            def mock_scanner(file_path):
                return []  # Empty results for test
            
            # This should categorize files and use different strategies
            vulnerabilities = scanner.scan_adaptively(files, mock_scanner)
            
            # Should return empty list but complete without error
            assert vulnerabilities == []
            
            # Check performance stats were recorded
            stats = scanner.get_performance_stats()
            assert "performance_metrics" in stats
    
    def test_performance_stats(self):
        """Test performance statistics collection."""
        config = PerformanceConfig()
        scanner = AdaptiveScanner(config)
        
        stats = scanner.get_performance_stats()
        
        assert "performance_metrics" in stats
        assert "cache_stats" in stats
        assert "config" in stats
        assert stats["config"]["max_workers"] == config.max_workers


class TestScalabilityManager:
    """Test scalability management."""
    
    def test_optimal_config_selection(self):
        """Test optimal configuration selection."""
        from src.pqc_migration_audit.performance_optimizer import ScalabilityManager
        
        manager = ScalabilityManager()
        
        # Test small workload
        config = manager.get_optimal_config(50, 10*1024*1024)  # 50 files, 10MB
        assert config.max_workers <= 4
        assert config.chunk_size == 50
        
        # Test large workload
        config = manager.get_optimal_config(5000, 1024*1024*1024)  # 5K files, 1GB
        assert config.max_workers > 4
        assert config.chunk_size > 50
        assert config.cache_size > 500


class TestPerformanceIntegration:
    """Integration tests for performance components."""
    
    def test_create_optimized_scanner(self):
        """Test creation of optimized scanner."""
        scanner = create_performance_optimized_scanner(
            file_count=1000,
            total_size_bytes=100*1024*1024
        )
        
        assert isinstance(scanner, AdaptiveScanner)
        assert scanner.config.max_workers > 0
        assert scanner.config.chunk_size > 0
    
    def test_memory_pressure_handling(self):
        """Test handling of memory pressure."""
        config = PerformanceConfig(memory_limit_mb=1)  # Very low limit
        
        with patch('psutil.Process') as mock_process:
            mock_process.return_value.memory_info.return_value.rss = 2 * 1024 * 1024  # 2MB
            
            optimizer = MemoryOptimizer(memory_limit_mb=1)
            
            # This should trigger memory pressure handling
            with pytest.raises(Exception):  # ResourceExhaustedException
                with optimizer.memory_context():
                    time.sleep(0.1)  # Let monitor thread run
    
    def test_cache_performance_under_load(self):
        """Test cache performance under high load."""
        cache = CacheManager(max_size=100, ttl=60)
        
        # Simulate high concurrent access
        def cache_worker(worker_id):
            for i in range(100):
                key = f"worker_{worker_id}_key_{i}"
                cache.set(key, f"value_{i}")
                cache.get(key)
        
        threads = []
        for worker_id in range(5):
            thread = threading.Thread(target=cache_worker, args=(worker_id,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        stats = cache.get_stats()
        assert stats["hits"] > 0
        assert stats["misses"] >= 0
        
        # Cache should not exceed max size due to eviction
        assert stats["size"] <= 100


@pytest.mark.slow
class TestPerformanceBenchmarks:
    """Performance benchmark tests."""
    
    def test_parallel_vs_sequential_performance(self, temp_files=None):
        """Compare parallel vs sequential processing performance."""
        if not temp_files:
            # Create temporary files for benchmark
            temp_dir = Path(tempfile.mkdtemp())
            files = []
            for i in range(20):
                file_path = temp_dir / f"bench_file_{i}.py"
                with open(file_path, 'w') as f:
                    f.write("import rsa\nkey = rsa.generate_private_key()\n" * 10)
                files.append(file_path)
        else:
            files = temp_files
        
        def slow_scanner(file_path):
            # Simulate slow processing
            time.sleep(0.05)
            return [
                Vulnerability(
                    file_path=str(file_path),
                    line_number=1,
                    algorithm=CryptoAlgorithm.RSA,
                    severity=Severity.HIGH,
                    description="Benchmark vuln"
                )
            ]
        
        # Sequential processing
        start_time = time.time()
        sequential_results = []
        for file_path in files:
            sequential_results.extend(slow_scanner(file_path))
        sequential_time = time.time() - start_time
        
        # Parallel processing
        config = PerformanceConfig(max_workers=4, chunk_size=5)
        processor = ParallelFileProcessor(config)
        
        start_time = time.time()
        parallel_results = processor.process_files_parallel(files, slow_scanner)
        parallel_time = time.time() - start_time
        
        # Results should be the same
        assert len(parallel_results) == len(sequential_results)
        
        # Parallel should be faster (with some tolerance for overhead)
        speedup_ratio = sequential_time / parallel_time
        assert speedup_ratio > 1.5  # At least 50% faster
        
        # Cleanup
        if not temp_files:
            import shutil
            shutil.rmtree(temp_dir)
    
    def test_memory_usage_optimization(self):
        """Test memory usage during large scans."""
        import psutil
        import gc
        
        process = psutil.Process()
        
        # Get baseline memory
        gc.collect()
        baseline_memory = process.memory_info().rss
        
        # Create large number of mock vulnerabilities
        vulnerabilities = []
        for i in range(10000):
            vuln = Vulnerability(
                file_path=f"file_{i}.py",
                line_number=i,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.HIGH,
                description=f"Vulnerability {i}",
                code_snippet="mock code snippet"
            )
            vulnerabilities.append(vuln)
        
        peak_memory = process.memory_info().rss
        
        # Clean up and check memory is released
        del vulnerabilities
        gc.collect()
        final_memory = process.memory_info().rss
        
        memory_growth = peak_memory - baseline_memory
        memory_released = peak_memory - final_memory
        
        # Should release most of the allocated memory
        release_ratio = memory_released / memory_growth
        assert release_ratio > 0.8  # At least 80% released
    
    @pytest.mark.asyncio
    async def test_async_performance_scaling(self):
        """Test async performance scales with concurrent operations."""
        config = PerformanceConfig(max_workers=8)
        scanner = AsyncFileScanner(config)
        
        def variable_delay_scanner(file_path):
            # Variable delay to simulate real-world processing
            import random
            time.sleep(random.uniform(0.05, 0.15))
            return [Vulnerability(
                file_path=str(file_path),
                line_number=1,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.HIGH,
                description="Async test vuln"
            )]
        
        # Test with different numbers of files
        file_counts = [10, 20, 40]
        results = []
        
        for count in file_counts:
            files = [Path(f"async_file_{i}.py") for i in range(count)]
            
            start_time = time.time()
            with patch('builtins.open'), patch('pathlib.Path.stat'):
                vulnerabilities = await scanner.scan_files_async(files, variable_delay_scanner)
            duration = time.time() - start_time
            
            results.append((count, duration, len(vulnerabilities)))
        
        # Check that processing time doesn't scale linearly with file count
        # (indicating parallel processing is working)
        for i in range(1, len(results)):
            file_ratio = results[i][0] / results[i-1][0]
            time_ratio = results[i][1] / results[i-1][1]
            
            # Time should scale sub-linearly due to parallelism
            assert time_ratio < file_ratio * 0.8


if __name__ == "__main__":
    pytest.main([__file__, "-v"])