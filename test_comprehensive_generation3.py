#!/usr/bin/env python3
"""
Comprehensive tests for Generation 3: MAKE IT SCALE functionality.
Tests performance optimization, caching, concurrent processing, and auto-scaling.
"""

import os
import sys
import tempfile
import json
import pytest
import time
import threading
import asyncio
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from pqc_migration_audit.core import CryptoAuditor, RiskAssessment
from pqc_migration_audit.types import ScanResults, Vulnerability, Severity, CryptoAlgorithm

# Try importing Generation 3 performance features
try:
    from pqc_migration_audit.performance_engine import PerformanceEngine, PerformanceMetrics
    from pqc_migration_audit.performance_optimizer import PerformanceOptimizer
    from pqc_migration_audit.advanced_caching import AdaptiveCache, CacheStrategy
    from pqc_migration_audit.auto_scaling import AutoScaler, WorkerPool, global_auto_scaler
    from pqc_migration_audit.scalability_engine import ScalabilityEngine
    PERFORMANCE_FEATURES_AVAILABLE = True
except ImportError:
    PERFORMANCE_FEATURES_AVAILABLE = False
    
    # Mock classes for testing when features aren't available
    class MockPerformanceEngine:
        def __init__(self): pass
        def get_metrics(self): return {}
    
    class MockAdaptiveCache:
        def __init__(self): pass
        def get(self, key): return None
        def put(self, key, value): pass
    
    class MockAutoScaler:
        def __init__(self): pass
        def start_monitoring(self): pass
        def stop_monitoring(self): pass


class TestPerformanceBaseline:
    """Test baseline performance characteristics."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.auditor = CryptoAuditor()
    
    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def create_large_test_project(self, num_files: int = 100):
        """Create a large test project for performance testing."""
        vulnerable_code = '''
import rsa
from cryptography.hazmat.primitives.asymmetric import ec

def generate_rsa_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

def generate_ecc_key():
    return ec.generate_private_key(ec.SECP256R1())

class CryptoService:
    def __init__(self):
        self.rsa_key = generate_rsa_key()
        self.ecc_key = generate_ecc_key()
'''
        
        for i in range(num_files):
            file_path = Path(self.temp_dir) / f"crypto_service_{i}.py"
            file_path.write_text(vulnerable_code, encoding='utf-8')
        
        # Create some Java files too
        java_code = '''
import java.security.KeyPairGenerator;

public class CryptoService {
    public void generateRSAKey() {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }
}
'''
        for i in range(num_files // 5):  # 20% Java files
            file_path = Path(self.temp_dir) / f"CryptoService{i}.java"
            file_path.write_text(java_code, encoding='utf-8')
    
    def test_baseline_scan_performance(self):
        """Test baseline scanning performance."""
        num_files = 50
        self.create_large_test_project(num_files)
        
        start_time = time.time()
        results = self.auditor.scan_directory(self.temp_dir)
        scan_time = time.time() - start_time
        
        # Performance assertions
        assert scan_time < 30  # Should complete within 30 seconds
        assert results.scanned_files >= num_files
        assert len(results.vulnerabilities) >= num_files * 2  # Multiple vulns per file
        
        # Calculate throughput
        files_per_second = results.scanned_files / scan_time
        assert files_per_second > 2  # Should process at least 2 files per second
        
        print(f"Baseline performance: {files_per_second:.2f} files/sec, "
              f"{len(results.vulnerabilities)} vulnerabilities found")
    
    def test_memory_efficiency_large_project(self):
        """Test memory efficiency with large projects."""
        import psutil
        import os
        
        # Get initial memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Create and scan large project
        num_files = 100
        self.create_large_test_project(num_files)
        results = self.auditor.scan_directory(self.temp_dir)
        
        # Get final memory usage
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Memory should not increase excessively
        assert memory_increase < 200  # Less than 200MB increase
        assert results.scanned_files >= num_files
        
        print(f"Memory usage: {initial_memory:.1f}MB -> {final_memory:.1f}MB "
              f"(+{memory_increase:.1f}MB)")
    
    def test_scalability_with_increasing_load(self):
        """Test scalability with increasing project sizes."""
        test_sizes = [10, 25, 50]
        performance_results = []
        
        for size in test_sizes:
            # Clean up previous test
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            os.makedirs(self.temp_dir)
            
            self.create_large_test_project(size)
            
            start_time = time.time()
            results = self.auditor.scan_directory(self.temp_dir)
            scan_time = time.time() - start_time
            
            files_per_second = results.scanned_files / scan_time
            performance_results.append((size, files_per_second, scan_time))
        
        # Performance should scale reasonably with project size
        for i, (size, fps, time) in enumerate(performance_results):
            print(f"Size {size}: {fps:.2f} files/sec, {time:.2f}s total")
            
            # Performance should not degrade dramatically
            if i > 0:
                prev_fps = performance_results[i-1][1]
                # Allow some performance degradation but not more than 50%
                assert fps > prev_fps * 0.5, f"Performance degraded too much: {fps} vs {prev_fps}"


@pytest.mark.skipif(not PERFORMANCE_FEATURES_AVAILABLE, reason="Performance features not available")
class TestPerformanceEngine:
    """Test performance monitoring and optimization engine."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_performance_engine_initialization(self):
        """Test PerformanceEngine initialization."""
        engine = PerformanceEngine()
        
        assert engine is not None
        assert hasattr(engine, 'start_monitoring')
        assert hasattr(engine, 'stop_monitoring')
        assert hasattr(engine, 'get_metrics')
    
    def test_performance_metrics_collection(self):
        """Test performance metrics collection."""
        engine = PerformanceEngine()
        engine.start_monitoring()
        
        # Simulate some work
        time.sleep(0.1)
        
        metrics = engine.get_metrics()
        engine.stop_monitoring()
        
        assert isinstance(metrics, dict)
        assert 'cpu_usage' in metrics or 'memory_usage' in metrics
    
    def test_performance_optimizer_initialization(self):
        """Test PerformanceOptimizer initialization."""
        optimizer = PerformanceOptimizer()
        
        assert optimizer is not None
        assert hasattr(optimizer, 'optimize_scan_strategy')
        assert hasattr(optimizer, 'get_optimal_worker_count')
    
    def test_performance_optimizer_scan_strategy(self):
        """Test scan strategy optimization."""
        optimizer = PerformanceOptimizer()
        
        # Test with different project characteristics
        project_info = {
            'file_count': 1000,
            'average_file_size': 1024,
            'languages': ['python', 'java'],
            'directory_depth': 5
        }
        
        strategy = optimizer.optimize_scan_strategy(project_info)
        
        assert isinstance(strategy, dict)
        assert 'batch_size' in strategy or 'worker_count' in strategy
    
    def test_optimal_worker_count_calculation(self):
        """Test optimal worker count calculation."""
        optimizer = PerformanceOptimizer()
        
        worker_count = optimizer.get_optimal_worker_count()
        
        assert isinstance(worker_count, int)
        assert 1 <= worker_count <= 32  # Reasonable range


@pytest.mark.skipif(not PERFORMANCE_FEATURES_AVAILABLE, reason="Performance features not available")
class TestAdaptiveCaching:
    """Test adaptive caching functionality."""
    
    def test_adaptive_cache_initialization(self):
        """Test AdaptiveCache initialization."""
        cache = AdaptiveCache()
        
        assert cache is not None
        assert hasattr(cache, 'get')
        assert hasattr(cache, 'put')
        assert hasattr(cache, 'clear')
    
    def test_adaptive_cache_basic_operations(self):
        """Test basic cache operations."""
        cache = AdaptiveCache()
        
        # Test put and get
        cache.put('test_key', 'test_value')
        value = cache.get('test_key')
        
        assert value == 'test_value'
        
        # Test cache miss
        miss_value = cache.get('nonexistent_key')
        assert miss_value is None
    
    def test_adaptive_cache_with_scan_results(self):
        """Test caching with actual scan results."""
        cache = AdaptiveCache()
        
        # Create mock scan results
        vulnerabilities = [
            Vulnerability(
                file_path="/test/file.py",
                line_number=1,
                algorithm=CryptoAlgorithm.RSA,
                severity=Severity.HIGH,
                description="Test vulnerability",
                code_snippet="test code",
                recommendation="Test recommendation"
            )
        ]
        
        results = ScanResults(
            scan_path="/test",
            timestamp="2025-01-01 00:00:00",
            vulnerabilities=vulnerabilities,
            scanned_files=1,
            total_lines=100,
            scan_time=1.0,
            languages_detected=['python']
        )
        
        # Cache results
        cache_key = "scan_/test"
        cache.put(cache_key, results)
        
        # Retrieve results
        cached_results = cache.get(cache_key)
        assert cached_results is not None
        assert len(cached_results.vulnerabilities) == 1
    
    def test_cache_strategy_selection(self):
        """Test cache strategy selection based on access patterns."""
        cache = AdaptiveCache()
        
        # Simulate different access patterns
        cache.put('frequent_key', 'frequent_value')
        cache.put('rare_key', 'rare_value')
        
        # Frequent access
        for _ in range(10):
            cache.get('frequent_key')
        
        # Rare access
        cache.get('rare_key')
        
        # Strategy should adapt to access patterns
        strategy = cache.get_current_strategy()
        assert strategy is not None


@pytest.mark.skipif(not PERFORMANCE_FEATURES_AVAILABLE, reason="Performance features not available")
class TestAutoScaling:
    """Test auto-scaling functionality."""
    
    def test_auto_scaler_initialization(self):
        """Test AutoScaler initialization."""
        scaler = AutoScaler()
        
        assert scaler is not None
        assert hasattr(scaler, 'start_monitoring')
        assert hasattr(scaler, 'stop_monitoring')
        assert hasattr(scaler, 'scale_workers')
    
    def test_worker_pool_initialization(self):
        """Test WorkerPool initialization."""
        pool = WorkerPool(initial_size=4)
        
        assert pool is not None
        assert hasattr(pool, 'submit_task')
        assert hasattr(pool, 'scale_to')
    
    def test_worker_pool_scaling(self):
        """Test worker pool scaling operations."""
        pool = WorkerPool(initial_size=2)
        
        # Test scaling up
        pool.scale_to(4)
        assert pool.current_size >= 4
        
        # Test scaling down
        pool.scale_to(2)
        assert pool.current_size <= 2
    
    def test_global_auto_scaler(self):
        """Test global auto-scaler instance."""
        assert global_auto_scaler is not None
        assert hasattr(global_auto_scaler, 'start_monitoring')
        assert hasattr(global_auto_scaler, 'stop_monitoring')
    
    def test_auto_scaling_under_load(self):
        """Test auto-scaling behavior under load."""
        scaler = AutoScaler(
            min_workers=2,
            max_workers=8,
            scale_up_threshold=0.8,
            scale_down_threshold=0.3
        )
        
        scaler.start_monitoring()
        
        # Simulate high load
        def dummy_work():
            time.sleep(0.01)
            return "completed"
        
        # Submit multiple tasks to create load
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(dummy_work) for _ in range(20)]
            for future in as_completed(futures):
                future.result()
        
        # Allow time for scaling decisions
        time.sleep(0.1)
        
        scaler.stop_monitoring()
        
        # Verify scaler operated without errors
        assert True  # If we get here, no exceptions were raised


@pytest.mark.skipif(not PERFORMANCE_FEATURES_AVAILABLE, reason="Performance features not available")
class TestScalabilityEngine:
    """Test scalability engine functionality."""
    
    def test_scalability_engine_initialization(self):
        """Test ScalabilityEngine initialization."""
        engine = ScalabilityEngine()
        
        assert engine is not None
        assert hasattr(engine, 'analyze_scalability')
        assert hasattr(engine, 'optimize_for_scale')
    
    def test_scalability_analysis(self):
        """Test scalability analysis functionality."""
        engine = ScalabilityEngine()
        
        # Mock system characteristics
        system_info = {
            'cpu_cores': 8,
            'memory_gb': 16,
            'disk_type': 'SSD',
            'network_bandwidth': 1000  # Mbps
        }
        
        analysis = engine.analyze_scalability(system_info)
        
        assert isinstance(analysis, dict)
        assert 'recommendations' in analysis
    
    def test_scale_optimization(self):
        """Test optimization for scale."""
        engine = ScalabilityEngine()
        
        # Mock workload characteristics
        workload = {
            'files_to_scan': 10000,
            'average_file_size': 2048,
            'vulnerability_density': 0.1,
            'target_completion_time': 300  # 5 minutes
        }
        
        optimization = engine.optimize_for_scale(workload)
        
        assert isinstance(optimization, dict)
        assert 'worker_count' in optimization or 'batch_size' in optimization


class TestConcurrentScanning:
    """Test concurrent scanning capabilities."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def create_concurrent_test_project(self):
        """Create project structure for concurrent scanning tests."""
        # Create multiple directories with files
        for dir_num in range(5):
            dir_path = Path(self.temp_dir) / f"module_{dir_num}"
            dir_path.mkdir()
            
            for file_num in range(10):
                file_path = dir_path / f"crypto_{file_num}.py"
                content = f'''
import rsa
import hashlib

def generate_key_{file_num}():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

def hash_data(data):
    return hashlib.md5(data.encode()).hexdigest()
'''
                file_path.write_text(content, encoding='utf-8')
    
    def test_concurrent_directory_scanning(self):
        """Test scanning multiple directories concurrently."""
        self.create_concurrent_test_project()
        
        # Scan with standard auditor
        start_time = time.time()
        auditor = CryptoAuditor()
        results = auditor.scan_directory(self.temp_dir)
        sequential_time = time.time() - start_time
        
        # Verify results
        assert results.scanned_files >= 50  # 5 dirs * 10 files
        assert len(results.vulnerabilities) >= 100  # Multiple vulns per file
        
        print(f"Sequential scan: {sequential_time:.2f}s, "
              f"{results.scanned_files / sequential_time:.1f} files/sec")
    
    def test_thread_safe_vulnerability_collection(self):
        """Test thread-safe vulnerability collection."""
        self.create_concurrent_test_project()
        
        auditor = CryptoAuditor()
        
        # Perform multiple scans concurrently on same directory
        def scan_task():
            return auditor.scan_directory(self.temp_dir)
        
        # Run concurrent scans
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(scan_task) for _ in range(3)]
            results_list = [future.result() for future in as_completed(futures)]
        
        # All scans should complete successfully
        assert len(results_list) == 3
        for results in results_list:
            assert isinstance(results, ScanResults)
            assert results.scanned_files > 0
            assert len(results.vulnerabilities) > 0
    
    def test_memory_efficiency_concurrent_scanning(self):
        """Test memory efficiency during concurrent scanning."""
        import psutil
        
        self.create_concurrent_test_project()
        
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Perform concurrent scans
        def scan_task(scan_id):
            auditor = CryptoAuditor()
            return auditor.scan_directory(self.temp_dir)
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(scan_task, i) for i in range(4)]
            results_list = [future.result() for future in as_completed(futures)]
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable for concurrent operation
        assert memory_increase < 500  # Less than 500MB increase
        assert len(results_list) == 4
        
        print(f"Concurrent memory usage: {initial_memory:.1f}MB -> "
              f"{final_memory:.1f}MB (+{memory_increase:.1f}MB)")


class TestPerformanceIntegration:
    """Integration tests for performance features."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def create_enterprise_scale_project(self):
        """Create an enterprise-scale test project."""
        languages = {
            'python': '.py',
            'java': '.java',
            'javascript': '.js',
            'go': '.go',
            'cpp': '.cpp'
        }
        
        code_templates = {
            'python': '''
import rsa
from cryptography.hazmat.primitives.asymmetric import ec
import hashlib

class CryptoModule:
    def __init__(self):
        self.rsa_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.ec_key = ec.generate_private_key(ec.SECP256R1())
    
    def weak_hash(self, data):
        return hashlib.md5(data.encode()).hexdigest()
''',
            'java': '''
import java.security.KeyPairGenerator;
import java.security.MessageDigest;

public class CryptoService {
    public KeyPair generateRSAKey() {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }
    
    public KeyPair generateECKey() {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        return keyGen.generateKeyPair();
    }
}
''',
            'javascript': '''
const crypto = require('crypto');

function generateRSAKey() {
    return crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048
    });
}

function weakHash(data) {
    return crypto.createHash('md5').update(data).digest('hex');
}
''',
            'go': '''
package main

import (
    "crypto/rsa"
    "crypto/rand"
    "crypto/md5"
)

func generateRSAKey() (*rsa.PrivateKey, error) {
    return rsa.GenerateKey(rand.Reader, 2048)
}

func weakHash(data []byte) []byte {
    hasher := md5.New()
    hasher.Write(data)
    return hasher.Sum(nil)
}
''',
            'cpp': '''
#include <openssl/rsa.h>
#include <openssl/md5.h>

class CryptoManager {
public:
    RSA* generateRSAKey() {
        return RSA_generate_key(2048, RSA_F4, NULL, NULL);
    }
    
    void weakHash(const char* data, unsigned char* output) {
        MD5((unsigned char*)data, strlen(data), output);
    }
};
'''
        }
        
        # Create directory structure
        for module_num in range(20):  # 20 modules
            module_dir = Path(self.temp_dir) / f"module_{module_num}"
            module_dir.mkdir()
            
            for lang, ext in languages.items():
                for file_num in range(5):  # 5 files per language per module
                    file_path = module_dir / f"crypto_service_{file_num}{ext}"
                    content = code_templates.get(lang, '// No template')
                    file_path.write_text(content, encoding='utf-8')
    
    def test_enterprise_scale_performance(self):
        """Test performance at enterprise scale."""
        self.create_enterprise_scale_project()
        
        # Configure auditor for performance
        config = {
            'max_scan_time_seconds': 600,  # 10 minutes max
            'max_files_per_scan': 1000,
            'enable_performance_optimization': True
        }
        
        auditor = CryptoAuditor(config)
        
        start_time = time.time()
        results = auditor.scan_directory(self.temp_dir)
        total_time = time.time() - start_time
        
        # Performance expectations for enterprise scale
        assert total_time < 300  # Should complete in under 5 minutes
        assert results.scanned_files >= 400  # 20 modules * 5 languages * 5 files
        assert len(results.vulnerabilities) >= 1000  # Multiple vulns per file
        
        # Throughput should be reasonable
        throughput = results.scanned_files / total_time
        assert throughput > 2  # At least 2 files per second
        
        print(f"Enterprise scale: {results.scanned_files} files in {total_time:.2f}s "
              f"({throughput:.1f} files/sec)")
        print(f"Found {len(results.vulnerabilities)} vulnerabilities across "
              f"{len(results.languages_detected)} languages")
    
    def test_performance_with_caching(self):
        """Test performance improvement with caching."""
        self.create_enterprise_scale_project()
        
        # First scan (cold cache)
        auditor = CryptoAuditor({'enable_performance_optimization': True})
        
        start_time = time.time()
        results1 = auditor.scan_directory(self.temp_dir)
        cold_time = time.time() - start_time
        
        # Second scan (warm cache) - simulate by re-scanning same directory
        start_time = time.time()
        results2 = auditor.scan_directory(self.temp_dir, incremental=True)
        warm_time = time.time() - start_time
        
        # Warm cache should be faster (or at least not significantly slower)
        assert warm_time <= cold_time * 2  # Allow some overhead
        assert results2.scanned_files == results1.scanned_files
        
        print(f"Caching effect: {cold_time:.2f}s (cold) -> {warm_time:.2f}s (warm)")
    
    @pytest.mark.skipif(not PERFORMANCE_FEATURES_AVAILABLE, reason="Performance features not available")
    def test_auto_scaling_integration(self):
        """Test auto-scaling integration with real workload."""
        self.create_enterprise_scale_project()
        
        # Enable auto-scaling
        global_auto_scaler.start_monitoring()
        
        try:
            config = {
                'enable_performance_optimization': True,
                'auto_scaling': {
                    'enabled': True,
                    'min_workers': 2,
                    'max_workers': 8
                }
            }
            
            auditor = CryptoAuditor(config)
            results = auditor.scan_directory(self.temp_dir)
            
            # Auto-scaling should help with large workloads
            assert results.scanned_files > 0
            assert len(results.vulnerabilities) > 0
            
        finally:
            global_auto_scaler.stop_monitoring()


class TestResourceOptimization:
    """Test resource optimization and efficiency."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_memory_leak_prevention(self):
        """Test prevention of memory leaks during long-running scans."""
        import psutil
        import gc
        
        process = psutil.Process()
        
        # Perform multiple scan cycles
        memory_readings = []
        
        for cycle in range(5):
            # Create temporary files
            temp_files = []
            for i in range(20):
                file_path = Path(self.temp_dir) / f"temp_{cycle}_{i}.py"
                file_path.write_text("import rsa; rsa.generate_private_key()")
                temp_files.append(file_path)
            
            # Scan files
            auditor = CryptoAuditor()
            results = auditor.scan_directory(self.temp_dir)
            
            # Clean up files
            for file_path in temp_files:
                file_path.unlink()
            
            # Force garbage collection
            gc.collect()
            
            # Record memory usage
            memory_mb = process.memory_info().rss / 1024 / 1024
            memory_readings.append(memory_mb)
        
        # Memory should not continuously grow
        initial_memory = memory_readings[0]
        final_memory = memory_readings[-1]
        growth = final_memory - initial_memory
        
        assert growth < 100  # Less than 100MB growth over 5 cycles
        print(f"Memory stability: {initial_memory:.1f}MB -> {final_memory:.1f}MB "
              f"(+{growth:.1f}MB over 5 cycles)")
    
    def test_cpu_usage_efficiency(self):
        """Test CPU usage efficiency."""
        import psutil
        
        # Create test files
        for i in range(50):
            file_path = Path(self.temp_dir) / f"crypto_{i}.py"
            file_path.write_text("import rsa; rsa.generate_private_key()" * 10)
        
        # Monitor CPU usage during scan
        cpu_samples = []
        
        def cpu_monitor():
            for _ in range(20):  # Sample for 2 seconds
                cpu_samples.append(psutil.cpu_percent(interval=0.1))
        
        # Start CPU monitoring
        import threading
        monitor_thread = threading.Thread(target=cpu_monitor)
        monitor_thread.start()
        
        # Perform scan
        auditor = CryptoAuditor()
        results = auditor.scan_directory(self.temp_dir)
        
        monitor_thread.join()
        
        # Analyze CPU usage
        avg_cpu = sum(cpu_samples) / len(cpu_samples)
        max_cpu = max(cpu_samples)
        
        # CPU usage should be reasonable (not constantly at 100%)
        assert avg_cpu < 90  # Average CPU usage under 90%
        assert results.scanned_files >= 50
        
        print(f"CPU efficiency: {avg_cpu:.1f}% average, {max_cpu:.1f}% peak")
    
    def test_disk_io_optimization(self):
        """Test disk I/O optimization."""
        # Create files with varying sizes
        small_files = []
        large_files = []
        
        # Small files (typical source files)
        for i in range(30):
            file_path = Path(self.temp_dir) / f"small_{i}.py"
            content = "import rsa; rsa.generate_private_key()" * 5
            file_path.write_text(content)
            small_files.append(file_path)
        
        # Large files (less common but should be handled efficiently)
        for i in range(5):
            file_path = Path(self.temp_dir) / f"large_{i}.py"
            content = "import rsa; rsa.generate_private_key()" * 100
            file_path.write_text(content)
            large_files.append(file_path)
        
        # Scan with I/O optimization
        start_time = time.time()
        auditor = CryptoAuditor()
        results = auditor.scan_directory(self.temp_dir)
        scan_time = time.time() - start_time
        
        # Should handle both small and large files efficiently
        assert results.scanned_files == 35
        assert scan_time < 30  # Should complete quickly
        assert len(results.vulnerabilities) >= 35  # At least one per file
        
        print(f"I/O efficiency: {results.scanned_files} files in {scan_time:.2f}s")


if __name__ == "__main__":
    # Run tests with coverage reporting
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "--cov=src/pqc_migration_audit",
        "--cov-append",
        "--cov-report=term-missing",
        "--cov-report=html:htmlcov_gen3",
        "--cov-fail-under=80"
    ])