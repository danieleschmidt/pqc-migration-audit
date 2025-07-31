# Performance testing configuration for PQC Migration Audit
import pytest
import time
import psutil
import tempfile
from pathlib import Path
from contextlib import contextmanager

@pytest.fixture(scope="session")
def performance_config():
    """Global performance testing configuration."""
    return {
        "max_memory_mb": 256,
        "max_execution_time_seconds": 30,
        "large_repo_file_count": 1000,
        "benchmark_iterations": 10,
        "cpu_threshold_percent": 80
    }

@pytest.fixture
def large_test_repository():
    """Create a large test repository for performance testing."""
    temp_dir = tempfile.mkdtemp()
    repo_path = Path(temp_dir) / "large_repo"
    repo_path.mkdir()
    
    # Generate test files with various crypto patterns
    crypto_patterns = [
        "rsa.generate_private_key(65537, 2048)",
        "ecdsa.SigningKey.generate()",
        "hashlib.sha1(data).hexdigest()",
        "cryptography.fernet.Fernet.generate_key()"
    ]
    
    for i in range(1000):
        file_path = repo_path / f"file_{i:04d}.py"
        pattern = crypto_patterns[i % len(crypto_patterns)]
        file_path.write_text(f"""
# Generated test file {i}
import cryptography
import hashlib

def crypto_function_{i}():
    # Sample vulnerable pattern
    {pattern}
    return "test"
""")
    
    yield repo_path
    
    # Cleanup
    import shutil
    shutil.rmtree(temp_dir)

@contextmanager
def monitor_performance():
    """Context manager to monitor CPU and memory usage."""
    process = psutil.Process()
    start_time = time.perf_counter()
    start_memory = process.memory_info().rss / 1024 / 1024  # MB
    start_cpu = process.cpu_percent()
    
    yield
    
    end_time = time.perf_counter()
    end_memory = process.memory_info().rss / 1024 / 1024  # MB
    end_cpu = process.cpu_percent()
    
    execution_time = end_time - start_time
    memory_delta = end_memory - start_memory
    
    # Store metrics for reporting
    if not hasattr(monitor_performance, 'metrics'):
        monitor_performance.metrics = []
    
    monitor_performance.metrics.append({
        'execution_time': execution_time,
        'memory_used_mb': end_memory,
        'memory_delta_mb': memory_delta,
        'cpu_percent': end_cpu
    })

@pytest.fixture
def benchmark_reporter():
    """Fixture to collect and report benchmark results."""
    results = []
    
    def add_result(test_name, metrics):
        results.append({
            'test': test_name,
            'metrics': metrics
        })
    
    yield add_result
    
    # Generate performance report
    if results:
        print("\n" + "="*50)
        print("PERFORMANCE BENCHMARK RESULTS")
        print("="*50)
        
        for result in results:
            print(f"\nTest: {result['test']}")
            print(f"  Execution Time: {result['metrics']['execution_time']:.3f}s")
            print(f"  Memory Used: {result['metrics']['memory_used_mb']:.1f} MB")
            print(f"  CPU Usage: {result['metrics']['cpu_percent']:.1f}%")