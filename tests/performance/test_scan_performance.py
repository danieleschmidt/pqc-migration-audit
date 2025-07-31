# Performance tests for PQC audit scanning functionality
import pytest
import time
from pathlib import Path

@pytest.mark.performance
def test_large_repository_scan_time(large_test_repository, performance_config, benchmark_reporter):
    """Test scanning performance on large repositories."""
    from pqc_migration_audit.core import AuditEngine
    
    with monitor_performance() as metrics:
        audit_engine = AuditEngine()
        results = audit_engine.scan_directory(large_test_repository)
    
    # Performance assertions
    assert metrics['execution_time'] < performance_config['max_execution_time_seconds']
    assert metrics['memory_used_mb'] < performance_config['max_memory_mb']
    assert len(results) > 0  # Should find vulnerabilities
    
    benchmark_reporter('large_repository_scan', metrics)

@pytest.mark.performance
def test_memory_usage_scaling(performance_config):
    """Test memory usage scales reasonably with repository size."""
    import psutil
    from pqc_migration_audit.core import AuditEngine
    
    process = psutil.Process()
    baseline_memory = process.memory_info().rss / 1024 / 1024
    
    # Test with different repository sizes
    for size in [100, 500, 1000]:
        with temporary_repo(size) as repo_path:
            audit_engine = AuditEngine()
            
            start_memory = process.memory_info().rss / 1024 / 1024
            audit_engine.scan_directory(repo_path)
            end_memory = process.memory_info().rss / 1024 / 1024
            
            memory_growth = end_memory - baseline_memory
            
            # Memory should not grow excessively
            assert memory_growth < performance_config['max_memory_mb']
            
            # Memory growth should be reasonable relative to repo size
            memory_per_file = memory_growth / size
            assert memory_per_file < 1.0  # Less than 1MB per file

@pytest.mark.performance
@pytest.mark.parametrize("file_count", [50, 100, 500])
def test_scan_time_complexity(file_count, benchmark_reporter):
    """Test that scan time complexity is reasonable."""
    from pqc_migration_audit.core import AuditEngine
    
    with temporary_repo(file_count) as repo_path:
        audit_engine = AuditEngine()
        
        start_time = time.perf_counter()
        results = audit_engine.scan_directory(repo_path)
        end_time = time.perf_counter()
        
        execution_time = end_time - start_time
        time_per_file = execution_time / file_count
        
        # Should process at least 10 files per second
        assert time_per_file < 0.1
        
        metrics = {
            'execution_time': execution_time,
            'files_processed': file_count,
            'time_per_file': time_per_file,
            'vulnerabilities_found': len(results)
        }
        
        benchmark_reporter(f'scan_complexity_{file_count}_files', metrics)

@pytest.mark.performance
def test_concurrent_scan_performance():
    """Test performance with concurrent scanning operations."""
    import concurrent.futures
    from pqc_migration_audit.core import AuditEngine
    
    def scan_task(repo_path):
        audit_engine = AuditEngine()
        return audit_engine.scan_directory(repo_path)
    
    with temporary_repo(200) as repo_path:
        start_time = time.perf_counter()
        
        # Run 4 concurrent scans
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(scan_task, repo_path) for _ in range(4)]
            results = [future.result() for future in futures]
        
        end_time = time.perf_counter()
        
        # Concurrent execution should not be significantly slower than sequential
        execution_time = end_time - start_time  
        assert execution_time < 20  # Should complete within 20 seconds
        assert all(len(result) > 0 for result in results)  # All should find results

# Helper function
def temporary_repo(file_count):
    """Create temporary repository with specified number of files."""
    import tempfile
    import shutil
    from contextlib import contextmanager
    
    @contextmanager
    def _temp_repo():
        temp_dir = tempfile.mkdtemp()
        repo_path = Path(temp_dir) / "temp_repo"
        repo_path.mkdir()
        
        # Create test files with crypto patterns
        for i in range(file_count):
            file_path = repo_path / f"test_{i}.py"
            file_path.write_text(f"""
import rsa
key = rsa.generate_private_key(65537, 2048)
""")
        
        yield repo_path
        shutil.rmtree(temp_dir)
    
    return _temp_repo()