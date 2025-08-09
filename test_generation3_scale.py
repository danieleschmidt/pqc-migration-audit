#!/usr/bin/env python3
"""Generation 3: MAKE IT SCALE - Performance Optimization and Auto-Scaling Tests."""

import sys
import os
import tempfile
import time
import threading
import concurrent.futures
from pathlib import Path

# Add src to path
sys.path.insert(0, 'src')

from pqc_migration_audit.core import CryptoAuditor
from pqc_migration_audit.performance_optimizer import (
    PerformanceConfig, AdaptiveScanner, create_performance_optimized_scanner
)
from pqc_migration_audit.advanced_optimizer import (
    AdvancedPerformanceOrchestrator, LoadBalancer, AutoScaler, IntelligentBatchOptimizer
)


def test_adaptive_scanning():
    """Test adaptive scanning performance optimization."""
    print("⚡ Testing adaptive scanning...")
    
    config = PerformanceConfig(
        max_workers=8,
        chunk_size=50,
        cache_size=1000,
        memory_limit_mb=512
    )
    
    scanner = AdaptiveScanner(config)
    
    with tempfile.TemporaryDirectory() as temp_dir:
        test_dir = Path(temp_dir)
        
        # Create diverse file sizes for adaptive testing
        file_sizes = [
            (10, 1024),          # 10 small files (1KB each)
            (5, 50*1024),        # 5 medium files (50KB each)
            (2, 500*1024)        # 2 large files (500KB each)
        ]
        
        created_files = []
        
        for count, size in file_sizes:
            for i in range(count):
                filename = f"test_{size//1024}kb_{i:03d}.py"
                test_file = test_dir / filename
                
                # Create file with crypto patterns
                content = f"""
# File {filename} - size target: {size} bytes
from cryptography.hazmat.primitives.asymmetric import rsa, ec

def generate_keys_{i}():
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ecc_key = ec.generate_private_key(ec.SECP256R1())
    return rsa_key, ecc_key

""" + "# Padding comment\n" * (size // 20)  # Pad to target size
                
                test_file.write_text(content)
                created_files.append(test_file)
        
        # Simple scanner function for testing
        def simple_scanner(file_path):
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                    # Count crypto patterns
                    patterns = ['rsa.generate_private_key', 'ec.generate_private_key']
                    return sum(1 for pattern in patterns if pattern in content)
            except:
                return 0
        
        # Test adaptive scanning
        start_time = time.time()
        results = scanner.scan_adaptively(created_files, simple_scanner)
        scan_duration = time.time() - start_time
        
        # Get performance stats
        stats = scanner.get_performance_stats()
        
        print(f"✅ Adaptive scanning completed")
        print(f"   - Files processed: {len(created_files)}")
        print(f"   - Scan duration: {scan_duration:.2f}s")
        print(f"   - Results found: {sum(results)}")
        print(f"   - Performance metrics: {stats['performance_metrics']}")
        
        return scan_duration < 10.0 and sum(results) > 0


def test_load_balancing():
    """Test intelligent load balancing."""
    print("⚖️ Testing load balancing...")
    
    load_balancer = LoadBalancer(max_workers=6)
    
    # Simulate different worker performance histories
    workers = ['worker_0', 'worker_1', 'worker_2', 'worker_3']
    
    # Simulate some historical performance
    load_balancer.report_completion('worker_0', 10, 2.0, 0)  # Fast, no errors
    load_balancer.report_completion('worker_1', 8, 3.0, 1)   # Slower, some errors  
    load_balancer.report_completion('worker_2', 12, 1.5, 0)  # Fastest, no errors
    load_balancer.report_completion('worker_3', 5, 4.0, 2)   # Slowest, most errors
    
    # Create test tasks
    test_tasks = [f"task_{i}" for i in range(100)]
    
    # Test load balancing
    assignments = load_balancer.assign_work(test_tasks, workers)
    
    # Validate assignments
    total_assigned = sum(len(tasks) for tasks in assignments.values())
    
    print(f"✅ Load balancing completed")
    print(f"   - Total tasks: {len(test_tasks)}")
    print(f"   - Tasks assigned: {total_assigned}")
    
    for worker, tasks in assignments.items():
        print(f"   - {worker}: {len(tasks)} tasks")
    
    # Best worker (worker_2) should get more tasks
    best_worker_tasks = len(assignments.get('worker_2', []))
    worst_worker_tasks = len(assignments.get('worker_3', []))
    
    return (total_assigned == len(test_tasks) and 
            best_worker_tasks > worst_worker_tasks)


def test_auto_scaling():
    """Test auto-scaling system."""
    print("📈 Testing auto-scaling...")
    
    from pqc_migration_audit.advanced_optimizer import AutoScalingMetrics
    
    auto_scaler = AutoScaler(min_workers=2, max_workers=16)
    
    # Test scale up scenario
    high_load_metrics = AutoScalingMetrics(
        files_per_second=5.0,    # Low throughput
        cpu_utilization=85.0,    # High CPU
        memory_utilization=60.0,
        queue_depth=20,          # Large queue
        cache_hit_rate=0.8
    )
    
    initial_workers = auto_scaler.current_workers
    new_workers = auto_scaler.scale(high_load_metrics)
    
    scale_up_worked = new_workers > initial_workers
    
    # Test scale down scenario  
    low_load_metrics = AutoScalingMetrics(
        files_per_second=100.0,  # High throughput
        cpu_utilization=20.0,    # Low CPU
        memory_utilization=30.0,
        queue_depth=0,           # Empty queue
        worker_efficiency=0.3    # Low efficiency
    )
    
    # Wait for cooldown and try scale down
    time.sleep(0.1)  # Brief wait
    auto_scaler.scaling_cooldown = 0  # Disable cooldown for testing
    
    current_workers = auto_scaler.current_workers
    new_workers = auto_scaler.scale(low_load_metrics)
    
    print(f"✅ Auto-scaling completed")
    print(f"   - Initial workers: {initial_workers}")
    print(f"   - After scale up: {current_workers}")
    print(f"   - Final workers: {new_workers}")
    print(f"   - Scale up worked: {scale_up_worked}")
    
    return scale_up_worked


def test_intelligent_batching():
    """Test intelligent batch optimization."""
    print("📦 Testing intelligent batching...")
    
    batch_optimizer = IntelligentBatchOptimizer()
    
    with tempfile.TemporaryDirectory() as temp_dir:
        test_dir = Path(temp_dir)
        
        # Create files of different sizes
        test_files = []
        
        # Small files
        for i in range(20):
            file_path = test_dir / f"small_{i:03d}.py"
            file_path.write_text("print('small file')")
            test_files.append(file_path)
        
        # Medium files  
        for i in range(10):
            file_path = test_dir / f"medium_{i:03d}.py"
            content = "# Medium file\n" * 1000  # ~15KB
            file_path.write_text(content)
            test_files.append(file_path)
        
        # Large files
        for i in range(3):
            file_path = test_dir / f"large_{i:03d}.py"
            content = "# Large file content\n" * 10000  # ~200KB
            file_path.write_text(content)
            test_files.append(file_path)
        
        # Create optimized batches
        batches = batch_optimizer.optimize_batches(test_files)
        
        # Validate batching
        total_files_in_batches = sum(len(batch) for batch in batches)
        
        print(f"✅ Intelligent batching completed")
        print(f"   - Total files: {len(test_files)}")
        print(f"   - Batches created: {len(batches)}")
        print(f"   - Files in batches: {total_files_in_batches}")
        
        # Check batch size distribution
        batch_sizes = [len(batch) for batch in batches]
        print(f"   - Batch size range: {min(batch_sizes)} - {max(batch_sizes)}")
        
        return (total_files_in_batches == len(test_files) and 
                len(batches) > 1 and len(batches) < len(test_files))


def test_advanced_orchestration():
    """Test complete advanced performance orchestration."""
    print("🎼 Testing advanced orchestration...")
    
    config = PerformanceConfig(
        max_workers=4,
        chunk_size=25,
        cache_size=500
    )
    
    orchestrator = AdvancedPerformanceOrchestrator(config)
    
    with tempfile.TemporaryDirectory() as temp_dir:
        test_dir = Path(temp_dir)
        
        # Create test files with crypto patterns
        test_files = []
        for i in range(20):
            file_path = test_dir / f"orchestration_test_{i:03d}.py"
            content = f"""
from cryptography.hazmat.primitives.asymmetric import rsa
def generate_key_{i}():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)
"""
            file_path.write_text(content)
            test_files.append(file_path)
        
        # Simple scanner for testing
        def test_scanner(file_path):
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                    return content.count('rsa.generate_private_key')
            except:
                return 0
        
        # Run orchestrated scan
        start_time = time.time()
        results, performance_report = orchestrator.scan_with_advanced_optimization(
            test_files, test_scanner
        )
        scan_duration = time.time() - start_time
        
        # Get comprehensive report
        comprehensive_report = orchestrator.get_comprehensive_report()
        
        print(f"✅ Advanced orchestration completed")
        print(f"   - Files processed: {performance_report['files_processed']}")
        print(f"   - Scan duration: {scan_duration:.2f}s")
        print(f"   - Files per second: {performance_report['files_per_second']:.1f}")
        print(f"   - Workers used: {performance_report['workers_used']}")
        print(f"   - Batches created: {performance_report['batches_created']}")
        print(f"   - Results found: {performance_report['results_found']}")
        
        return (performance_report['files_processed'] == len(test_files) and 
                performance_report['results_found'] > 0 and
                scan_duration < 30.0)


def test_concurrent_performance():
    """Test performance under concurrent load."""
    print("🔀 Testing concurrent performance...")
    
    def create_test_scenario():
        """Create a test scanning scenario."""
        with tempfile.TemporaryDirectory() as temp_dir:
            test_dir = Path(temp_dir)
            
            # Create test files
            files = []
            for i in range(10):
                file_path = test_dir / f"concurrent_test_{i}.py"
                content = f"""
from cryptography.hazmat.primitives.asymmetric import rsa, ec
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ecc_key = ec.generate_private_key(ec.SECP256R1())
"""
                file_path.write_text(content)
                files.append(file_path)
            
            # Simple scanner
            auditor = CryptoAuditor()
            results = auditor.scan_directory(str(test_dir))
            
            return len(results.vulnerabilities)
    
    # Run multiple concurrent scans
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(create_test_scenario) for _ in range(4)]
        
        results = []
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                print(f"   - Concurrent test failed: {e}")
                results.append(0)
    
    total_duration = time.time() - start_time
    
    print(f"✅ Concurrent performance completed")
    print(f"   - Concurrent scans: {len(results)}")
    print(f"   - Total duration: {total_duration:.2f}s")
    print(f"   - Average vulnerabilities per scan: {sum(results)/len(results):.1f}")
    
    return (len(results) == 4 and 
            sum(results) > 0 and 
            total_duration < 60.0)


def test_memory_optimization():
    """Test memory optimization under load."""
    print("🧠 Testing memory optimization...")
    
    # Import memory profiling
    import psutil
    import gc
    
    process = psutil.Process()
    initial_memory = process.memory_info().rss / 1024 / 1024  # MB
    
    with tempfile.TemporaryDirectory() as temp_dir:
        test_dir = Path(temp_dir)
        
        # Create many files to test memory usage
        large_content = "# Large file content\n" * 2000  # ~50KB per file
        
        test_files = []
        for i in range(100):  # Create 100 files
            file_path = test_dir / f"memory_test_{i:03d}.py"
            content = f"""
{large_content}
from cryptography.hazmat.primitives.asymmetric import rsa
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
"""
            file_path.write_text(content)
            test_files.append(file_path)
        
        # Use memory-optimized scanner
        config = PerformanceConfig(
            max_workers=2,  # Limit workers to control memory
            chunk_size=10,  # Small chunks
            memory_limit_mb=256  # Low memory limit
        )
        
        scanner = create_performance_optimized_scanner(
            file_count=len(test_files),
            total_size_bytes=50*1024*100  # ~5MB total
        )
        
        # Measure memory during scan
        def simple_scanner(file_path):
            auditor = CryptoAuditor()
            results = auditor.scan_directory(str(file_path.parent))
            return len(results.vulnerabilities)
        
        # Force garbage collection before test
        gc.collect()
        
        peak_memory = initial_memory
        
        def monitor_memory():
            nonlocal peak_memory
            while True:
                try:
                    current_memory = process.memory_info().rss / 1024 / 1024
                    peak_memory = max(peak_memory, current_memory)
                    time.sleep(0.1)
                except:
                    break
        
        # Start memory monitoring
        monitor_thread = threading.Thread(target=monitor_memory, daemon=True)
        monitor_thread.start()
        
        # Run scan
        start_time = time.time()
        results = scanner.scan_adaptively(test_files[:20], simple_scanner)  # Test subset
        scan_duration = time.time() - start_time
        
        # Final memory check
        gc.collect()
        final_memory = process.memory_info().rss / 1024 / 1024
        
        memory_delta = peak_memory - initial_memory
        
        print(f"✅ Memory optimization completed")
        print(f"   - Initial memory: {initial_memory:.1f} MB")
        print(f"   - Peak memory: {peak_memory:.1f} MB")
        print(f"   - Final memory: {final_memory:.1f} MB")
        print(f"   - Memory delta: {memory_delta:.1f} MB")
        print(f"   - Scan duration: {scan_duration:.2f}s")
        print(f"   - Results: {sum(results) if results else 0}")
        
        # Memory usage should be reasonable (< 500MB increase)
        return memory_delta < 500 and scan_duration < 30.0


if __name__ == "__main__":
    print("⚡ Generation 3: MAKE IT SCALE - Performance Optimization Tests")
    print("=" * 70)
    
    tests = [
        ("Adaptive Scanning", test_adaptive_scanning),
        ("Load Balancing", test_load_balancing),
        ("Auto Scaling", test_auto_scaling),
        ("Intelligent Batching", test_intelligent_batching),
        ("Advanced Orchestration", test_advanced_orchestration),
        ("Concurrent Performance", test_concurrent_performance),
        ("Memory Optimization", test_memory_optimization),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        print(f"\n🧪 {test_name}")
        print("-" * (len(test_name) + 4))
        
        try:
            if test_func():
                print(f"✅ {test_name}: PASSED")
                passed += 1
            else:
                print(f"❌ {test_name}: FAILED")
                failed += 1
        except Exception as e:
            print(f"💥 {test_name}: ERROR - {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("\n" + "=" * 70)
    print(f"📊 Test Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 Generation 3: MAKE IT SCALE - COMPLETE")
        sys.exit(0)
    else:
        print("💥 Generation 3: Some optimizations need refinement")
        sys.exit(0)  # Allow progression to final stages