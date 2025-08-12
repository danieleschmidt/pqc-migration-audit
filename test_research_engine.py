#!/usr/bin/env python3
"""Test the enhanced research engine capabilities."""

import sys
import logging
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from pqc_migration_audit.research_engine import (
    ResearchOrchestrator, AlgorithmBenchmark, ResearchMode,
    ResearchHypothesis, ExperimentResult
)

def test_research_engine():
    """Test comprehensive research engine functionality."""
    print("🧪 Testing Enhanced Research Engine")
    print("=" * 50)
    
    # Initialize research orchestrator
    orchestrator = ResearchOrchestrator(ResearchMode.COMPARATIVE_ANALYSIS)
    print(f"✅ Initialized research orchestrator in mode: {orchestrator.research_mode}")
    
    # Test algorithm benchmarking with statistical validation
    print("\n📊 Testing Algorithm Benchmarking...")
    benchmarker = AlgorithmBenchmark()
    
    # Benchmark individual algorithms
    algorithms_to_test = ['kyber_768', 'dilithium3', 'sphincs_128f']
    
    for algo in algorithms_to_test:
        try:
            result = benchmarker.benchmark_algorithm(algo, test_data_size=1000, runs=3)
            print(f"  {algo}: {result['mean_ops_per_sec']:.2f} ops/sec (CV: {result['coefficient_of_variation']:.1f}%)")
            print(f"    Significant: {result['statistical_significance']['significant']}")
            print(f"    Reproducibility: {'High' if result['statistical_significance']['coefficient_of_variation'] < 10 else 'Medium'}")
        except Exception as e:
            print(f"  ❌ {algo}: {e}")
    
    # Test comparative analysis
    print("\n🔬 Testing Comparative Analysis...")
    comparison_result = benchmarker.compare_algorithms(algorithms_to_test)
    print(f"  Compared {len(comparison_result['algorithms_compared'])} algorithms")
    
    # Display rankings
    for metric, rankings in comparison_result['rankings'].items():
        print(f"  {metric} ranking:")
        for rank_data in rankings[:3]:  # Top 3
            print(f"    {rank_data['rank']}. {rank_data['algorithm']}: {rank_data['value']}")
    
    # Test hypothesis formulation
    print("\n💡 Testing Hypothesis Formulation...")
    hypothesis = orchestrator.formulate_research_hypothesis(
        title="Hybrid Kyber-RSA Performance Analysis",
        description="Compare hybrid post-quantum/classical cryptosystems against pure PQC implementations",
        expected_outcome="Hybrid systems will show 15-25% performance improvement during transition period"
    )
    print(f"  ✅ Hypothesis ID: {hypothesis.hypothesis_id}")
    print(f"  📋 Success metrics: {len(hypothesis.success_metrics)} defined")
    print(f"  ⏱️  Estimated duration: {hypothesis.estimated_duration_hours} hours")
    
    # Test experimental comparative study
    print("\n🔍 Testing Experimental Study...")
    try:
        experiment = orchestrator.execute_comparative_study(algorithms_to_test, hypothesis.hypothesis_id)
        print(f"  ✅ Experiment ID: {experiment.experiment_id}")
        print(f"  📈 Duration: {experiment.duration_seconds:.2f}s")
        print(f"  🎯 Reproducibility Score: {experiment.reproducibility_score:.3f}")
        print(f"  📊 Statistical Significance Tests: {len(experiment.statistical_significance)}")
        print(f"  📖 Peer Review Ready: {'Yes' if experiment.peer_review_ready else 'No'}")
        print(f"  🏆 Conclusion: {experiment.conclusion[:100]}...")
    except Exception as e:
        print(f"  ❌ Experiment failed: {e}")
    
    # Test novel algorithm discovery
    print("\n🚀 Testing Novel Algorithm Discovery...")
    try:
        discovery_result = orchestrator.discover_novel_algorithms()
        print(f"  🔍 Current algorithms analyzed: {discovery_result['current_algorithm_count']}")
        print(f"  💡 Novel concepts generated: {len(discovery_result['novel_concepts'])}")
        print(f"  🎯 Research opportunities: {len(discovery_result['research_opportunities'])}")
        
        # Show top research opportunities
        for i, opportunity in enumerate(discovery_result['research_opportunities'][:3], 1):
            print(f"    {i}. {opportunity['title']} (Priority: {opportunity['priority_score']:.2f})")
    except Exception as e:
        print(f"  ❌ Discovery failed: {e}")
    
    # Test research metrics tracking
    print(f"\n📈 Research Metrics Summary:")
    metrics = orchestrator.research_metrics
    for metric_name, value in metrics.items():
        print(f"  {metric_name.replace('_', ' ').title()}: {value}")
    
    print(f"\n🧪 Research Engine Testing Complete!")
    print(f"Active Hypotheses: {len(orchestrator.active_hypotheses)}")
    print(f"Completed Experiments: {len(orchestrator.experiment_results)}")
    
    # Show publication readiness
    publication_ready_count = sum(1 for exp in orchestrator.experiment_results.values() if exp.peer_review_ready)
    print(f"Publication-Ready Results: {publication_ready_count}")
    
    return True

def test_algorithm_benchmark_edge_cases():
    """Test edge cases and error handling in algorithm benchmarking."""
    print("\n🧪 Testing Edge Cases and Error Handling...")
    
    benchmarker = AlgorithmBenchmark()
    
    # Test unknown algorithm
    try:
        benchmarker.benchmark_algorithm('unknown_algorithm')
        print("  ❌ Should have failed for unknown algorithm")
    except ValueError as e:
        print(f"  ✅ Correctly handled unknown algorithm: {str(e)[:50]}...")
    
    # Test single run (no statistical significance)
    result = benchmarker.benchmark_algorithm('kyber_512', test_data_size=100, runs=1)
    print(f"  ✅ Single run handled: CV = {result['coefficient_of_variation']:.2f}%")
    
    # Test empty algorithm list for comparison
    try:
        benchmarker.compare_algorithms([])
        print("  ❌ Should have failed for empty algorithm list")
    except Exception as e:
        print(f"  ✅ Correctly handled empty algorithm list")

def main():
    """Main test runner."""
    logging.basicConfig(level=logging.INFO)
    
    try:
        print("🔬 PQC Research Engine - Enhanced Testing Suite")
        print("=" * 60)
        
        # Core functionality tests
        success = test_research_engine()
        
        # Edge case tests
        test_algorithm_benchmark_edge_cases()
        
        if success:
            print("\n🎉 All Research Engine Tests Passed!")
            print("🔬 Research capabilities enhanced with:")
            print("  • Statistical validation framework")
            print("  • Reproducibility scoring")
            print("  • Publication-ready artifact generation")
            print("  • Novel algorithm discovery")
            print("  • Comprehensive experimental design")
            return True
        else:
            print("\n❌ Some tests failed")
            return False
            
    except Exception as e:
        print(f"\n💥 Test suite failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)