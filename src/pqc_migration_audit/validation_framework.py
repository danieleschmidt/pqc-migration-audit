"""Comprehensive validation framework for research operations and data integrity."""

import time
import json
import hashlib
import logging
from typing import Dict, List, Any, Optional, Callable, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
import threading
from pathlib import Path
import statistics


class ValidationLevel(Enum):
    """Validation intensity levels."""
    BASIC = "basic"
    STANDARD = "standard"
    COMPREHENSIVE = "comprehensive"
    RESEARCH_GRADE = "research_grade"


class ValidationResult(Enum):
    """Validation outcome types."""
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    ERROR = "error"


@dataclass
class ValidationCheck:
    """Individual validation check result."""
    check_name: str
    result: ValidationResult
    message: str
    severity: str
    data_checked: Any = None
    expected_value: Any = None
    actual_value: Any = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationReport:
    """Comprehensive validation report."""
    validation_id: str
    timestamp: str
    validation_level: ValidationLevel
    target_type: str
    target_identifier: str
    checks: List[ValidationCheck]
    overall_result: ValidationResult
    summary: Dict[str, int]
    recommendations: List[str]
    data_integrity_score: float
    confidence_level: float


class ResearchDataValidator:
    """Validator for research data integrity and quality."""
    
    def __init__(self, validation_level: ValidationLevel = ValidationLevel.STANDARD):
        self.validation_level = validation_level
        self.logger = logging.getLogger(__name__)
        self.validation_history: List[ValidationReport] = []
        
        # Validation thresholds
        self.thresholds = {
            'min_sample_size': 3,
            'max_coefficient_of_variation': 50.0,  # 50%
            'min_statistical_significance': 0.05,
            'min_reproducibility_score': 0.7,
            'max_outlier_percentage': 10.0,  # 10%
            'min_data_completeness': 0.95  # 95%
        }
    
    def validate_benchmark_result(self, benchmark_data: Dict[str, Any]) -> ValidationReport:
        """Validate benchmark result data integrity and quality."""
        validation_id = f"bench_val_{int(time.time())}_{hash(str(benchmark_data)) % 1000}"
        checks = []
        
        # Basic structure validation
        checks.extend(self._validate_benchmark_structure(benchmark_data))
        
        # Data quality validation
        checks.extend(self._validate_benchmark_data_quality(benchmark_data))
        
        # Statistical validation
        checks.extend(self._validate_benchmark_statistics(benchmark_data))
        
        # Performance validation
        checks.extend(self._validate_performance_metrics(benchmark_data))
        
        return self._compile_validation_report(
            validation_id, "benchmark_result", benchmark_data.get('algorithm', 'unknown'), checks
        )
    
    def validate_experiment_result(self, experiment_data: Dict[str, Any]) -> ValidationReport:
        """Validate experiment result comprehensiveness and reliability."""
        validation_id = f"exp_val_{int(time.time())}_{hash(str(experiment_data)) % 1000}"
        checks = []
        
        # Experimental design validation
        checks.extend(self._validate_experimental_design(experiment_data))
        
        # Statistical significance validation
        checks.extend(self._validate_statistical_analysis(experiment_data))
        
        # Reproducibility validation
        checks.extend(self._validate_reproducibility(experiment_data))
        
        # Research quality validation
        if self.validation_level in [ValidationLevel.COMPREHENSIVE, ValidationLevel.RESEARCH_GRADE]:
            checks.extend(self._validate_research_quality(experiment_data))
        
        return self._compile_validation_report(
            validation_id, "experiment_result", experiment_data.get('experiment_id', 'unknown'), checks
        )
    
    def validate_algorithm_discovery(self, discovery_data: Dict[str, Any]) -> ValidationReport:
        """Validate novel algorithm discovery results."""
        validation_id = f"disc_val_{int(time.time())}_{hash(str(discovery_data)) % 1000}"
        checks = []
        
        # Discovery completeness validation
        checks.extend(self._validate_discovery_completeness(discovery_data))
        
        # Theoretical validation
        checks.extend(self._validate_theoretical_models(discovery_data))
        
        # Innovation validation
        checks.extend(self._validate_innovation_metrics(discovery_data))
        
        return self._compile_validation_report(
            validation_id, "algorithm_discovery", "novel_discovery", checks
        )
    
    def _validate_benchmark_structure(self, data: Dict[str, Any]) -> List[ValidationCheck]:
        """Validate benchmark data structure."""
        checks = []
        
        required_fields = ['algorithm', 'mean_ops_per_sec', 'statistical_significance']
        for field in required_fields:
            if field not in data:
                checks.append(ValidationCheck(
                    f"required_field_{field}",
                    ValidationResult.FAIL,
                    f"Required field '{field}' missing from benchmark data",
                    "high"
                ))
            else:
                checks.append(ValidationCheck(
                    f"required_field_{field}",
                    ValidationResult.PASS,
                    f"Required field '{field}' present",
                    "low"
                ))
        
        # Check data types
        type_checks = [
            ('mean_ops_per_sec', (int, float)),
            ('runs', int),
            ('test_data_size', int)
        ]
        
        for field, expected_type in type_checks:
            if field in data:
                if isinstance(data[field], expected_type):
                    checks.append(ValidationCheck(
                        f"type_check_{field}",
                        ValidationResult.PASS,
                        f"Field '{field}' has correct type",
                        "low"
                    ))
                else:
                    checks.append(ValidationCheck(
                        f"type_check_{field}",
                        ValidationResult.FAIL,
                        f"Field '{field}' has incorrect type: {type(data[field])} (expected {expected_type})",
                        "medium"
                    ))
        
        return checks
    
    def _validate_benchmark_data_quality(self, data: Dict[str, Any]) -> List[ValidationCheck]:
        """Validate benchmark data quality metrics."""
        checks = []
        
        # Check for reasonable performance values
        if 'mean_ops_per_sec' in data:
            ops_per_sec = data['mean_ops_per_sec']
            if ops_per_sec <= 0:
                checks.append(ValidationCheck(
                    "performance_positive",
                    ValidationResult.FAIL,
                    f"Operations per second must be positive, got {ops_per_sec}",
                    "high"
                ))
            elif ops_per_sec > 1e9:  # 1 billion ops/sec seems unrealistic
                checks.append(ValidationCheck(
                    "performance_realistic",
                    ValidationResult.WARN,
                    f"Operations per second seems unrealistically high: {ops_per_sec}",
                    "medium"
                ))
            else:
                checks.append(ValidationCheck(
                    "performance_reasonable",
                    ValidationResult.PASS,
                    "Performance metrics are within reasonable range",
                    "low"
                ))
        
        # Check coefficient of variation
        if 'coefficient_of_variation' in data:
            cv = data['coefficient_of_variation']
            if cv > self.thresholds['max_coefficient_of_variation']:
                checks.append(ValidationCheck(
                    "coefficient_variation",
                    ValidationResult.WARN,
                    f"High coefficient of variation ({cv:.1f}%) indicates low reproducibility",
                    "medium"
                ))
            else:
                checks.append(ValidationCheck(
                    "coefficient_variation",
                    ValidationResult.PASS,
                    f"Coefficient of variation ({cv:.1f}%) is acceptable",
                    "low"
                ))
        
        # Check sample size
        if 'runs' in data:
            runs = data['runs']
            if runs < self.thresholds['min_sample_size']:
                checks.append(ValidationCheck(
                    "sample_size",
                    ValidationResult.WARN,
                    f"Sample size ({runs}) is below recommended minimum ({self.thresholds['min_sample_size']})",
                    "medium"
                ))
            else:
                checks.append(ValidationCheck(
                    "sample_size",
                    ValidationResult.PASS,
                    f"Sample size ({runs}) is adequate",
                    "low"
                ))
        
        return checks
    
    def _validate_benchmark_statistics(self, data: Dict[str, Any]) -> List[ValidationCheck]:
        """Validate statistical aspects of benchmark data."""
        checks = []
        
        if 'statistical_significance' in data:
            sig_data = data['statistical_significance']
            
            # Check statistical significance
            if 'significant' in sig_data:
                if sig_data['significant']:
                    checks.append(ValidationCheck(
                        "statistical_significance",
                        ValidationResult.PASS,
                        "Results show statistical significance",
                        "low"
                    ))
                else:
                    checks.append(ValidationCheck(
                        "statistical_significance",
                        ValidationResult.WARN,
                        "Results do not show statistical significance",
                        "medium"
                    ))
            
            # Check confidence intervals
            if 'confidence_interval' in sig_data:
                ci = sig_data['confidence_interval']
                if isinstance(ci, list) and len(ci) == 2:
                    if ci[0] < ci[1]:
                        checks.append(ValidationCheck(
                            "confidence_interval",
                            ValidationResult.PASS,
                            "Confidence interval is properly formatted",
                            "low"
                        ))
                    else:
                        checks.append(ValidationCheck(
                            "confidence_interval",
                            ValidationResult.FAIL,
                            "Confidence interval bounds are reversed",
                            "high"
                        ))
        
        return checks
    
    def _validate_performance_metrics(self, data: Dict[str, Any]) -> List[ValidationCheck]:
        """Validate performance-related metrics."""
        checks = []
        
        # Check for outliers in raw results
        if 'raw_results' in data:
            raw_results = data['raw_results']
            if isinstance(raw_results, list) and len(raw_results) > 1:
                values = [r.get('operations_per_second', 0) for r in raw_results if isinstance(r, dict)]
                
                if values:
                    outliers = self._detect_outliers(values)
                    outlier_percentage = (len(outliers) / len(values)) * 100
                    
                    if outlier_percentage > self.thresholds['max_outlier_percentage']:
                        checks.append(ValidationCheck(
                            "outlier_detection",
                            ValidationResult.WARN,
                            f"High percentage of outliers detected: {outlier_percentage:.1f}%",
                            "medium"
                        ))
                    else:
                        checks.append(ValidationCheck(
                            "outlier_detection",
                            ValidationResult.PASS,
                            f"Acceptable outlier percentage: {outlier_percentage:.1f}%",
                            "low"
                        ))
        
        return checks
    
    def _validate_experimental_design(self, data: Dict[str, Any]) -> List[ValidationCheck]:
        """Validate experimental design quality."""
        checks = []
        
        # Check for control groups or baselines
        if 'baseline_comparison' in data:
            checks.append(ValidationCheck(
                "baseline_present",
                ValidationResult.PASS,
                "Baseline comparison data is present",
                "low"
            ))
        else:
            checks.append(ValidationCheck(
                "baseline_present",
                ValidationResult.WARN,
                "No baseline comparison data found",
                "medium"
            ))
        
        # Check experiment duration
        if 'duration_seconds' in data:
            duration = data['duration_seconds']
            if duration < 1:
                checks.append(ValidationCheck(
                    "experiment_duration",
                    ValidationResult.WARN,
                    f"Very short experiment duration: {duration:.2f}s",
                    "medium"
                ))
            elif duration > 3600:  # 1 hour
                checks.append(ValidationCheck(
                    "experiment_duration",
                    ValidationResult.WARN,
                    f"Very long experiment duration: {duration:.2f}s",
                    "low"
                ))
            else:
                checks.append(ValidationCheck(
                    "experiment_duration",
                    ValidationResult.PASS,
                    f"Reasonable experiment duration: {duration:.2f}s",
                    "low"
                ))
        
        return checks
    
    def _validate_statistical_analysis(self, data: Dict[str, Any]) -> List[ValidationCheck]:
        """Validate statistical analysis quality."""
        checks = []
        
        if 'statistical_significance' in data:
            sig_data = data['statistical_significance']
            
            # Check p-value ranges
            for comparison, stats in sig_data.items():
                if isinstance(stats, dict) and 'p_value' in stats:
                    p_value = stats['p_value']
                    if 0 <= p_value <= 1:
                        checks.append(ValidationCheck(
                            f"p_value_range_{comparison}",
                            ValidationResult.PASS,
                            f"P-value for {comparison} is in valid range",
                            "low"
                        ))
                    else:
                        checks.append(ValidationCheck(
                            f"p_value_range_{comparison}",
                            ValidationResult.FAIL,
                            f"P-value for {comparison} is out of valid range: {p_value}",
                            "high"
                        ))
        
        return checks
    
    def _validate_reproducibility(self, data: Dict[str, Any]) -> List[ValidationCheck]:
        """Validate reproducibility metrics."""
        checks = []
        
        if 'reproducibility_score' in data:
            score = data['reproducibility_score']
            if score >= self.thresholds['min_reproducibility_score']:
                checks.append(ValidationCheck(
                    "reproducibility_score",
                    ValidationResult.PASS,
                    f"Good reproducibility score: {score:.3f}",
                    "low"
                ))
            elif score >= 0.5:
                checks.append(ValidationCheck(
                    "reproducibility_score",
                    ValidationResult.WARN,
                    f"Moderate reproducibility score: {score:.3f}",
                    "medium"
                ))
            else:
                checks.append(ValidationCheck(
                    "reproducibility_score",
                    ValidationResult.FAIL,
                    f"Low reproducibility score: {score:.3f}",
                    "high"
                ))
        
        return checks
    
    def _validate_research_quality(self, data: Dict[str, Any]) -> List[ValidationCheck]:
        """Validate research-grade quality standards."""
        checks = []
        
        # Check for peer review readiness
        if 'peer_review_ready' in data:
            if data['peer_review_ready']:
                checks.append(ValidationCheck(
                    "peer_review_readiness",
                    ValidationResult.PASS,
                    "Results meet peer review standards",
                    "low"
                ))
            else:
                checks.append(ValidationCheck(
                    "peer_review_readiness",
                    ValidationResult.WARN,
                    "Results do not meet peer review standards",
                    "medium"
                ))
        
        # Check for methodological documentation
        if 'raw_data' in data and isinstance(data['raw_data'], dict):
            if data['raw_data']:
                checks.append(ValidationCheck(
                    "methodology_documentation",
                    ValidationResult.PASS,
                    "Raw data and methodology documented",
                    "low"
                ))
        
        return checks
    
    def _validate_discovery_completeness(self, data: Dict[str, Any]) -> List[ValidationCheck]:
        """Validate completeness of algorithm discovery results."""
        checks = []
        
        required_sections = ['novel_concepts', 'theoretical_models', 'research_opportunities']
        for section in required_sections:
            if section in data and data[section]:
                checks.append(ValidationCheck(
                    f"discovery_section_{section}",
                    ValidationResult.PASS,
                    f"Discovery section '{section}' is complete",
                    "low"
                ))
            else:
                checks.append(ValidationCheck(
                    f"discovery_section_{section}",
                    ValidationResult.WARN,
                    f"Discovery section '{section}' is missing or empty",
                    "medium"
                ))
        
        return checks
    
    def _validate_theoretical_models(self, data: Dict[str, Any]) -> List[ValidationCheck]:
        """Validate theoretical model quality."""
        checks = []
        
        if 'theoretical_models' in data:
            models = data['theoretical_models']
            if isinstance(models, dict):
                for model_name, model_data in models.items():
                    if isinstance(model_data, dict):
                        required_metrics = ['theoretical_speed', 'estimated_key_size', 'security_confidence']
                        missing_metrics = [m for m in required_metrics if m not in model_data]
                        
                        if not missing_metrics:
                            checks.append(ValidationCheck(
                                f"model_completeness_{model_name}",
                                ValidationResult.PASS,
                                f"Model '{model_name}' has complete metrics",
                                "low"
                            ))
                        else:
                            checks.append(ValidationCheck(
                                f"model_completeness_{model_name}",
                                ValidationResult.WARN,
                                f"Model '{model_name}' missing metrics: {missing_metrics}",
                                "medium"
                            ))
        
        return checks
    
    def _validate_innovation_metrics(self, data: Dict[str, Any]) -> List[ValidationCheck]:
        """Validate innovation and novelty metrics."""
        checks = []
        
        if 'research_opportunities' in data:
            opportunities = data['research_opportunities']
            if isinstance(opportunities, list) and opportunities:
                high_priority_count = sum(1 for opp in opportunities if opp.get('priority_score', 0) > 0.7)
                
                if high_priority_count > 0:
                    checks.append(ValidationCheck(
                        "innovation_potential",
                        ValidationResult.PASS,
                        f"Identified {high_priority_count} high-priority research opportunities",
                        "low"
                    ))
                else:
                    checks.append(ValidationCheck(
                        "innovation_potential",
                        ValidationResult.WARN,
                        "No high-priority research opportunities identified",
                        "medium"
                    ))
        
        return checks
    
    def _detect_outliers(self, values: List[float]) -> List[float]:
        """Detect outliers using IQR method."""
        if len(values) < 4:
            return []
        
        sorted_values = sorted(values)
        n = len(sorted_values)
        q1_index = n // 4
        q3_index = 3 * n // 4
        
        q1 = sorted_values[q1_index]
        q3 = sorted_values[q3_index]
        iqr = q3 - q1
        
        lower_bound = q1 - 1.5 * iqr
        upper_bound = q3 + 1.5 * iqr
        
        return [v for v in values if v < lower_bound or v > upper_bound]
    
    def _compile_validation_report(self, validation_id: str, target_type: str, 
                                 target_identifier: str, checks: List[ValidationCheck]) -> ValidationReport:
        """Compile comprehensive validation report."""
        summary = {
            'pass': sum(1 for c in checks if c.result == ValidationResult.PASS),
            'warn': sum(1 for c in checks if c.result == ValidationResult.WARN),
            'fail': sum(1 for c in checks if c.result == ValidationResult.FAIL),
            'error': sum(1 for c in checks if c.result == ValidationResult.ERROR)
        }
        
        # Determine overall result
        if summary['fail'] > 0 or summary['error'] > 0:
            overall_result = ValidationResult.FAIL
        elif summary['warn'] > 0:
            overall_result = ValidationResult.WARN
        else:
            overall_result = ValidationResult.PASS
        
        # Calculate data integrity score
        total_checks = len(checks)
        if total_checks > 0:
            integrity_score = (summary['pass'] + 0.5 * summary['warn']) / total_checks
        else:
            integrity_score = 0.0
        
        # Calculate confidence level
        confidence_level = max(0.1, min(1.0, integrity_score))
        
        # Generate recommendations
        recommendations = self._generate_recommendations(checks, summary)
        
        report = ValidationReport(
            validation_id=validation_id,
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
            validation_level=self.validation_level,
            target_type=target_type,
            target_identifier=target_identifier,
            checks=checks,
            overall_result=overall_result,
            summary=summary,
            recommendations=recommendations,
            data_integrity_score=integrity_score,
            confidence_level=confidence_level
        )
        
        self.validation_history.append(report)
        return report
    
    def _generate_recommendations(self, checks: List[ValidationCheck], summary: Dict[str, int]) -> List[str]:
        """Generate actionable recommendations based on validation results."""
        recommendations = []
        
        # High-severity issues
        for check in checks:
            if check.result == ValidationResult.FAIL and check.severity == "high":
                recommendations.append(f"CRITICAL: {check.message}")
        
        # Medium-severity warnings
        warn_count = summary['warn']
        if warn_count > 3:
            recommendations.append(f"Consider addressing {warn_count} warnings to improve data quality")
        
        # Sample size recommendations
        sample_size_issues = [c for c in checks if 'sample_size' in c.check_name and c.result == ValidationResult.WARN]
        if sample_size_issues:
            recommendations.append("Increase sample size (number of runs) for more reliable results")
        
        # Reproducibility recommendations
        repro_issues = [c for c in checks if 'reproducibility' in c.check_name and c.result != ValidationResult.PASS]
        if repro_issues:
            recommendations.append("Improve experimental conditions to enhance reproducibility")
        
        return recommendations
    
    def get_validation_summary(self) -> Dict[str, Any]:
        """Get summary of all validation activities."""
        if not self.validation_history:
            return {'message': 'No validations performed yet'}
        
        recent_reports = self.validation_history[-10:]  # Last 10 reports
        
        return {
            'total_validations': len(self.validation_history),
            'validation_level': self.validation_level.value,
            'recent_results': {
                'pass': sum(1 for r in recent_reports if r.overall_result == ValidationResult.PASS),
                'warn': sum(1 for r in recent_reports if r.overall_result == ValidationResult.WARN),
                'fail': sum(1 for r in recent_reports if r.overall_result == ValidationResult.FAIL)
            },
            'average_integrity_score': statistics.mean(r.data_integrity_score for r in recent_reports),
            'average_confidence_level': statistics.mean(r.confidence_level for r in recent_reports),
            'common_issues': self._analyze_common_validation_issues(),
            'improvement_trends': self._analyze_improvement_trends()
        }
    
    def _analyze_common_validation_issues(self) -> Dict[str, int]:
        """Analyze most common validation issues."""
        issue_counts = {}
        
        for report in self.validation_history[-20:]:  # Last 20 reports
            for check in report.checks:
                if check.result in [ValidationResult.WARN, ValidationResult.FAIL]:
                    issue_type = check.check_name.split('_')[0]  # First part of check name
                    issue_counts[issue_type] = issue_counts.get(issue_type, 0) + 1
        
        return dict(sorted(issue_counts.items(), key=lambda x: x[1], reverse=True)[:5])
    
    def _analyze_improvement_trends(self) -> Dict[str, float]:
        """Analyze trends in validation quality over time."""
        if len(self.validation_history) < 5:
            return {'trend': 'insufficient_data'}
        
        recent_scores = [r.data_integrity_score for r in self.validation_history[-5:]]
        older_scores = [r.data_integrity_score for r in self.validation_history[-10:-5]] if len(self.validation_history) >= 10 else []
        
        if older_scores:
            recent_avg = statistics.mean(recent_scores)
            older_avg = statistics.mean(older_scores)
            
            return {
                'trend': 'improving' if recent_avg > older_avg else 'declining' if recent_avg < older_avg else 'stable',
                'recent_average': recent_avg,
                'older_average': older_avg,
                'improvement_rate': recent_avg - older_avg
            }
        else:
            return {'trend': 'insufficient_historical_data'}


# Global validator instance
global_validator = ResearchDataValidator(ValidationLevel.STANDARD)


def validated_operation(validation_type: str = "benchmark", validation_level: ValidationLevel = ValidationLevel.STANDARD):
    """Decorator for automatically validating operation results."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            
            # Validate result based on type
            validator = ResearchDataValidator(validation_level)
            
            if validation_type == "benchmark" and isinstance(result, dict):
                validation_report = validator.validate_benchmark_result(result)
            elif validation_type == "experiment" and isinstance(result, dict):
                validation_report = validator.validate_experiment_result(result)
            elif validation_type == "discovery" and isinstance(result, dict):
                validation_report = validator.validate_algorithm_discovery(result)
            else:
                return result
            
            # Add validation report to result
            if isinstance(result, dict):
                result['_validation_report'] = {
                    'validation_id': validation_report.validation_id,
                    'overall_result': validation_report.overall_result.value,
                    'data_integrity_score': validation_report.data_integrity_score,
                    'confidence_level': validation_report.confidence_level,
                    'summary': validation_report.summary,
                    'recommendations': validation_report.recommendations[:3]  # Top 3 recommendations
                }
            
            return result
        return wrapper
    return decorator