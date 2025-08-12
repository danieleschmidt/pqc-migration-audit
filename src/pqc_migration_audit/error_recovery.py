"""Advanced error recovery and resilience mechanisms for PQC research operations."""

import time
import logging
import threading
import traceback
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps, lru_cache
import asyncio
import concurrent.futures
from contextlib import contextmanager
import json
import os
from pathlib import Path


class ErrorSeverity(Enum):
    """Error severity levels for research operations."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RecoveryStrategy(Enum):
    """Recovery strategies for different error types."""
    RETRY = "retry"
    FALLBACK = "fallback"
    SKIP = "skip"
    ABORT = "abort"
    PARTIAL_RECOVERY = "partial_recovery"


@dataclass
class ErrorContext:
    """Context information for error analysis and recovery."""
    error_id: str
    timestamp: str
    operation_type: str
    error_type: str
    error_message: str
    stack_trace: str
    severity: ErrorSeverity
    recovery_strategy: RecoveryStrategy
    retry_count: int = 0
    max_retries: int = 3
    context_data: Dict[str, Any] = field(default_factory=dict)
    recovery_successful: bool = False


class CircuitBreaker:
    """Circuit breaker pattern for preventing cascade failures."""
    
    def __init__(self, failure_threshold: int = 5, timeout: float = 60.0, name: str = "default"):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.name = name
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'CLOSED'  # CLOSED, OPEN, HALF_OPEN
        self.logger = logging.getLogger(__name__)
    
    def __call__(self, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            return self._call_with_circuit_breaker(func, *args, **kwargs)
        return wrapper
    
    def _call_with_circuit_breaker(self, func, *args, **kwargs):
        if self.state == 'OPEN':
            if self._should_attempt_reset():
                self.state = 'HALF_OPEN'
                self.logger.info(f"Circuit breaker {self.name} attempting reset")
            else:
                raise Exception(f"Circuit breaker {self.name} is OPEN - calls blocked")
        
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise
    
    def _should_attempt_reset(self) -> bool:
        return (self.last_failure_time is not None and 
                time.time() - self.last_failure_time >= self.timeout)
    
    def _on_success(self):
        self.failure_count = 0
        self.state = 'CLOSED'
        if self.state == 'HALF_OPEN':
            self.logger.info(f"Circuit breaker {self.name} reset to CLOSED")
    
    def _on_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = 'OPEN'
            self.logger.warning(f"Circuit breaker {self.name} opened due to {self.failure_count} failures")


class ErrorRecoveryManager:
    """Advanced error recovery manager with multiple strategies."""
    
    def __init__(self):
        self.error_history: List[ErrorContext] = []
        self.recovery_strategies: Dict[str, RecoveryStrategy] = {}
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.logger = logging.getLogger(__name__)
        self.recovery_stats = {
            'total_errors': 0,
            'successful_recoveries': 0,
            'failed_recoveries': 0,
            'circuit_breaks': 0
        }
    
    def register_circuit_breaker(self, operation_name: str, failure_threshold: int = 5, timeout: float = 60.0) -> CircuitBreaker:
        """Register a circuit breaker for an operation."""
        circuit_breaker = CircuitBreaker(failure_threshold, timeout, operation_name)
        self.circuit_breakers[operation_name] = circuit_breaker
        return circuit_breaker
    
    def robust_execution(self, operation_name: str, func: Callable, *args, **kwargs) -> Any:
        """Execute function with comprehensive error handling and recovery."""
        circuit_breaker = self.circuit_breakers.get(operation_name)
        
        if circuit_breaker:
            try:
                return circuit_breaker._call_with_circuit_breaker(func, *args, **kwargs)
            except Exception as e:
                return self._handle_error_with_recovery(operation_name, e, func, *args, **kwargs)
        else:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                return self._handle_error_with_recovery(operation_name, e, func, *args, **kwargs)
    
    def _handle_error_with_recovery(self, operation_name: str, error: Exception, func: Callable, *args, **kwargs) -> Any:
        """Handle error with appropriate recovery strategy."""
        error_context = self._create_error_context(operation_name, error, func, *args, **kwargs)
        self.error_history.append(error_context)
        self.recovery_stats['total_errors'] += 1
        
        recovery_strategy = self._determine_recovery_strategy(error_context)
        error_context.recovery_strategy = recovery_strategy
        
        self.logger.warning(f"Error in {operation_name}: {error}. Applying strategy: {recovery_strategy.value}")
        
        if recovery_strategy == RecoveryStrategy.RETRY:
            return self._retry_with_backoff(error_context, func, *args, **kwargs)
        elif recovery_strategy == RecoveryStrategy.FALLBACK:
            return self._execute_fallback(error_context, func, *args, **kwargs)
        elif recovery_strategy == RecoveryStrategy.PARTIAL_RECOVERY:
            return self._attempt_partial_recovery(error_context, func, *args, **kwargs)
        elif recovery_strategy == RecoveryStrategy.SKIP:
            self.logger.info(f"Skipping failed operation {operation_name}")
            return None
        else:  # ABORT
            self.recovery_stats['failed_recoveries'] += 1
            raise error
    
    def _create_error_context(self, operation_name: str, error: Exception, func: Callable, *args, **kwargs) -> ErrorContext:
        """Create detailed error context for analysis."""
        error_id = f"err_{int(time.time())}_{hash(str(error)) % 10000}"
        severity = self._assess_error_severity(error, operation_name)
        
        return ErrorContext(
            error_id=error_id,
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
            operation_type=operation_name,
            error_type=type(error).__name__,
            error_message=str(error),
            stack_trace=traceback.format_exc(),
            severity=severity,
            recovery_strategy=RecoveryStrategy.RETRY,  # Default, will be updated
            context_data={
                'function_name': func.__name__,
                'args_count': len(args),
                'kwargs_keys': list(kwargs.keys())
            }
        )
    
    def _assess_error_severity(self, error: Exception, operation_name: str) -> ErrorSeverity:
        """Assess the severity of an error."""
        critical_operations = ['database_write', 'security_validation', 'core_algorithm']
        critical_errors = ['SecurityException', 'DatabaseException', 'SystemExit', 'KeyboardInterrupt']
        
        if operation_name in critical_operations or type(error).__name__ in critical_errors:
            return ErrorSeverity.CRITICAL
        elif isinstance(error, (ValueError, TypeError, KeyError)):
            return ErrorSeverity.HIGH
        elif isinstance(error, (ConnectionError, TimeoutError)):
            return ErrorSeverity.MEDIUM
        else:
            return ErrorSeverity.LOW
    
    def _determine_recovery_strategy(self, error_context: ErrorContext) -> RecoveryStrategy:
        """Determine the appropriate recovery strategy based on error context."""
        if error_context.severity == ErrorSeverity.CRITICAL:
            return RecoveryStrategy.ABORT
        elif error_context.severity == ErrorSeverity.HIGH:
            return RecoveryStrategy.FALLBACK if error_context.retry_count >= 2 else RecoveryStrategy.RETRY
        elif error_context.severity == ErrorSeverity.MEDIUM:
            return RecoveryStrategy.PARTIAL_RECOVERY if error_context.retry_count >= 1 else RecoveryStrategy.RETRY
        else:  # LOW
            return RecoveryStrategy.SKIP if error_context.retry_count >= 3 else RecoveryStrategy.RETRY
    
    def _retry_with_backoff(self, error_context: ErrorContext, func: Callable, *args, **kwargs) -> Any:
        """Retry operation with exponential backoff."""
        if error_context.retry_count >= error_context.max_retries:
            self.recovery_stats['failed_recoveries'] += 1
            raise Exception(f"Max retries ({error_context.max_retries}) exceeded for {error_context.operation_type}")
        
        error_context.retry_count += 1
        backoff_time = min(2 ** error_context.retry_count, 30)  # Cap at 30 seconds
        
        self.logger.info(f"Retrying {error_context.operation_type} (attempt {error_context.retry_count}) after {backoff_time}s")
        time.sleep(backoff_time)
        
        try:
            result = func(*args, **kwargs)
            error_context.recovery_successful = True
            self.recovery_stats['successful_recoveries'] += 1
            return result
        except Exception as e:
            # Recursive call for additional retries
            return self._handle_error_with_recovery(error_context.operation_type, e, func, *args, **kwargs)
    
    def _execute_fallback(self, error_context: ErrorContext, func: Callable, *args, **kwargs) -> Any:
        """Execute fallback strategy for failed operations."""
        fallback_strategies = {
            'algorithm_benchmark': self._fallback_simple_benchmark,
            'comparative_analysis': self._fallback_basic_comparison,
            'novel_discovery': self._fallback_template_generation,
            'statistical_analysis': self._fallback_basic_stats
        }
        
        fallback_func = fallback_strategies.get(error_context.operation_type)
        
        if fallback_func:
            try:
                self.logger.info(f"Executing fallback for {error_context.operation_type}")
                result = fallback_func(*args, **kwargs)
                error_context.recovery_successful = True
                self.recovery_stats['successful_recoveries'] += 1
                return result
            except Exception as fallback_error:
                self.logger.error(f"Fallback failed for {error_context.operation_type}: {fallback_error}")
                self.recovery_stats['failed_recoveries'] += 1
                return None
        else:
            self.logger.warning(f"No fallback strategy available for {error_context.operation_type}")
            self.recovery_stats['failed_recoveries'] += 1
            return None
    
    def _attempt_partial_recovery(self, error_context: ErrorContext, func: Callable, *args, **kwargs) -> Any:
        """Attempt partial recovery by modifying operation parameters."""
        try:
            # Attempt with reduced complexity or scope
            modified_kwargs = kwargs.copy()
            
            # Reduce test data size if applicable
            if 'test_data_size' in modified_kwargs:
                modified_kwargs['test_data_size'] = max(100, modified_kwargs['test_data_size'] // 2)
            
            # Reduce number of runs if applicable
            if 'runs' in modified_kwargs:
                modified_kwargs['runs'] = max(1, modified_kwargs['runs'] // 2)
            
            # Reduce algorithm list size if applicable
            if 'algorithms' in modified_kwargs and isinstance(modified_kwargs['algorithms'], list):
                modified_kwargs['algorithms'] = modified_kwargs['algorithms'][:max(1, len(modified_kwargs['algorithms']) // 2)]
            
            self.logger.info(f"Attempting partial recovery for {error_context.operation_type} with reduced parameters")
            result = func(*args, **modified_kwargs)
            error_context.recovery_successful = True
            self.recovery_stats['successful_recoveries'] += 1
            
            # Add metadata about partial recovery
            if isinstance(result, dict):
                result['_partial_recovery'] = True
                result['_recovery_modifications'] = {
                    'original_params': kwargs,
                    'modified_params': modified_kwargs,
                    'recovery_reason': error_context.error_message
                }
            
            return result
        except Exception as partial_error:
            self.logger.error(f"Partial recovery failed for {error_context.operation_type}: {partial_error}")
            self.recovery_stats['failed_recoveries'] += 1
            return None
    
    # Fallback strategy implementations
    def _fallback_simple_benchmark(self, algorithm_name: str, *args, **kwargs) -> Dict[str, Any]:
        """Simple fallback benchmark implementation."""
        return {
            'algorithm': algorithm_name,
            'fallback_mode': True,
            'estimated_performance': 1000,  # Conservative estimate
            'confidence': 0.3,
            'note': 'Fallback benchmark - results are estimates only'
        }
    
    def _fallback_basic_comparison(self, algorithms: List[str], *args, **kwargs) -> Dict[str, Any]:
        """Basic fallback comparison implementation."""
        return {
            'algorithms_compared': algorithms,
            'fallback_mode': True,
            'rankings': {algo: i+1 for i, algo in enumerate(algorithms)},
            'confidence': 0.2,
            'note': 'Fallback comparison - results are based on theoretical estimates'
        }
    
    def _fallback_template_generation(self, *args, **kwargs) -> Dict[str, Any]:
        """Fallback novel algorithm generation using templates."""
        return {
            'novel_concepts': [
                {
                    'name': 'hybrid_fallback_concept',
                    'description': 'Template-based hybrid algorithm concept',
                    'confidence': 0.1,
                    'fallback_mode': True
                }
            ],
            'note': 'Fallback discovery - results are template-based'
        }
    
    def _fallback_basic_stats(self, data: Any, *args, **kwargs) -> Dict[str, Any]:
        """Basic fallback statistical analysis."""
        return {
            'statistical_analysis': 'fallback',
            'confidence': 0.1,
            'significant': False,
            'note': 'Fallback statistics - unable to perform full analysis'
        }
    
    def get_recovery_metrics(self) -> Dict[str, Any]:
        """Get comprehensive recovery and resilience metrics."""
        total_operations = self.recovery_stats['total_errors']
        
        return {
            'recovery_stats': self.recovery_stats,
            'success_rate': self.recovery_stats['successful_recoveries'] / max(1, total_operations),
            'error_rate': total_operations / max(1, total_operations + self.recovery_stats['successful_recoveries']),
            'circuit_breaker_status': {name: cb.state for name, cb in self.circuit_breakers.items()},
            'recent_errors': self.error_history[-10:],  # Last 10 errors
            'error_patterns': self._analyze_error_patterns(),
            'recommendations': self._generate_recovery_recommendations()
        }
    
    def _analyze_error_patterns(self) -> Dict[str, Any]:
        """Analyze patterns in error history."""
        if not self.error_history:
            return {}
        
        error_types = {}
        operation_errors = {}
        
        for error in self.error_history:
            error_types[error.error_type] = error_types.get(error.error_type, 0) + 1
            operation_errors[error.operation_type] = operation_errors.get(error.operation_type, 0) + 1
        
        return {
            'most_common_error_types': sorted(error_types.items(), key=lambda x: x[1], reverse=True)[:5],
            'most_error_prone_operations': sorted(operation_errors.items(), key=lambda x: x[1], reverse=True)[:5],
            'recovery_success_rate_by_strategy': self._calculate_recovery_success_by_strategy()
        }
    
    def _calculate_recovery_success_by_strategy(self) -> Dict[str, float]:
        """Calculate recovery success rate by strategy."""
        strategy_stats = {}
        
        for error in self.error_history:
            strategy = error.recovery_strategy.value
            if strategy not in strategy_stats:
                strategy_stats[strategy] = {'total': 0, 'successful': 0}
            
            strategy_stats[strategy]['total'] += 1
            if error.recovery_successful:
                strategy_stats[strategy]['successful'] += 1
        
        return {
            strategy: stats['successful'] / max(1, stats['total'])
            for strategy, stats in strategy_stats.items()
        }
    
    def _generate_recovery_recommendations(self) -> List[str]:
        """Generate recommendations based on error patterns."""
        recommendations = []
        
        if len(self.error_history) > 10:
            recent_errors = self.error_history[-10:]
            frequent_operations = {}
            
            for error in recent_errors:
                op = error.operation_type
                frequent_operations[op] = frequent_operations.get(op, 0) + 1
            
            for op, count in frequent_operations.items():
                if count >= 3:
                    recommendations.append(f"Consider reviewing {op} implementation - {count} errors in recent history")
        
        # Circuit breaker recommendations
        for name, cb in self.circuit_breakers.items():
            if cb.state == 'OPEN':
                recommendations.append(f"Circuit breaker '{name}' is open - investigate underlying issues")
        
        # Recovery rate recommendations
        success_rate = self.recovery_stats['successful_recoveries'] / max(1, self.recovery_stats['total_errors'])
        if success_rate < 0.7:
            recommendations.append(f"Recovery success rate is {success_rate:.1%} - consider implementing more fallback strategies")
        
        return recommendations


# Global error recovery manager instance
recovery_manager = ErrorRecoveryManager()


def resilient_operation(operation_name: str, circuit_breaker: bool = True, max_retries: int = 3):
    """Decorator for making operations resilient with error recovery."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if circuit_breaker:
                cb = recovery_manager.register_circuit_breaker(operation_name, failure_threshold=5, timeout=60.0)
            
            return recovery_manager.robust_execution(operation_name, func, *args, **kwargs)
        return wrapper
    return decorator


@contextmanager
def resilient_context(operation_name: str):
    """Context manager for resilient operations."""
    try:
        yield
    except Exception as e:
        recovery_manager._handle_error_with_recovery(operation_name, e, lambda: None)
        raise