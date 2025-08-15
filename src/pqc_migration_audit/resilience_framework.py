"""Advanced resilience and error recovery framework."""

import time
import functools
import random
import threading
from typing import Dict, Any, List, Optional, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
from contextlib import contextmanager
import logging
import traceback
from pathlib import Path

from .exceptions import (
    PQCAuditException, ScanException, ValidationException, SecurityException,
    FileSystemException, ScanTimeoutException
)
from .logging_config import get_logger


class FailureMode(Enum):
    """Types of failure modes."""
    TRANSIENT = "transient"
    PERMANENT = "permanent"
    TIMEOUT = "timeout"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    SECURITY_VIOLATION = "security_violation"


class RecoveryStrategy(Enum):
    """Recovery strategies for different failure modes."""
    RETRY = "retry"
    FALLBACK = "fallback"
    CIRCUIT_BREAKER = "circuit_breaker"
    GRACEFUL_DEGRADATION = "graceful_degradation"
    FAIL_FAST = "fail_fast"


@dataclass
class FailureEvent:
    """Record of a failure event."""
    timestamp: float
    failure_mode: FailureMode
    exception: Exception
    context: Dict[str, Any] = field(default_factory=dict)
    recovery_attempted: bool = False
    recovery_successful: bool = False
    recovery_strategy: Optional[RecoveryStrategy] = None


@dataclass
class CircuitBreakerState:
    """Circuit breaker state management."""
    failure_count: int = 0
    last_failure_time: float = 0
    state: str = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
    failure_threshold: int = 5
    timeout_duration: float = 60.0
    success_threshold: int = 3
    consecutive_successes: int = 0


class ResilienceManager:
    """Advanced resilience and error recovery manager."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize resilience manager.
        
        Args:
            config: Resilience configuration
        """
        self.config = config or {}
        self.logger = get_logger('pqc_audit.resilience')
        
        # Configuration
        self.enable_auto_recovery = self.config.get('enable_auto_recovery', True)
        self.max_retry_attempts = self.config.get('max_retry_attempts', 3)
        self.retry_delay_base = self.config.get('retry_delay_base', 1.0)
        self.enable_circuit_breaker = self.config.get('enable_circuit_breaker', True)
        self.enable_graceful_degradation = self.config.get('enable_graceful_degradation', True)
        
        # State tracking
        self.failure_history: List[FailureEvent] = []
        self.circuit_breakers: Dict[str, CircuitBreakerState] = {}
        self.recovery_metrics: Dict[str, Any] = {
            'total_failures': 0,
            'successful_recoveries': 0,
            'failed_recoveries': 0,
            'circuit_breaker_trips': 0
        }
        
        # Thread safety
        self._lock = threading.RLock()
    
    @contextmanager
    def resilient_operation(self, operation_name: str, context: Optional[Dict[str, Any]] = None):
        """Context manager for resilient operations.
        
        Args:
            operation_name: Name of the operation
            context: Additional context information
        """
        start_time = time.time()
        context = context or {}
        
        try:
            # Check circuit breaker
            if self.enable_circuit_breaker:
                self._check_circuit_breaker(operation_name)
            
            yield
            
            # Record success
            if self.enable_circuit_breaker:
                self._record_success(operation_name)
            
            # Log successful operation
            self.logger.log_performance_metric(
                f"{operation_name}_duration",
                time.time() - start_time,
                "seconds"
            )
            
        except Exception as e:
            # Record failure
            failure_event = self._record_failure(operation_name, e, context)
            
            # Attempt recovery if enabled
            if self.enable_auto_recovery:
                recovered = self._attempt_recovery(operation_name, failure_event)
                if recovered:
                    return
            
            # If recovery failed or disabled, re-raise
            raise
    
    def retry_with_backoff(self, max_attempts: Optional[int] = None,
                          base_delay: Optional[float] = None,
                          backoff_factor: float = 2.0,
                          jitter: bool = True):
        """Decorator for retry with exponential backoff.
        
        Args:
            max_attempts: Maximum retry attempts
            base_delay: Base delay between retries
            backoff_factor: Exponential backoff factor
            jitter: Add random jitter to delays
        """
        max_attempts = max_attempts or self.max_retry_attempts
        base_delay = base_delay or self.retry_delay_base
        
        def decorator(func: Callable):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                last_exception = None
                
                for attempt in range(max_attempts):
                    try:
                        return func(*args, **kwargs)
                    except Exception as e:
                        last_exception = e
                        
                        # Don't retry certain types of exceptions
                        if isinstance(e, (SecurityException, ValidationException)):
                            raise
                        
                        if attempt < max_attempts - 1:
                            # Calculate delay with exponential backoff
                            delay = base_delay * (backoff_factor ** attempt)
                            
                            # Add jitter to prevent thundering herd
                            if jitter:
                                delay *= (0.5 + random.random() * 0.5)
                            
                            self.logger.logger.warning(
                                f"Attempt {attempt + 1} failed, retrying in {delay:.2f}s: {str(e)}"
                            )
                            time.sleep(delay)
                        else:
                            self.logger.logger.error(
                                f"All {max_attempts} attempts failed for {func.__name__}"
                            )
                
                # All attempts failed
                raise last_exception
            
            return wrapper
        return decorator
    
    def circuit_breaker(self, failure_threshold: int = 5,
                       timeout_duration: float = 60.0,
                       success_threshold: int = 3):
        """Circuit breaker decorator.
        
        Args:
            failure_threshold: Number of failures before opening circuit
            timeout_duration: Time to wait before trying again
            success_threshold: Consecutive successes needed to close circuit
        """
        def decorator(func: Callable):
            operation_name = f"{func.__module__}.{func.__name__}"
            
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                # Initialize circuit breaker if needed
                if operation_name not in self.circuit_breakers:
                    self.circuit_breakers[operation_name] = CircuitBreakerState(
                        failure_threshold=failure_threshold,
                        timeout_duration=timeout_duration,
                        success_threshold=success_threshold
                    )
                
                breaker = self.circuit_breakers[operation_name]
                
                # Check circuit state
                if breaker.state == "OPEN":
                    if time.time() - breaker.last_failure_time < breaker.timeout_duration:
                        raise ScanException(
                            f"Circuit breaker OPEN for {operation_name}",
                            error_code="CIRCUIT_BREAKER_OPEN"
                        )
                    else:
                        # Move to half-open state
                        breaker.state = "HALF_OPEN"
                        breaker.consecutive_successes = 0
                
                try:
                    result = func(*args, **kwargs)
                    
                    # Record success
                    with self._lock:
                        if breaker.state == "HALF_OPEN":
                            breaker.consecutive_successes += 1
                            if breaker.consecutive_successes >= breaker.success_threshold:
                                breaker.state = "CLOSED"
                                breaker.failure_count = 0
                                self.logger.logger.info(f"Circuit breaker CLOSED for {operation_name}")
                        elif breaker.state == "CLOSED":
                            breaker.failure_count = max(0, breaker.failure_count - 1)
                    
                    return result
                    
                except Exception as e:
                    # Record failure
                    with self._lock:
                        breaker.failure_count += 1
                        breaker.last_failure_time = time.time()
                        
                        if breaker.failure_count >= breaker.failure_threshold:
                            breaker.state = "OPEN"
                            self.recovery_metrics['circuit_breaker_trips'] += 1
                            self.logger.logger.warning(f"Circuit breaker OPEN for {operation_name}")
                    
                    raise
            
            return wrapper
        return decorator
    
    def graceful_degradation(self, fallback_func: Optional[Callable] = None,
                           degraded_result: Any = None):
        """Graceful degradation decorator.
        
        Args:
            fallback_func: Fallback function to call on failure
            degraded_result: Default result to return on failure
        """
        def decorator(func: Callable):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    # Log degradation
                    self.logger.logger.warning(
                        f"Graceful degradation activated for {func.__name__}: {str(e)}"
                    )
                    
                    # Try fallback function
                    if fallback_func:
                        try:
                            return fallback_func(*args, **kwargs)
                        except Exception as fallback_e:
                            self.logger.logger.error(
                                f"Fallback function also failed: {str(fallback_e)}"
                            )
                    
                    # Return degraded result
                    return degraded_result
            
            return wrapper
        return decorator
    
    def _check_circuit_breaker(self, operation_name: str):
        """Check circuit breaker state.
        
        Args:
            operation_name: Name of the operation
            
        Raises:
            ScanException: If circuit breaker is open
        """
        if operation_name not in self.circuit_breakers:
            return
        
        breaker = self.circuit_breakers[operation_name]
        
        if breaker.state == "OPEN":
            if time.time() - breaker.last_failure_time < breaker.timeout_duration:
                raise ScanException(
                    f"Circuit breaker is OPEN for {operation_name}",
                    error_code="CIRCUIT_BREAKER_OPEN",
                    details={
                        'failure_count': breaker.failure_count,
                        'last_failure_time': breaker.last_failure_time,
                        'timeout_duration': breaker.timeout_duration
                    }
                )
    
    def _record_success(self, operation_name: str):
        """Record successful operation.
        
        Args:
            operation_name: Name of the operation
        """
        if operation_name not in self.circuit_breakers:
            return
        
        breaker = self.circuit_breakers[operation_name]
        
        with self._lock:
            if breaker.state == "HALF_OPEN":
                breaker.consecutive_successes += 1
                if breaker.consecutive_successes >= breaker.success_threshold:
                    breaker.state = "CLOSED"
                    breaker.failure_count = 0
                    self.logger.logger.info(f"Circuit breaker CLOSED for {operation_name}")
    
    def _record_failure(self, operation_name: str, exception: Exception,
                       context: Dict[str, Any]) -> FailureEvent:
        """Record failure event.
        
        Args:
            operation_name: Name of the operation
            exception: Exception that occurred
            context: Additional context
            
        Returns:
            Failure event record
        """
        # Classify failure mode
        failure_mode = self._classify_failure(exception)
        
        # Create failure event
        failure_event = FailureEvent(
            timestamp=time.time(),
            failure_mode=failure_mode,
            exception=exception,
            context={**context, 'operation': operation_name}
        )
        
        # Record in history
        with self._lock:
            self.failure_history.append(failure_event)
            self.recovery_metrics['total_failures'] += 1
            
            # Limit history size
            if len(self.failure_history) > 1000:
                self.failure_history = self.failure_history[-500:]
        
        # Update circuit breaker
        if self.enable_circuit_breaker and operation_name in self.circuit_breakers:
            breaker = self.circuit_breakers[operation_name]
            breaker.failure_count += 1
            breaker.last_failure_time = time.time()
            
            if breaker.failure_count >= breaker.failure_threshold:
                breaker.state = "OPEN"
                self.recovery_metrics['circuit_breaker_trips'] += 1
        
        # Log failure
        self.logger.log_error(exception, {
            'operation': operation_name,
            'failure_mode': failure_mode.value,
            'context': context
        })
        
        return failure_event
    
    def _classify_failure(self, exception: Exception) -> FailureMode:
        """Classify type of failure.
        
        Args:
            exception: Exception that occurred
            
        Returns:
            Failure mode classification
        """
        if isinstance(exception, ScanTimeoutException):
            return FailureMode.TIMEOUT
        elif isinstance(exception, SecurityException):
            return FailureMode.SECURITY_VIOLATION
        elif isinstance(exception, FileSystemException):
            if "permission" in str(exception).lower():
                return FailureMode.PERMANENT
            else:
                return FailureMode.TRANSIENT
        elif isinstance(exception, (MemoryError, OSError)):
            return FailureMode.RESOURCE_EXHAUSTION
        elif isinstance(exception, ValidationException):
            return FailureMode.PERMANENT
        else:
            # Default to transient for unknown errors
            return FailureMode.TRANSIENT
    
    def _attempt_recovery(self, operation_name: str, failure_event: FailureEvent) -> bool:
        """Attempt to recover from failure.
        
        Args:
            operation_name: Name of the operation
            failure_event: Failure event to recover from
            
        Returns:
            True if recovery was successful
        """
        # Determine recovery strategy
        strategy = self._select_recovery_strategy(failure_event)
        
        if strategy == RecoveryStrategy.FAIL_FAST:
            return False
        
        failure_event.recovery_attempted = True
        failure_event.recovery_strategy = strategy
        
        try:
            if strategy == RecoveryStrategy.RETRY:
                # Simple retry with delay
                time.sleep(self.retry_delay_base)
                # Note: Actual retry would be handled by calling code
                return True
                
            elif strategy == RecoveryStrategy.GRACEFUL_DEGRADATION:
                # Log degradation and continue with limited functionality
                self.logger.logger.warning(
                    f"Graceful degradation activated for {operation_name}"
                )
                return True
                
            elif strategy == RecoveryStrategy.CIRCUIT_BREAKER:
                # Circuit breaker will handle this
                return False
                
            else:
                return False
                
        except Exception as recovery_error:
            self.logger.logger.error(
                f"Recovery attempt failed: {str(recovery_error)}"
            )
            self.recovery_metrics['failed_recoveries'] += 1
            return False
        
        finally:
            failure_event.recovery_successful = True
            self.recovery_metrics['successful_recoveries'] += 1
    
    def _select_recovery_strategy(self, failure_event: FailureEvent) -> RecoveryStrategy:
        """Select appropriate recovery strategy.
        
        Args:
            failure_event: Failure event to analyze
            
        Returns:
            Recommended recovery strategy
        """
        failure_mode = failure_event.failure_mode
        
        if failure_mode == FailureMode.SECURITY_VIOLATION:
            return RecoveryStrategy.FAIL_FAST
        elif failure_mode == FailureMode.PERMANENT:
            return RecoveryStrategy.FAIL_FAST
        elif failure_mode == FailureMode.TIMEOUT:
            return RecoveryStrategy.GRACEFUL_DEGRADATION
        elif failure_mode == FailureMode.RESOURCE_EXHAUSTION:
            return RecoveryStrategy.CIRCUIT_BREAKER
        elif failure_mode == FailureMode.TRANSIENT:
            return RecoveryStrategy.RETRY
        else:
            return RecoveryStrategy.GRACEFUL_DEGRADATION
    
    def get_resilience_metrics(self) -> Dict[str, Any]:
        """Get resilience metrics summary.
        
        Returns:
            Resilience metrics
        """
        circuit_breaker_summary = {}
        for name, breaker in self.circuit_breakers.items():
            circuit_breaker_summary[name] = {
                'state': breaker.state,
                'failure_count': breaker.failure_count,
                'last_failure_time': breaker.last_failure_time
            }
        
        # Failure mode distribution
        failure_modes = {}
        for event in self.failure_history:
            mode = event.failure_mode.value
            failure_modes[mode] = failure_modes.get(mode, 0) + 1
        
        # Recovery success rate
        recovery_attempts = sum(1 for event in self.failure_history if event.recovery_attempted)
        recovery_successes = sum(1 for event in self.failure_history if event.recovery_successful)
        recovery_rate = (recovery_successes / recovery_attempts * 100) if recovery_attempts > 0 else 0
        
        return {
            'metrics': self.recovery_metrics,
            'circuit_breakers': circuit_breaker_summary,
            'failure_modes': failure_modes,
            'recovery_success_rate': round(recovery_rate, 2),
            'recent_failures': len([
                event for event in self.failure_history 
                if time.time() - event.timestamp < 3600  # Last hour
            ]),
            'configuration': {
                'auto_recovery_enabled': self.enable_auto_recovery,
                'circuit_breaker_enabled': self.enable_circuit_breaker,
                'graceful_degradation_enabled': self.enable_graceful_degradation,
                'max_retry_attempts': self.max_retry_attempts
            }
        }