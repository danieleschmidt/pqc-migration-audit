"""Advanced resilience and fault tolerance system for PQC Migration Audit."""

import time
import threading
import logging
import asyncio
import json
import hashlib
import queue
import statistics
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, Future
from functools import wraps
import contextlib
import inspect
import traceback


class ResilienceStrategy(Enum):
    """Resilience strategy types."""
    CIRCUIT_BREAKER = "circuit_breaker"
    RETRY_EXPONENTIAL = "retry_exponential"
    RETRY_LINEAR = "retry_linear"
    TIMEOUT = "timeout"
    BULKHEAD = "bulkhead"
    RATE_LIMITER = "rate_limiter"
    FALLBACK = "fallback"
    CACHE = "cache"


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Circuit is open, calls fail fast
    HALF_OPEN = "half_open"  # Testing if service has recovered


@dataclass
class ResilienceConfig:
    """Configuration for resilience strategies."""
    strategy: ResilienceStrategy
    failure_threshold: int = 5
    success_threshold: int = 3
    timeout_seconds: float = 30.0
    recovery_timeout_seconds: float = 60.0
    max_retries: int = 3
    retry_delay_seconds: float = 1.0
    exponential_base: float = 2.0
    max_delay_seconds: float = 300.0
    rate_limit_per_second: float = 10.0
    bulkhead_max_concurrent: int = 10
    cache_ttl_seconds: float = 300.0
    enabled: bool = True


@dataclass
class ResilienceMetrics:
    """Metrics for resilience monitoring."""
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    circuit_breaker_trips: int = 0
    retries_attempted: int = 0
    fallback_activations: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    avg_response_time_ms: float = 0.0
    last_failure_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None


class CircuitBreaker:
    """Advanced circuit breaker with half-open state and metrics."""
    
    def __init__(self, config: ResilienceConfig):
        self.config = config
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None
        self.last_state_change = datetime.now()
        self.metrics = ResilienceMetrics()
        self._lock = threading.RLock()
        self.logger = logging.getLogger(f"{__name__}.circuit_breaker")
    
    def call(self, func: Callable, *args, **kwargs):
        """Execute function through circuit breaker."""
        with self._lock:
            if not self.config.enabled:
                return func(*args, **kwargs)
            
            self.metrics.total_calls += 1
            
            # Check if circuit should transition from OPEN to HALF_OPEN
            if self.state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self._transition_to_half_open()
                else:
                    self.metrics.failed_calls += 1
                    raise CircuitBreakerOpenException(
                        f"Circuit breaker is OPEN. Last failure: {self.last_failure_time}"
                    )
            
            # Execute the function
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                self._on_success(time.time() - start_time)
                return result
            
            except Exception as e:
                self._on_failure(e, time.time() - start_time)
                raise
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset."""
        if self.last_failure_time is None:
            return True
        
        time_since_failure = datetime.now() - self.last_failure_time
        return time_since_failure.total_seconds() >= self.config.recovery_timeout_seconds
    
    def _transition_to_half_open(self):
        """Transition circuit breaker to half-open state."""
        self.state = CircuitState.HALF_OPEN
        self.success_count = 0
        self.last_state_change = datetime.now()
        self.logger.info("Circuit breaker transitioned to HALF_OPEN")
    
    def _on_success(self, response_time_ms: float):
        """Handle successful execution."""
        self.metrics.successful_calls += 1
        self.metrics.last_success_time = datetime.now()
        
        # Update average response time
        self._update_avg_response_time(response_time_ms * 1000)  # Convert to ms
        
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.success_threshold:
                self._transition_to_closed()
        elif self.state == CircuitState.OPEN:
            # This shouldn't happen, but handle gracefully
            self._transition_to_closed()
    
    def _on_failure(self, exception: Exception, response_time_ms: float):
        """Handle failed execution."""
        self.metrics.failed_calls += 1
        self.metrics.last_failure_time = datetime.now()
        self.last_failure_time = datetime.now()
        
        # Update average response time
        self._update_avg_response_time(response_time_ms * 1000)
        
        if self.state == CircuitState.CLOSED:
            self.failure_count += 1
            if self.failure_count >= self.config.failure_threshold:
                self._transition_to_open()
        elif self.state == CircuitState.HALF_OPEN:
            self._transition_to_open()
    
    def _transition_to_closed(self):
        """Transition circuit breaker to closed state."""
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_state_change = datetime.now()
        self.logger.info("Circuit breaker transitioned to CLOSED")
    
    def _transition_to_open(self):
        """Transition circuit breaker to open state."""
        self.state = CircuitState.OPEN
        self.metrics.circuit_breaker_trips += 1
        self.last_state_change = datetime.now()
        self.logger.warning(
            f"Circuit breaker transitioned to OPEN after {self.failure_count} failures"
        )
    
    def _update_avg_response_time(self, response_time_ms: float):
        """Update average response time using exponential moving average."""
        if self.metrics.avg_response_time_ms == 0:
            self.metrics.avg_response_time_ms = response_time_ms
        else:
            # Exponential moving average with alpha = 0.1
            alpha = 0.1
            self.metrics.avg_response_time_ms = (
                alpha * response_time_ms + 
                (1 - alpha) * self.metrics.avg_response_time_ms
            )
    
    def get_status(self) -> Dict[str, Any]:
        """Get circuit breaker status and metrics."""
        return {
            'state': self.state.value,
            'failure_count': self.failure_count,
            'success_count': self.success_count,
            'last_failure_time': self.last_failure_time.isoformat() if self.last_failure_time else None,
            'last_state_change': self.last_state_change.isoformat(),
            'metrics': {
                'total_calls': self.metrics.total_calls,
                'successful_calls': self.metrics.successful_calls,
                'failed_calls': self.metrics.failed_calls,
                'success_rate': (
                    self.metrics.successful_calls / max(1, self.metrics.total_calls) * 100
                ),
                'circuit_breaker_trips': self.metrics.circuit_breaker_trips,
                'avg_response_time_ms': self.metrics.avg_response_time_ms
            }
        }


class RetryStrategy:
    """Advanced retry strategy with exponential backoff and jitter."""
    
    def __init__(self, config: ResilienceConfig):
        self.config = config
        self.metrics = ResilienceMetrics()
        self.logger = logging.getLogger(f"{__name__}.retry")
    
    def execute(self, func: Callable, *args, **kwargs):
        """Execute function with retry logic."""
        if not self.config.enabled:
            return func(*args, **kwargs)
        
        last_exception = None
        
        for attempt in range(self.config.max_retries + 1):
            try:
                self.metrics.total_calls += 1
                start_time = time.time()
                
                result = func(*args, **kwargs)
                
                response_time = (time.time() - start_time) * 1000
                self._update_avg_response_time(response_time)
                self.metrics.successful_calls += 1
                self.metrics.last_success_time = datetime.now()
                
                if attempt > 0:
                    self.logger.info(f"Function succeeded on attempt {attempt + 1}")
                
                return result
                
            except Exception as e:
                last_exception = e
                self.metrics.failed_calls += 1
                self.metrics.last_failure_time = datetime.now()
                
                if attempt < self.config.max_retries:
                    self.metrics.retries_attempted += 1
                    delay = self._calculate_delay(attempt)
                    
                    self.logger.warning(
                        f"Attempt {attempt + 1} failed: {str(e)}. "
                        f"Retrying in {delay:.2f}s..."
                    )
                    
                    time.sleep(delay)
                else:
                    self.logger.error(
                        f"All {self.config.max_retries + 1} attempts failed. "
                        f"Final error: {str(e)}"
                    )
        
        # If we get here, all retries failed
        raise last_exception
    
    def _calculate_delay(self, attempt: int) -> float:
        """Calculate retry delay with exponential backoff and jitter."""
        if self.config.strategy == ResilienceStrategy.RETRY_LINEAR:
            base_delay = self.config.retry_delay_seconds * (attempt + 1)
        else:  # RETRY_EXPONENTIAL
            base_delay = (
                self.config.retry_delay_seconds * 
                (self.config.exponential_base ** attempt)
            )
        
        # Apply maximum delay cap
        base_delay = min(base_delay, self.config.max_delay_seconds)
        
        # Add jitter (±20% of base delay)
        import random
        jitter = base_delay * 0.2 * (2 * random.random() - 1)
        final_delay = max(0, base_delay + jitter)
        
        return final_delay
    
    def _update_avg_response_time(self, response_time_ms: float):
        """Update average response time."""
        if self.metrics.avg_response_time_ms == 0:
            self.metrics.avg_response_time_ms = response_time_ms
        else:
            alpha = 0.1
            self.metrics.avg_response_time_ms = (
                alpha * response_time_ms + 
                (1 - alpha) * self.metrics.avg_response_time_ms
            )


class BulkheadIsolation:
    """Bulkhead pattern for resource isolation."""
    
    def __init__(self, config: ResilienceConfig):
        self.config = config
        self.executor = ThreadPoolExecutor(
            max_workers=config.bulkhead_max_concurrent,
            thread_name_prefix="bulkhead"
        )
        self.metrics = ResilienceMetrics()
        self.active_tasks = 0
        self._lock = threading.Lock()
        self.logger = logging.getLogger(f"{__name__}.bulkhead")
    
    def execute(self, func: Callable, *args, **kwargs) -> Future:
        """Execute function in isolated bulkhead."""
        if not self.config.enabled:
            # Create a completed future with the result
            future = Future()
            try:
                result = func(*args, **kwargs)
                future.set_result(result)
            except Exception as e:
                future.set_exception(e)
            return future
        
        with self._lock:
            self.active_tasks += 1
            self.metrics.total_calls += 1
        
        def wrapped_execution():
            try:
                start_time = time.time()
                result = func(*args, **kwargs)
                
                response_time = (time.time() - start_time) * 1000
                self._update_metrics(True, response_time)
                
                return result
                
            except Exception as e:
                self._update_metrics(False, 0)
                raise
            finally:
                with self._lock:
                    self.active_tasks -= 1
        
        return self.executor.submit(wrapped_execution)
    
    def _update_metrics(self, success: bool, response_time_ms: float):
        """Update bulkhead metrics."""
        if success:
            self.metrics.successful_calls += 1
            self.metrics.last_success_time = datetime.now()
            
            if self.metrics.avg_response_time_ms == 0:
                self.metrics.avg_response_time_ms = response_time_ms
            else:
                alpha = 0.1
                self.metrics.avg_response_time_ms = (
                    alpha * response_time_ms + 
                    (1 - alpha) * self.metrics.avg_response_time_ms
                )
        else:
            self.metrics.failed_calls += 1
            self.metrics.last_failure_time = datetime.now()
    
    def get_status(self) -> Dict[str, Any]:
        """Get bulkhead status."""
        return {
            'max_concurrent': self.config.bulkhead_max_concurrent,
            'active_tasks': self.active_tasks,
            'utilization_percent': (
                self.active_tasks / self.config.bulkhead_max_concurrent * 100
            ),
            'metrics': {
                'total_calls': self.metrics.total_calls,
                'successful_calls': self.metrics.successful_calls,
                'failed_calls': self.metrics.failed_calls,
                'avg_response_time_ms': self.metrics.avg_response_time_ms
            }
        }
    
    def shutdown(self):
        """Shutdown the bulkhead executor."""
        self.executor.shutdown(wait=True)


class ResilienceCache:
    """Simple in-memory cache for resilience patterns."""
    
    def __init__(self, config: ResilienceConfig):
        self.config = config
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.metrics = ResilienceMetrics()
        self._lock = threading.RLock()
        self.logger = logging.getLogger(f"{__name__}.cache")
        
        # Start cleanup thread
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_expired, 
            daemon=True
        )
        self._cleanup_thread.start()
    
    def get(self, key: str) -> Any:
        """Get value from cache."""
        with self._lock:
            if key in self.cache:
                entry = self.cache[key]
                if entry['expires_at'] > datetime.now():
                    self.metrics.cache_hits += 1
                    return entry['value']
                else:
                    # Expired entry
                    del self.cache[key]
            
            self.metrics.cache_misses += 1
            return None
    
    def set(self, key: str, value: Any):
        """Set value in cache."""
        with self._lock:
            expires_at = datetime.now() + timedelta(seconds=self.config.cache_ttl_seconds)
            self.cache[key] = {
                'value': value,
                'expires_at': expires_at,
                'created_at': datetime.now()
            }
    
    def _cleanup_expired(self):
        """Cleanup expired cache entries."""
        while True:
            try:
                time.sleep(60)  # Cleanup every minute
                
                with self._lock:
                    now = datetime.now()
                    expired_keys = [
                        key for key, entry in self.cache.items()
                        if entry['expires_at'] <= now
                    ]
                    
                    for key in expired_keys:
                        del self.cache[key]
                    
                    if expired_keys:
                        self.logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
                        
            except Exception as e:
                self.logger.error(f"Error in cache cleanup: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get cache status."""
        with self._lock:
            total_requests = self.metrics.cache_hits + self.metrics.cache_misses
            hit_rate = (
                self.metrics.cache_hits / max(1, total_requests) * 100
            )
            
            return {
                'size': len(self.cache),
                'hit_rate_percent': hit_rate,
                'metrics': {
                    'cache_hits': self.metrics.cache_hits,
                    'cache_misses': self.metrics.cache_misses,
                    'total_requests': total_requests
                }
            }


class ResilienceManager:
    """Central manager for all resilience strategies."""
    
    def __init__(self):
        self.strategies: Dict[str, Dict[str, Any]] = {}
        self.global_metrics = ResilienceMetrics()
        self.logger = logging.getLogger(__name__)
        self._lock = threading.RLock()
    
    def register_strategy(self, name: str, config: ResilienceConfig):
        """Register a resilience strategy."""
        with self._lock:
            strategy_impl = self._create_strategy_implementation(config)
            
            self.strategies[name] = {
                'config': config,
                'implementation': strategy_impl,
                'created_at': datetime.now(),
                'last_used': None
            }
            
            self.logger.info(f"Registered resilience strategy: {name} ({config.strategy.value})")
    
    def _create_strategy_implementation(self, config: ResilienceConfig):
        """Create strategy implementation based on config."""
        if config.strategy == ResilienceStrategy.CIRCUIT_BREAKER:
            return CircuitBreaker(config)
        elif config.strategy in [ResilienceStrategy.RETRY_EXPONENTIAL, ResilienceStrategy.RETRY_LINEAR]:
            return RetryStrategy(config)
        elif config.strategy == ResilienceStrategy.BULKHEAD:
            return BulkheadIsolation(config)
        elif config.strategy == ResilienceStrategy.CACHE:
            return ResilienceCache(config)
        else:
            raise ValueError(f"Unsupported resilience strategy: {config.strategy}")
    
    def execute_with_resilience(self, strategy_name: str, func: Callable, *args, **kwargs):
        """Execute function with specified resilience strategy."""
        if strategy_name not in self.strategies:
            self.logger.warning(f"Unknown resilience strategy: {strategy_name}")
            return func(*args, **kwargs)
        
        strategy_info = self.strategies[strategy_name]
        strategy_impl = strategy_info['implementation']
        
        with self._lock:
            strategy_info['last_used'] = datetime.now()
            self.global_metrics.total_calls += 1
        
        try:
            start_time = time.time()
            
            if isinstance(strategy_impl, CircuitBreaker):
                result = strategy_impl.call(func, *args, **kwargs)
            elif isinstance(strategy_impl, RetryStrategy):
                result = strategy_impl.execute(func, *args, **kwargs)
            elif isinstance(strategy_impl, BulkheadIsolation):
                future = strategy_impl.execute(func, *args, **kwargs)
                result = future.result()  # Wait for completion
            else:
                result = func(*args, **kwargs)
            
            response_time = (time.time() - start_time) * 1000
            self._update_global_metrics(True, response_time)
            
            return result
            
        except Exception as e:
            self._update_global_metrics(False, 0)
            raise
    
    def _update_global_metrics(self, success: bool, response_time_ms: float):
        """Update global resilience metrics."""
        if success:
            self.global_metrics.successful_calls += 1
            self.global_metrics.last_success_time = datetime.now()
        else:
            self.global_metrics.failed_calls += 1
            self.global_metrics.last_failure_time = datetime.now()
        
        # Update average response time
        if self.global_metrics.avg_response_time_ms == 0:
            self.global_metrics.avg_response_time_ms = response_time_ms
        else:
            alpha = 0.1
            self.global_metrics.avg_response_time_ms = (
                alpha * response_time_ms + 
                (1 - alpha) * self.global_metrics.avg_response_time_ms
            )
    
    def get_strategy_status(self, strategy_name: str) -> Optional[Dict[str, Any]]:
        """Get status of specific strategy."""
        if strategy_name not in self.strategies:
            return None
        
        strategy_info = self.strategies[strategy_name]
        strategy_impl = strategy_info['implementation']
        
        base_status = {
            'name': strategy_name,
            'strategy_type': strategy_info['config'].strategy.value,
            'enabled': strategy_info['config'].enabled,
            'created_at': strategy_info['created_at'].isoformat(),
            'last_used': strategy_info['last_used'].isoformat() if strategy_info['last_used'] else None
        }
        
        if hasattr(strategy_impl, 'get_status'):
            base_status.update(strategy_impl.get_status())
        
        return base_status
    
    def get_global_status(self) -> Dict[str, Any]:
        """Get global resilience status."""
        total_calls = self.global_metrics.total_calls
        success_rate = (
            self.global_metrics.successful_calls / max(1, total_calls) * 100
        )
        
        return {
            'registered_strategies': len(self.strategies),
            'active_strategies': len([
                name for name, info in self.strategies.items()
                if info['config'].enabled
            ]),
            'global_metrics': {
                'total_calls': total_calls,
                'successful_calls': self.global_metrics.successful_calls,
                'failed_calls': self.global_metrics.failed_calls,
                'success_rate_percent': success_rate,
                'avg_response_time_ms': self.global_metrics.avg_response_time_ms,
                'last_success_time': (
                    self.global_metrics.last_success_time.isoformat()
                    if self.global_metrics.last_success_time else None
                ),
                'last_failure_time': (
                    self.global_metrics.last_failure_time.isoformat()
                    if self.global_metrics.last_failure_time else None
                )
            },
            'strategies': {
                name: self.get_strategy_status(name)
                for name in self.strategies.keys()
            }
        }
    
    def shutdown(self):
        """Shutdown all resilience strategies."""
        for strategy_info in self.strategies.values():
            strategy_impl = strategy_info['implementation']
            if hasattr(strategy_impl, 'shutdown'):
                strategy_impl.shutdown()


# Exceptions
class ResilienceException(Exception):
    """Base exception for resilience patterns."""
    pass


class CircuitBreakerOpenException(ResilienceException):
    """Exception raised when circuit breaker is open."""
    pass


class BulkheadCapacityException(ResilienceException):
    """Exception raised when bulkhead capacity is exceeded."""
    pass


# Global resilience manager
global_resilience_manager = ResilienceManager()


# Decorators for easy usage
def with_circuit_breaker(name: str = None, **kwargs):
    """Decorator to apply circuit breaker pattern."""
    def decorator(func):
        strategy_name = name or f"circuit_breaker_{func.__name__}"
        
        # Register strategy if not exists
        if strategy_name not in global_resilience_manager.strategies:
            config = ResilienceConfig(
                strategy=ResilienceStrategy.CIRCUIT_BREAKER,
                **kwargs
            )
            global_resilience_manager.register_strategy(strategy_name, config)
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            return global_resilience_manager.execute_with_resilience(
                strategy_name, func, *args, **kwargs
            )
        
        return wrapper
    return decorator


def with_retry(name: str = None, strategy: str = "exponential", **kwargs):
    """Decorator to apply retry pattern."""
    def decorator(func):
        strategy_name = name or f"retry_{func.__name__}"
        
        retry_strategy = (
            ResilienceStrategy.RETRY_EXPONENTIAL 
            if strategy == "exponential" 
            else ResilienceStrategy.RETRY_LINEAR
        )
        
        # Register strategy if not exists
        if strategy_name not in global_resilience_manager.strategies:
            config = ResilienceConfig(
                strategy=retry_strategy,
                **kwargs
            )
            global_resilience_manager.register_strategy(strategy_name, config)
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            return global_resilience_manager.execute_with_resilience(
                strategy_name, func, *args, **kwargs
            )
        
        return wrapper
    return decorator


def with_bulkhead(name: str = None, **kwargs):
    """Decorator to apply bulkhead pattern."""
    def decorator(func):
        strategy_name = name or f"bulkhead_{func.__name__}"
        
        # Register strategy if not exists
        if strategy_name not in global_resilience_manager.strategies:
            config = ResilienceConfig(
                strategy=ResilienceStrategy.BULKHEAD,
                **kwargs
            )
            global_resilience_manager.register_strategy(strategy_name, config)
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            return global_resilience_manager.execute_with_resilience(
                strategy_name, func, *args, **kwargs
            )
        
        return wrapper
    return decorator


# Initialize default resilience strategies
def initialize_default_strategies():
    """Initialize default resilience strategies for common operations."""
    
    # Circuit breaker for file operations
    global_resilience_manager.register_strategy(
        "file_operations",
        ResilienceConfig(
            strategy=ResilienceStrategy.CIRCUIT_BREAKER,
            failure_threshold=5,
            recovery_timeout_seconds=30.0
        )
    )
    
    # Retry for network operations
    global_resilience_manager.register_strategy(
        "network_operations",
        ResilienceConfig(
            strategy=ResilienceStrategy.RETRY_EXPONENTIAL,
            max_retries=3,
            retry_delay_seconds=1.0,
            exponential_base=2.0,
            max_delay_seconds=30.0
        )
    )
    
    # Bulkhead for scan operations
    global_resilience_manager.register_strategy(
        "scan_operations",
        ResilienceConfig(
            strategy=ResilienceStrategy.BULKHEAD,
            bulkhead_max_concurrent=5
        )
    )


# Initialize default strategies
initialize_default_strategies()