# Advanced debugging configuration for PQC Migration Audit
import logging
import sys
import os
from pathlib import Path
from typing import Optional

# Configure advanced logging for debugging
def setup_debug_logging(log_level: str = "DEBUG", log_file: Optional[str] = None):
    """Setup comprehensive debug logging."""
    
    # Create formatter with detailed information
    formatter = logging.Formatter(
        '[%(asctime)s] %(name)s:%(lineno)d %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(getattr(logging, log_level.upper()))
    
    # File handler if specified
    handlers = [console_handler]
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)
        handlers.append(file_handler)
    
    # Configure root logger
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        handlers=handlers,
        force=True
    )
    
    # Enable debug logging for our modules
    for module in ['pqc_migration_audit', 'pqc_audit']:
        logger = logging.getLogger(module)
        logger.setLevel(logging.DEBUG)

def enable_comprehensive_debugging():
    """Enable comprehensive debugging features."""
    
    # Enable all warnings
    import warnings
    warnings.filterwarnings('default')
    
    # Enable detailed tracebacks
    sys.tracebacklimit = 1000
    
    # Enable garbage collection debugging
    import gc
    gc.set_debug(gc.DEBUG_STATS | gc.DEBUG_LEAK)
    
    # Enable asyncio debugging
    os.environ['PYTHONASYNCIODEBUG'] = '1'
    
    # Enable development mode
    os.environ['PYTHONDEVMODE'] = '1'

def setup_performance_debugging():
    """Setup performance debugging tools."""
    
    # Memory profiling setup  
    try:
        from memory_profiler import profile
        print("Memory profiler available - use @profile decorator")
    except ImportError:
        print("memory-profiler not installed - install with: pip install memory-profiler")
    
    # CPU profiling setup
    try:
        import cProfile
        import pstats
        print("cProfile available for CPU profiling")
    except ImportError:
        print("cProfile not available")
    
    # Line profiling setup
    try:
        import line_profiler
        print("line_profiler available - use @profile decorator")
    except ImportError:
        print("line-profiler not installed - install with: pip install line-profiler")

def create_debug_helpers():
    """Create debugging helper functions."""
    
    def debug_function_calls(func):
        """Decorator to debug function calls."""
        import functools
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            logger = logging.getLogger(func.__module__)
            logger.debug(f"Calling {func.__name__} with args={args}, kwargs={kwargs}")
            
            try:
                result = func(*args, **kwargs)
                logger.debug(f"{func.__name__} returned: {type(result).__name__}")
                return result
            except Exception as e:
                logger.error(f"{func.__name__} raised {type(e).__name__}: {e}")
                raise
        
        return wrapper
    
    def debug_execution_time(func):
        """Decorator to measure execution time."""
        import functools
        import time
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            result = func(*args, **kwargs)
            end_time = time.perf_counter()
            
            logger = logging.getLogger(func.__module__)
            logger.debug(f"{func.__name__} executed in {end_time - start_time:.4f} seconds")
            
            return result
        
        return wrapper
    
    # Make decorators globally available
    import builtins
    builtins.debug_calls = debug_function_calls
    builtins.debug_time = debug_execution_time

def setup_interactive_debugging():
    """Setup interactive debugging tools."""
    
    # Enhanced exception handler
    def debug_exception_handler(exc_type, exc_value, exc_traceback):
        """Enhanced exception handler for debugging."""
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        
        print("\n" + "="*60)
        print("UNHANDLED EXCEPTION OCCURRED")
        print("="*60)
        
        import traceback
        traceback.print_exception(exc_type, exc_value, exc_traceback)
        
        print("\n" + "="*60)
        print("DEBUGGING INFORMATION")
        print("="*60)
        
        # Print local variables from the traceback
        tb = exc_traceback
        while tb is not None:
            frame = tb.tb_frame
            print(f"\nFrame: {frame.f_code.co_filename}:{tb.tb_lineno} in {frame.f_code.co_name}")
            
            if frame.f_locals:
                print("Local variables:")
                for var, value in frame.f_locals.items():
                    if not var.startswith('_'):
                        try:
                            print(f"  {var} = {repr(value)[:100]}")
                        except:
                            print(f"  {var} = <unable to represent>")
            
            tb = tb.tb_next
        
        print("\n" + "="*60)
        
        # Drop into debugger if available
        try:
            import pdb
            print("Entering post-mortem debugger...")
            pdb.post_mortem(exc_traceback)
        except:
            pass
    
    # Install the exception handler
    sys.excepthook = debug_exception_handler

def initialize_debugging():
    """Initialize all debugging features."""
    
    # Check if debug mode is enabled
    debug_enabled = os.getenv('PQC_AUDIT_DEBUG', 'false').lower() == 'true'
    log_level = os.getenv('PQC_AUDIT_LOG_LEVEL', 'INFO')
    
    if debug_enabled:
        print("🐛 Debug mode enabled")
        
        # Setup logging
        log_file = os.getenv('PQC_AUDIT_LOG_FILE')
        setup_debug_logging(log_level, log_file)
        
        # Enable comprehensive debugging
        enable_comprehensive_debugging()
        
        # Setup performance debugging
        setup_performance_debugging()
        
        # Create debug helpers
        create_debug_helpers()
        
        # Setup interactive debugging
        setup_interactive_debugging()
        
        print("🔧 Debug configuration complete")
    else:
        # Basic logging for production
        setup_debug_logging(log_level)

# Auto-initialize when imported
if __name__ != '__main__':
    initialize_debugging()

# Debug utility functions
def dump_object_info(obj, name="object"):
    """Dump detailed information about an object."""
    logger = logging.getLogger(__name__)
    logger.debug(f"--- {name} INFO ---")
    logger.debug(f"Type: {type(obj)}")
    logger.debug(f"Module: {getattr(type(obj), '__module__', 'unknown')}")
    logger.debug(f"Size: {sys.getsizeof(obj)} bytes")
    
    if hasattr(obj, '__dict__'):
        logger.debug("Attributes:")
        for attr, value in obj.__dict__.items():
            if not attr.startswith('_'):
                logger.debug(f"  {attr}: {type(value)} = {repr(value)[:50]}")
    
    logger.debug("--- END INFO ---")

def trace_calls(func):
    """Decorator to trace all function calls."""
    import functools
    
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        logger = logging.getLogger(func.__module__)
        indent = getattr(trace_calls, 'indent', 0)
        trace_calls.indent = indent + 1
        
        prefix = "  " * indent
        logger.debug(f"{prefix}→ {func.__name__}({args}, {kwargs})")
        
        try:
            result = func(*args, **kwargs)
            logger.debug(f"{prefix}← {func.__name__} = {type(result)}")
            return result
        finally:
            trace_calls.indent = indent
    
    return wrapper

# Export main debugging functions
__all__ = [
    'initialize_debugging',
    'setup_debug_logging', 
    'dump_object_info',
    'trace_calls'
]