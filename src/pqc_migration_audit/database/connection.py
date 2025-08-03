"""Database connection management for PQC Migration Audit."""

import os
import sqlite3
from typing import Optional, Dict, Any
from contextlib import contextmanager
import json
from pathlib import Path
import threading


class DatabaseConnection:
    """SQLite database connection manager for storing scan results and analysis."""
    
    def __init__(self, db_path: Optional[str] = None):
        """Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file. If None, uses in-memory database.
        """
        self.db_path = db_path or ":memory:"
        self._local = threading.local()
        self._init_database()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get thread-local database connection."""
        if not hasattr(self._local, 'connection'):
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row  # Enable dict-like access
            conn.execute("PRAGMA foreign_keys = ON")  # Enable foreign key constraints
            self._local.connection = conn
        return self._local.connection
    
    @contextmanager
    def get_cursor(self):
        """Get database cursor with automatic cleanup."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()
    
    def _init_database(self):
        """Initialize database schema."""
        with self.get_cursor() as cursor:
            # Create scan_results table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_path TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    scan_time REAL NOT NULL,
                    scanned_files INTEGER NOT NULL,
                    total_lines INTEGER NOT NULL,
                    languages_detected TEXT NOT NULL,  -- JSON array
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create vulnerabilities table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_result_id INTEGER NOT NULL,
                    file_path TEXT NOT NULL,
                    line_number INTEGER NOT NULL,
                    algorithm TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    key_size INTEGER,
                    description TEXT NOT NULL,
                    code_snippet TEXT NOT NULL,
                    recommendation TEXT NOT NULL,
                    cwe_id TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_result_id) REFERENCES scan_results(id) ON DELETE CASCADE
                )
            """)
            
            # Create migration_plans table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS migration_plans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_result_id INTEGER NOT NULL,
                    plan_data TEXT NOT NULL,  -- JSON data
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_result_id) REFERENCES scan_results(id) ON DELETE CASCADE
                )
            """)
            
            # Create risk_assessments table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS risk_assessments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_result_id INTEGER NOT NULL,
                    hndl_risk_score INTEGER NOT NULL,
                    migration_hours INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    assessment_data TEXT NOT NULL,  -- JSON data
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_result_id) REFERENCES scan_results(id) ON DELETE CASCADE
                )
            """)
            
            # Create inventory_items table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS inventory_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_result_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    version TEXT,
                    location TEXT NOT NULL,
                    algorithms TEXT NOT NULL,  -- JSON array
                    key_sizes TEXT,  -- JSON array
                    usage_context TEXT NOT NULL,
                    pqc_ready BOOLEAN DEFAULT FALSE,
                    migration_priority TEXT NOT NULL,
                    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_result_id) REFERENCES scan_results(id) ON DELETE CASCADE
                )
            """)
            
            # Create compliance_assessments table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS compliance_assessments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_result_id INTEGER NOT NULL,
                    framework TEXT NOT NULL,
                    compliance_percentage REAL NOT NULL,
                    requirements_met TEXT NOT NULL,  -- JSON array
                    requirements_pending TEXT NOT NULL,  -- JSON array
                    deadline TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_result_id) REFERENCES scan_results(id) ON DELETE CASCADE
                )
            """)
            
            # Create indexes for better performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_result ON vulnerabilities(scan_result_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_algorithm ON vulnerabilities(algorithm)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_timestamp ON scan_results(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_inventory_items_scan_result ON inventory_items(scan_result_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_compliance_assessments_scan_result ON compliance_assessments(scan_result_id)")
    
    def execute_query(self, query: str, params: tuple = ()) -> list:
        """Execute a SELECT query and return results."""
        with self.get_cursor() as cursor:
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def execute_insert(self, query: str, params: tuple = ()) -> int:
        """Execute an INSERT query and return the last row ID."""
        with self.get_cursor() as cursor:
            cursor.execute(query, params)
            return cursor.lastrowid
    
    def execute_update(self, query: str, params: tuple = ()) -> int:
        """Execute an UPDATE query and return the number of affected rows."""
        with self.get_cursor() as cursor:
            cursor.execute(query, params)
            return cursor.rowcount
    
    def execute_delete(self, query: str, params: tuple = ()) -> int:
        """Execute a DELETE query and return the number of affected rows."""
        with self.get_cursor() as cursor:
            cursor.execute(query, params)
            return cursor.rowcount
    
    def close(self):
        """Close database connections."""
        if hasattr(self._local, 'connection'):
            self._local.connection.close()
            del self._local.connection


class CacheManager:
    """Simple file-based cache for storing analysis results."""
    
    def __init__(self, cache_dir: str = ".pqc-cache"):
        """Initialize cache manager.
        
        Args:
            cache_dir: Directory to store cache files
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        
    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Get value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found/expired
        """
        cache_file = self.cache_dir / f"{key}.json"
        
        if not cache_file.exists():
            return None
            
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
                
            # Check if cache has expired (1 hour TTL)
            import time
            if time.time() - data.get('timestamp', 0) > 3600:
                cache_file.unlink()  # Remove expired cache
                return None
                
            return data.get('value')
        except (json.JSONDecodeError, KeyError, OSError):
            # Invalid cache file, remove it
            try:
                cache_file.unlink()
            except OSError:
                pass
            return None
    
    def set(self, key: str, value: Dict[str, Any]) -> None:
        """Set value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
        """
        cache_file = self.cache_dir / f"{key}.json"
        
        import time
        cache_data = {
            'timestamp': time.time(),
            'value': value
        }
        
        try:
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
        except OSError:
            # Cache write failed, continue without caching
            pass
    
    def delete(self, key: str) -> None:
        """Delete value from cache.
        
        Args:
            key: Cache key to delete
        """
        cache_file = self.cache_dir / f"{key}.json"
        try:
            cache_file.unlink()
        except OSError:
            pass  # File doesn't exist or can't be deleted
    
    def clear(self) -> None:
        """Clear all cache files."""
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                cache_file.unlink()
            except OSError:
                pass
    
    def cleanup_expired(self) -> int:
        """Remove expired cache files.
        
        Returns:
            Number of files removed
        """
        import time
        current_time = time.time()
        removed_count = 0
        
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                
                if current_time - data.get('timestamp', 0) > 3600:  # 1 hour TTL
                    cache_file.unlink()
                    removed_count += 1
            except (json.JSONDecodeError, KeyError, OSError):
                # Invalid cache file, remove it
                try:
                    cache_file.unlink()
                    removed_count += 1
                except OSError:
                    pass
        
        return removed_count


# Global instances
_db_connection = None
_cache_manager = None


def get_database() -> DatabaseConnection:
    """Get singleton database connection."""
    global _db_connection
    if _db_connection is None:
        db_path = os.getenv('PQC_DATABASE_PATH', 'pqc_audit.db')
        _db_connection = DatabaseConnection(db_path)
    return _db_connection


def get_cache() -> CacheManager:
    """Get singleton cache manager."""
    global _cache_manager
    if _cache_manager is None:
        cache_dir = os.getenv('PQC_CACHE_DIR', '.pqc-cache')
        _cache_manager = CacheManager(cache_dir)
    return _cache_manager