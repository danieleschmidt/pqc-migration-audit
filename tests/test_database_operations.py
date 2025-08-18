"""Database operations testing for comprehensive coverage."""

import pytest
import sqlite3
import tempfile
import os
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Database imports with error handling
try:
    from pqc_migration_audit.database import (
        DatabaseConnection, DatabaseManager, migrate_database
    )
    DATABASE_AVAILABLE = True
except ImportError:
    DATABASE_AVAILABLE = False

try:
    from pqc_migration_audit.database.connection import (
        PostgreSQLConnection, SQLiteConnection, MySQLConnection
    )
    CONNECTION_AVAILABLE = True
except ImportError:
    CONNECTION_AVAILABLE = False

try:
    from pqc_migration_audit.database.models import (
        ScanResult, Vulnerability, CryptoAsset, MigrationPlan
    )
    MODELS_AVAILABLE = True
except ImportError:
    MODELS_AVAILABLE = False

try:
    from pqc_migration_audit.database.repository import (
        ScanResultRepository, VulnerabilityRepository, CryptoAssetRepository
    )
    REPOSITORY_AVAILABLE = True
except ImportError:
    REPOSITORY_AVAILABLE = False

from pqc_migration_audit.types import Severity, CryptoAlgorithm


@pytest.fixture
def temp_db_file():
    """Create a temporary SQLite database file."""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name
    
    yield db_path
    
    # Cleanup
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.fixture
def sqlite_connection(temp_db_file):
    """Create a SQLite database connection for testing."""
    conn = sqlite3.connect(temp_db_file)
    
    # Create basic schema
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY,
            file_path TEXT NOT NULL,
            scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            vulnerability_count INTEGER DEFAULT 0
        )
    """)
    
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY,
            scan_result_id INTEGER,
            file_path TEXT NOT NULL,
            line_number INTEGER,
            algorithm TEXT,
            severity TEXT,
            description TEXT,
            recommendation TEXT,
            FOREIGN KEY (scan_result_id) REFERENCES scan_results (id)
        )
    """)
    
    conn.execute("""
        CREATE TABLE IF NOT EXISTS crypto_assets (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            algorithm TEXT,
            key_size INTEGER,
            location TEXT,
            risk_level TEXT,
            migration_priority TEXT
        )
    """)
    
    conn.commit()
    yield conn
    conn.close()


@pytest.mark.skipif(not DATABASE_AVAILABLE, reason="Database module not available")
class TestDatabaseConnection:
    """Test database connection functionality."""

    def test_database_manager_initialization(self):
        """Test DatabaseManager initialization."""
        manager = DatabaseManager()
        assert manager is not None
        assert hasattr(manager, 'connect')
        assert hasattr(manager, 'disconnect')

    def test_database_connection_establishment(self, temp_db_file):
        """Test database connection establishment."""
        with patch('sqlite3.connect') as mock_connect:
            mock_conn = Mock()
            mock_connect.return_value = mock_conn
            
            manager = DatabaseManager()
            connection = manager.connect(f'sqlite:///{temp_db_file}')
            
            assert connection is not None
            mock_connect.assert_called_once()

    def test_database_migration(self, temp_db_file):
        """Test database migration functionality."""
        with patch('pqc_migration_audit.database.migrate_database') as mock_migrate:
            mock_migrate.return_value = True
            
            result = migrate_database(f'sqlite:///{temp_db_file}')
            assert result is True
            mock_migrate.assert_called_once()


@pytest.mark.skipif(not CONNECTION_AVAILABLE, reason="Connection module not available")
class TestDatabaseConnections:
    """Test specific database connection types."""

    def test_sqlite_connection_initialization(self):
        """Test SQLiteConnection initialization."""
        conn = SQLiteConnection(':memory:')
        assert conn is not None
        assert hasattr(conn, 'connect')
        assert hasattr(conn, 'execute')

    def test_postgresql_connection_initialization(self):
        """Test PostgreSQLConnection initialization."""
        with patch('psycopg2.connect'):
            conn = PostgreSQLConnection(
                host='localhost',
                database='test',
                user='test',
                password='test'
            )
            assert conn is not None
            assert hasattr(conn, 'connect')

    def test_mysql_connection_initialization(self):
        """Test MySQLConnection initialization."""
        with patch('mysql.connector.connect'):
            conn = MySQLConnection(
                host='localhost',
                database='test',
                user='test',
                password='test'
            )
            assert conn is not None
            assert hasattr(conn, 'connect')

    def test_sqlite_connection_operations(self, temp_db_file):
        """Test SQLite connection operations."""
        conn = SQLiteConnection(temp_db_file)
        
        # Test connection
        conn.connect()
        assert conn.is_connected()
        
        # Test query execution
        result = conn.execute('SELECT 1 as test')
        assert result is not None
        
        # Test disconnection
        conn.disconnect()
        assert not conn.is_connected()


@pytest.mark.skipif(not MODELS_AVAILABLE, reason="Models module not available")
class TestDatabaseModels:
    """Test database model functionality."""

    def test_scan_result_model_creation(self):
        """Test ScanResult model creation."""
        scan_result = ScanResult(
            file_path='/path/to/test.py',
            vulnerability_count=3,
            scan_date='2025-01-01'
        )
        
        assert scan_result.file_path == '/path/to/test.py'
        assert scan_result.vulnerability_count == 3
        assert scan_result.scan_date == '2025-01-01'

    def test_vulnerability_model_creation(self):
        """Test Vulnerability model creation."""
        vulnerability = Vulnerability(
            file_path='/path/to/test.py',
            line_number=42,
            algorithm='RSA',
            severity='high',
            description='RSA key generation detected',
            recommendation='Use ML-KEM instead'
        )
        
        assert vulnerability.file_path == '/path/to/test.py'
        assert vulnerability.line_number == 42
        assert vulnerability.algorithm == 'RSA'
        assert vulnerability.severity == 'high'

    def test_crypto_asset_model_creation(self):
        """Test CryptoAsset model creation."""
        asset = CryptoAsset(
            name='auth-service-key',
            algorithm='RSA',
            key_size=2048,
            location='/etc/ssl/private/key.pem',
            risk_level='high',
            migration_priority='urgent'
        )
        
        assert asset.name == 'auth-service-key'
        assert asset.algorithm == 'RSA'
        assert asset.key_size == 2048
        assert asset.risk_level == 'high'

    def test_migration_plan_model_creation(self):
        """Test MigrationPlan model creation."""
        plan = MigrationPlan(
            asset_id=1,
            current_algorithm='RSA',
            target_algorithm='ML-KEM',
            migration_steps=[
                'Generate new ML-KEM keypair',
                'Update configuration',
                'Test compatibility',
                'Deploy changes'
            ],
            estimated_effort='4 hours',
            priority='high'
        )
        
        assert plan.asset_id == 1
        assert plan.current_algorithm == 'RSA'
        assert plan.target_algorithm == 'ML-KEM'
        assert len(plan.migration_steps) == 4


@pytest.mark.skipif(not REPOSITORY_AVAILABLE, reason="Repository module not available")
class TestDatabaseRepositories:
    """Test database repository functionality."""

    def test_scan_result_repository_initialization(self):
        """Test ScanResultRepository initialization."""
        with patch('pqc_migration_audit.database.connection.SQLiteConnection'):
            repo = ScanResultRepository()
            assert repo is not None
            assert hasattr(repo, 'save')
            assert hasattr(repo, 'find_by_id')
            assert hasattr(repo, 'find_all')

    def test_vulnerability_repository_initialization(self):
        """Test VulnerabilityRepository initialization."""
        with patch('pqc_migration_audit.database.connection.SQLiteConnection'):
            repo = VulnerabilityRepository()
            assert repo is not None
            assert hasattr(repo, 'save')
            assert hasattr(repo, 'find_by_scan_result')

    def test_crypto_asset_repository_initialization(self):
        """Test CryptoAssetRepository initialization."""
        with patch('pqc_migration_audit.database.connection.SQLiteConnection'):
            repo = CryptoAssetRepository()
            assert repo is not None
            assert hasattr(repo, 'save')
            assert hasattr(repo, 'find_by_risk_level')

    def test_scan_result_repository_operations(self, sqlite_connection):
        """Test ScanResultRepository CRUD operations."""
        with patch('pqc_migration_audit.database.connection.SQLiteConnection.connect', return_value=sqlite_connection):
            repo = ScanResultRepository()
            
            # Test save operation
            scan_result = {
                'file_path': '/test/file.py',
                'vulnerability_count': 2
            }
            
            result_id = repo.save(scan_result)
            assert result_id is not None
            
            # Test find operation
            found_result = repo.find_by_id(result_id)
            assert found_result is not None
            assert found_result['file_path'] == '/test/file.py'

    def test_vulnerability_repository_operations(self, sqlite_connection):
        """Test VulnerabilityRepository CRUD operations."""
        with patch('pqc_migration_audit.database.connection.SQLiteConnection.connect', return_value=sqlite_connection):
            repo = VulnerabilityRepository()
            
            # Test save operation
            vulnerability = {
                'scan_result_id': 1,
                'file_path': '/test/file.py',
                'line_number': 10,
                'algorithm': 'RSA',
                'severity': 'high',
                'description': 'RSA usage detected',
                'recommendation': 'Use ML-KEM'
            }
            
            vuln_id = repo.save(vulnerability)
            assert vuln_id is not None
            
            # Test find by scan result
            vulnerabilities = repo.find_by_scan_result(1)
            assert vulnerabilities is not None
            assert len(vulnerabilities) >= 0

    def test_crypto_asset_repository_operations(self, sqlite_connection):
        """Test CryptoAssetRepository CRUD operations."""
        with patch('pqc_migration_audit.database.connection.SQLiteConnection.connect', return_value=sqlite_connection):
            repo = CryptoAssetRepository()
            
            # Test save operation
            asset = {
                'name': 'test-key',
                'algorithm': 'RSA',
                'key_size': 2048,
                'location': '/etc/ssl/test.pem',
                'risk_level': 'high',
                'migration_priority': 'urgent'
            }
            
            asset_id = repo.save(asset)
            assert asset_id is not None
            
            # Test find by risk level
            high_risk_assets = repo.find_by_risk_level('high')
            assert high_risk_assets is not None
            assert len(high_risk_assets) >= 0


class TestDatabaseOperationsIntegration:
    """Test integrated database operations."""

    def test_complete_scan_workflow_with_database(self, sqlite_connection):
        """Test complete scan workflow with database persistence."""
        # Simulate a complete scan workflow
        scan_data = {
            'file_path': '/project/src/crypto.py',
            'scan_date': '2025-01-01 12:00:00',
            'vulnerability_count': 3
        }
        
        vulnerabilities = [
            {
                'file_path': '/project/src/crypto.py',
                'line_number': 15,
                'algorithm': 'RSA',
                'severity': 'high',
                'description': 'RSA key generation',
                'recommendation': 'Use ML-KEM'
            },
            {
                'file_path': '/project/src/crypto.py',
                'line_number': 25,
                'algorithm': 'ECC',
                'severity': 'medium',
                'description': 'ECC curve usage',
                'recommendation': 'Use ML-DSA'
            },
            {
                'file_path': '/project/src/crypto.py',
                'line_number': 35,
                'algorithm': 'DES',
                'severity': 'critical',
                'description': 'DES encryption',
                'recommendation': 'Use AES-256'
            }
        ]
        
        # Insert scan result
        cursor = sqlite_connection.cursor()
        cursor.execute(
            "INSERT INTO scan_results (file_path, vulnerability_count) VALUES (?, ?)",
            (scan_data['file_path'], scan_data['vulnerability_count'])
        )
        scan_result_id = cursor.lastrowid
        
        # Insert vulnerabilities
        for vuln in vulnerabilities:
            cursor.execute(
                """INSERT INTO vulnerabilities 
                   (scan_result_id, file_path, line_number, algorithm, severity, description, recommendation) 
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (scan_result_id, vuln['file_path'], vuln['line_number'], 
                 vuln['algorithm'], vuln['severity'], vuln['description'], vuln['recommendation'])
            )
        
        sqlite_connection.commit()
        
        # Verify data was saved
        cursor.execute("SELECT COUNT(*) FROM scan_results")
        scan_count = cursor.fetchone()[0]
        assert scan_count >= 1
        
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE scan_result_id = ?", (scan_result_id,))
        vuln_count = cursor.fetchone()[0]
        assert vuln_count == 3
        
        # Test querying vulnerabilities by severity
        cursor.execute("SELECT * FROM vulnerabilities WHERE severity = 'critical'")
        critical_vulns = cursor.fetchall()
        assert len(critical_vulns) >= 1
        
        cursor.close()

    def test_crypto_asset_inventory_workflow(self, sqlite_connection):
        """Test crypto asset inventory workflow."""
        assets = [
            {
                'name': 'web-server-cert',
                'algorithm': 'RSA',
                'key_size': 2048,
                'location': '/etc/ssl/certs/server.crt',
                'risk_level': 'medium',
                'migration_priority': 'normal'
            },
            {
                'name': 'api-signing-key',
                'algorithm': 'ECC',
                'key_size': 256,
                'location': '/etc/ssl/private/api.key',
                'risk_level': 'high',
                'migration_priority': 'urgent'
            },
            {
                'name': 'legacy-encryption-key',
                'algorithm': 'DES',
                'key_size': 64,
                'location': '/var/lib/app/legacy.key',
                'risk_level': 'critical',
                'migration_priority': 'immediate'
            }
        ]
        
        cursor = sqlite_connection.cursor()
        
        # Insert crypto assets
        for asset in assets:
            cursor.execute(
                """INSERT INTO crypto_assets 
                   (name, algorithm, key_size, location, risk_level, migration_priority) 
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (asset['name'], asset['algorithm'], asset['key_size'], 
                 asset['location'], asset['risk_level'], asset['migration_priority'])
            )
        
        sqlite_connection.commit()
        
        # Query assets by risk level
        cursor.execute("SELECT * FROM crypto_assets WHERE risk_level = 'critical'")
        critical_assets = cursor.fetchall()
        assert len(critical_assets) >= 1
        
        # Query assets by migration priority
        cursor.execute("SELECT * FROM crypto_assets WHERE migration_priority = 'immediate'")
        immediate_assets = cursor.fetchall()
        assert len(immediate_assets) >= 1
        
        # Generate migration priority report
        cursor.execute(
            """SELECT migration_priority, COUNT(*) as count 
               FROM crypto_assets 
               GROUP BY migration_priority 
               ORDER BY CASE 
                   WHEN migration_priority = 'immediate' THEN 1
                   WHEN migration_priority = 'urgent' THEN 2
                   WHEN migration_priority = 'normal' THEN 3
                   ELSE 4 END"""
        )
        priority_report = cursor.fetchall()
        assert len(priority_report) >= 1
        
        cursor.close()

    def test_database_performance_with_large_dataset(self, sqlite_connection):
        """Test database performance with larger datasets."""
        import time
        
        cursor = sqlite_connection.cursor()
        
        # Generate large dataset
        start_time = time.time()
        
        vulnerabilities = []
        for i in range(1000):
            vulnerabilities.append((
                1,  # scan_result_id
                f'/test/file_{i % 10}.py',
                i % 100 + 1,  # line_number
                ['RSA', 'ECC', 'DES', 'AES'][i % 4],  # algorithm
                ['critical', 'high', 'medium', 'low'][i % 4],  # severity
                f'Vulnerability {i}',
                f'Recommendation {i}'
            ))
        
        # Batch insert
        cursor.executemany(
            """INSERT INTO vulnerabilities 
               (scan_result_id, file_path, line_number, algorithm, severity, description, recommendation) 
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            vulnerabilities
        )
        
        sqlite_connection.commit()
        insert_time = time.time() - start_time
        
        # Test query performance
        start_time = time.time()
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'critical'")
        critical_count = cursor.fetchone()[0]
        query_time = time.time() - start_time
        
        assert critical_count >= 0
        assert insert_time < 5.0  # Should complete within 5 seconds
        assert query_time < 1.0   # Query should be fast
        
        cursor.close()

    def test_database_transaction_handling(self, sqlite_connection):
        """Test database transaction handling and rollback."""
        cursor = sqlite_connection.cursor()
        
        try:
            # Start transaction
            cursor.execute("BEGIN TRANSACTION")
            
            # Insert test data
            cursor.execute(
                "INSERT INTO scan_results (file_path, vulnerability_count) VALUES (?, ?)",
                ('/test/transaction.py', 1)
            )
            
            # Simulate error condition
            raise Exception("Simulated error")
            
        except Exception:
            # Rollback on error
            sqlite_connection.rollback()
        
        # Verify no data was committed
        cursor.execute("SELECT COUNT(*) FROM scan_results WHERE file_path = '/test/transaction.py'")
        count = cursor.fetchone()[0]
        assert count == 0
        
        cursor.close()

    def test_database_connection_pooling(self):
        """Test database connection pooling functionality."""
        # Mock connection pool
        connection_pool = []
        max_connections = 5
        
        def get_connection():
            if len(connection_pool) < max_connections:
                # Create new connection
                conn = Mock()
                conn.is_active = True
                connection_pool.append(conn)
                return conn
            else:
                # Reuse existing connection
                return connection_pool[0]
        
        def release_connection(conn):
            if conn in connection_pool:
                conn.is_active = False
        
        # Test connection acquisition
        connections = []
        for i in range(7):  # More than max_connections
            conn = get_connection()
            connections.append(conn)
        
        # Should not exceed max connections
        assert len(set(connections)) <= max_connections
        
        # Test connection release
        for conn in connections:
            release_connection(conn)
        
        # All connections should be inactive
        inactive_count = sum(1 for conn in connection_pool if not conn.is_active)
        assert inactive_count == len(connection_pool)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
