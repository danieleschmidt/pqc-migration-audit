"""Repository pattern implementation for database operations."""

from typing import List, Optional, Dict, Any, Type, TypeVar
from abc import ABC, abstractmethod
from datetime import datetime

from .connection import get_database, DatabaseConnection
from .models import (
    ScanResultModel, VulnerabilityModel, MigrationPlanModel,
    RiskAssessmentModel, InventoryItemModel, ComplianceAssessmentModel
)

T = TypeVar('T')


class BaseRepository(ABC):
    """Base repository class with common CRUD operations."""
    
    def __init__(self, db: Optional[DatabaseConnection] = None):
        """Initialize repository with database connection.
        
        Args:
            db: Database connection. If None, uses singleton.
        """
        self.db = db or get_database()
    
    @property
    @abstractmethod
    def table_name(self) -> str:
        """Return table name for this repository."""
        pass
    
    @property
    @abstractmethod
    def model_class(self) -> Type[T]:
        """Return model class for this repository."""
        pass
    
    def create(self, model: T) -> int:
        """Create a new record.
        
        Args:
            model: Model instance to create
            
        Returns:
            ID of created record
        """
        data = model.to_dict()
        data.pop('id', None)  # Remove ID for creation
        data['created_at'] = datetime.now().isoformat()
        
        columns = ', '.join(data.keys())
        placeholders = ', '.join(['?' for _ in data])
        query = f"INSERT INTO {self.table_name} ({columns}) VALUES ({placeholders})"
        
        return self.db.execute_insert(query, tuple(data.values()))
    
    def get_by_id(self, record_id: int) -> Optional[T]:
        """Get record by ID.
        
        Args:
            record_id: Record ID
            
        Returns:
            Model instance or None if not found
        """
        query = f"SELECT * FROM {self.table_name} WHERE id = ?"
        results = self.db.execute_query(query, (record_id,))
        
        if results:
            return self.model_class.from_dict(results[0])
        return None
    
    def get_all(self, limit: Optional[int] = None, offset: int = 0) -> List[T]:
        """Get all records with optional pagination.
        
        Args:
            limit: Maximum number of records to return
            offset: Number of records to skip
            
        Returns:
            List of model instances
        """
        query = f"SELECT * FROM {self.table_name} ORDER BY created_at DESC"
        
        if limit:
            query += f" LIMIT {limit} OFFSET {offset}"
        
        results = self.db.execute_query(query)
        return [self.model_class.from_dict(row) for row in results]
    
    def update(self, model: T) -> bool:
        """Update existing record.
        
        Args:
            model: Model instance to update
            
        Returns:
            True if record was updated, False otherwise
        """
        if not model.id:
            return False
        
        data = model.to_dict()
        data['updated_at'] = datetime.now().isoformat()
        record_id = data.pop('id')
        
        set_clause = ', '.join([f"{col} = ?" for col in data.keys()])
        query = f"UPDATE {self.table_name} SET {set_clause} WHERE id = ?"
        
        return self.db.execute_update(query, tuple(data.values()) + (record_id,)) > 0
    
    def delete(self, record_id: int) -> bool:
        """Delete record by ID.
        
        Args:
            record_id: Record ID to delete
            
        Returns:
            True if record was deleted, False otherwise
        """
        query = f"DELETE FROM {self.table_name} WHERE id = ?"
        return self.db.execute_delete(query, (record_id,)) > 0
    
    def count(self) -> int:
        """Get total number of records in table.
        
        Returns:
            Total record count
        """
        query = f"SELECT COUNT(*) as count FROM {self.table_name}"
        results = self.db.execute_query(query)
        return results[0]['count'] if results else 0


class ScanResultRepository(BaseRepository):
    """Repository for scan results."""
    
    @property
    def table_name(self) -> str:
        return "scan_results"
    
    @property
    def model_class(self) -> Type[ScanResultModel]:
        return ScanResultModel
    
    def get_by_scan_path(self, scan_path: str) -> List[ScanResultModel]:
        """Get scan results by scan path.
        
        Args:
            scan_path: Path that was scanned
            
        Returns:
            List of scan results for the path
        """
        query = "SELECT * FROM scan_results WHERE scan_path = ? ORDER BY timestamp DESC"
        results = self.db.execute_query(query, (scan_path,))
        return [ScanResultModel.from_dict(row) for row in results]
    
    def get_latest_by_path(self, scan_path: str) -> Optional[ScanResultModel]:
        """Get most recent scan result for a path.
        
        Args:
            scan_path: Path that was scanned
            
        Returns:
            Most recent scan result or None
        """
        query = "SELECT * FROM scan_results WHERE scan_path = ? ORDER BY timestamp DESC LIMIT 1"
        results = self.db.execute_query(query, (scan_path,))
        
        if results:
            return ScanResultModel.from_dict(results[0])
        return None
    
    def get_recent_scans(self, limit: int = 10) -> List[ScanResultModel]:
        """Get most recent scan results.
        
        Args:
            limit: Maximum number of results to return
            
        Returns:
            List of recent scan results
        """
        query = "SELECT * FROM scan_results ORDER BY timestamp DESC LIMIT ?"
        results = self.db.execute_query(query, (limit,))
        return [ScanResultModel.from_dict(row) for row in results]


class VulnerabilityRepository(BaseRepository):
    """Repository for vulnerabilities."""
    
    @property
    def table_name(self) -> str:
        return "vulnerabilities"
    
    @property
    def model_class(self) -> Type[VulnerabilityModel]:
        return VulnerabilityModel
    
    def get_by_scan_result(self, scan_result_id: int) -> List[VulnerabilityModel]:
        """Get vulnerabilities for a scan result.
        
        Args:
            scan_result_id: Scan result ID
            
        Returns:
            List of vulnerabilities
        """
        query = "SELECT * FROM vulnerabilities WHERE scan_result_id = ? ORDER BY severity DESC, line_number ASC"
        results = self.db.execute_query(query, (scan_result_id,))
        return [VulnerabilityModel.from_dict(row) for row in results]
    
    def get_by_severity(self, severity: str) -> List[VulnerabilityModel]:
        """Get vulnerabilities by severity level.
        
        Args:
            severity: Severity level (critical, high, medium, low)
            
        Returns:
            List of vulnerabilities with specified severity
        """
        query = "SELECT * FROM vulnerabilities WHERE severity = ? ORDER BY created_at DESC"
        results = self.db.execute_query(query, (severity,))
        return [VulnerabilityModel.from_dict(row) for row in results]
    
    def get_by_algorithm(self, algorithm: str) -> List[VulnerabilityModel]:
        """Get vulnerabilities by algorithm type.
        
        Args:
            algorithm: Algorithm name (RSA, ECC, DSA, etc.)
            
        Returns:
            List of vulnerabilities for specified algorithm
        """
        query = "SELECT * FROM vulnerabilities WHERE algorithm = ? ORDER BY created_at DESC"
        results = self.db.execute_query(query, (algorithm,))
        return [VulnerabilityModel.from_dict(row) for row in results]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get vulnerability statistics.
        
        Returns:
            Dictionary with vulnerability statistics
        """
        # Severity distribution
        severity_query = """
            SELECT severity, COUNT(*) as count 
            FROM vulnerabilities 
            GROUP BY severity
        """
        severity_results = self.db.execute_query(severity_query)
        severity_stats = {row['severity']: row['count'] for row in severity_results}
        
        # Algorithm distribution
        algorithm_query = """
            SELECT algorithm, COUNT(*) as count 
            FROM vulnerabilities 
            GROUP BY algorithm
        """
        algorithm_results = self.db.execute_query(algorithm_query)
        algorithm_stats = {row['algorithm']: row['count'] for row in algorithm_results}
        
        # Total count
        total_count = self.count()
        
        return {
            'total_vulnerabilities': total_count,
            'by_severity': severity_stats,
            'by_algorithm': algorithm_stats
        }


class MigrationPlanRepository(BaseRepository):
    """Repository for migration plans."""
    
    @property
    def table_name(self) -> str:
        return "migration_plans"
    
    @property
    def model_class(self) -> Type[MigrationPlanModel]:
        return MigrationPlanModel
    
    def get_by_scan_result(self, scan_result_id: int) -> Optional[MigrationPlanModel]:
        """Get migration plan for a scan result.
        
        Args:
            scan_result_id: Scan result ID
            
        Returns:
            Migration plan or None if not found
        """
        query = "SELECT * FROM migration_plans WHERE scan_result_id = ? ORDER BY created_at DESC LIMIT 1"
        results = self.db.execute_query(query, (scan_result_id,))
        
        if results:
            return MigrationPlanModel.from_dict(results[0])
        return None


class RiskAssessmentRepository(BaseRepository):
    """Repository for risk assessments."""
    
    @property
    def table_name(self) -> str:
        return "risk_assessments"
    
    @property
    def model_class(self) -> Type[RiskAssessmentModel]:
        return RiskAssessmentModel
    
    def get_by_scan_result(self, scan_result_id: int) -> Optional[RiskAssessmentModel]:
        """Get risk assessment for a scan result.
        
        Args:
            scan_result_id: Scan result ID
            
        Returns:
            Risk assessment or None if not found
        """
        query = "SELECT * FROM risk_assessments WHERE scan_result_id = ? ORDER BY created_at DESC LIMIT 1"
        results = self.db.execute_query(query, (scan_result_id,))
        
        if results:
            return RiskAssessmentModel.from_dict(results[0])
        return None
    
    def get_high_risk_assessments(self, threshold: int = 70) -> List[RiskAssessmentModel]:
        """Get high-risk assessments above threshold.
        
        Args:
            threshold: Minimum risk score threshold
            
        Returns:
            List of high-risk assessments
        """
        query = "SELECT * FROM risk_assessments WHERE hndl_risk_score >= ? ORDER BY hndl_risk_score DESC"
        results = self.db.execute_query(query, (threshold,))
        return [RiskAssessmentModel.from_dict(row) for row in results]


class InventoryItemRepository(BaseRepository):
    """Repository for inventory items."""
    
    @property
    def table_name(self) -> str:
        return "inventory_items"
    
    @property
    def model_class(self) -> Type[InventoryItemModel]:
        return InventoryItemModel
    
    def get_by_scan_result(self, scan_result_id: int) -> List[InventoryItemModel]:
        """Get inventory items for a scan result.
        
        Args:
            scan_result_id: Scan result ID
            
        Returns:
            List of inventory items
        """
        query = "SELECT * FROM inventory_items WHERE scan_result_id = ? ORDER BY migration_priority DESC, name ASC"
        results = self.db.execute_query(query, (scan_result_id,))
        return [InventoryItemModel.from_dict(row) for row in results]
    
    def get_by_priority(self, priority: str) -> List[InventoryItemModel]:
        """Get inventory items by migration priority.
        
        Args:
            priority: Migration priority (critical, high, medium, low)
            
        Returns:
            List of inventory items with specified priority
        """
        query = "SELECT * FROM inventory_items WHERE migration_priority = ? ORDER BY last_updated DESC"
        results = self.db.execute_query(query, (priority,))
        return [InventoryItemModel.from_dict(row) for row in results]
    
    def get_pqc_ready_items(self) -> List[InventoryItemModel]:
        """Get items that are already PQC ready.
        
        Returns:
            List of PQC ready inventory items
        """
        query = "SELECT * FROM inventory_items WHERE pqc_ready = 1 ORDER BY last_updated DESC"
        results = self.db.execute_query(query)
        return [InventoryItemModel.from_dict(row) for row in results]


class ComplianceAssessmentRepository(BaseRepository):
    """Repository for compliance assessments."""
    
    @property
    def table_name(self) -> str:
        return "compliance_assessments"
    
    @property
    def model_class(self) -> Type[ComplianceAssessmentModel]:
        return ComplianceAssessmentModel
    
    def get_by_scan_result(self, scan_result_id: int) -> List[ComplianceAssessmentModel]:
        """Get compliance assessments for a scan result.
        
        Args:
            scan_result_id: Scan result ID
            
        Returns:
            List of compliance assessments
        """
        query = "SELECT * FROM compliance_assessments WHERE scan_result_id = ? ORDER BY framework ASC"
        results = self.db.execute_query(query, (scan_result_id,))
        return [ComplianceAssessmentModel.from_dict(row) for row in results]
    
    def get_by_framework(self, framework: str) -> List[ComplianceAssessmentModel]:
        """Get compliance assessments by framework.
        
        Args:
            framework: Framework name (NIST, BSI, ANSSI, etc.)
            
        Returns:
            List of compliance assessments for framework
        """
        query = "SELECT * FROM compliance_assessments WHERE framework = ? ORDER BY created_at DESC"
        results = self.db.execute_query(query, (framework,))
        return [ComplianceAssessmentModel.from_dict(row) for row in results]
    
    def get_compliance_overview(self) -> Dict[str, Any]:
        """Get compliance overview across all frameworks.
        
        Returns:
            Dictionary with compliance overview
        """
        query = """
            SELECT 
                framework,
                AVG(compliance_percentage) as avg_compliance,
                COUNT(*) as assessment_count,
                MAX(created_at) as latest_assessment
            FROM compliance_assessments 
            GROUP BY framework
            ORDER BY avg_compliance DESC
        """
        results = self.db.execute_query(query)
        
        return {
            'frameworks': [
                {
                    'framework': row['framework'],
                    'average_compliance': row['avg_compliance'],
                    'assessment_count': row['assessment_count'],
                    'latest_assessment': row['latest_assessment']
                }
                for row in results
            ]
        }