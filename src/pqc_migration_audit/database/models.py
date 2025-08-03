"""Database models for PQC Migration Audit."""

from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from datetime import datetime
import json


@dataclass
class ScanResultModel:
    """Database model for scan results."""
    
    id: Optional[int] = None
    scan_path: str = ""
    timestamp: str = ""
    scan_time: float = 0.0
    scanned_files: int = 0
    total_lines: int = 0
    languages_detected: List[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.languages_detected is None:
            self.languages_detected = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage."""
        return {
            'id': self.id,
            'scan_path': self.scan_path,
            'timestamp': self.timestamp,
            'scan_time': self.scan_time,
            'scanned_files': self.scanned_files,
            'total_lines': self.total_lines,
            'languages_detected': json.dumps(self.languages_detected),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanResultModel':
        """Create instance from dictionary."""
        languages = json.loads(data.get('languages_detected', '[]'))
        
        return cls(
            id=data.get('id'),
            scan_path=data.get('scan_path', ''),
            timestamp=data.get('timestamp', ''),
            scan_time=data.get('scan_time', 0.0),
            scanned_files=data.get('scanned_files', 0),
            total_lines=data.get('total_lines', 0),
            languages_detected=languages,
            created_at=datetime.fromisoformat(data['created_at']) if data.get('created_at') else None,
            updated_at=datetime.fromisoformat(data['updated_at']) if data.get('updated_at') else None
        )


@dataclass
class VulnerabilityModel:
    """Database model for vulnerabilities."""
    
    id: Optional[int] = None
    scan_result_id: int = 0
    file_path: str = ""
    line_number: int = 0
    algorithm: str = ""
    severity: str = ""
    key_size: Optional[int] = None
    description: str = ""
    code_snippet: str = ""
    recommendation: str = ""
    cwe_id: Optional[str] = None
    created_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage."""
        return {
            'id': self.id,
            'scan_result_id': self.scan_result_id,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'algorithm': self.algorithm,
            'severity': self.severity,
            'key_size': self.key_size,
            'description': self.description,
            'code_snippet': self.code_snippet,
            'recommendation': self.recommendation,
            'cwe_id': self.cwe_id,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VulnerabilityModel':
        """Create instance from dictionary."""
        return cls(
            id=data.get('id'),
            scan_result_id=data.get('scan_result_id', 0),
            file_path=data.get('file_path', ''),
            line_number=data.get('line_number', 0),
            algorithm=data.get('algorithm', ''),
            severity=data.get('severity', ''),
            key_size=data.get('key_size'),
            description=data.get('description', ''),
            code_snippet=data.get('code_snippet', ''),
            recommendation=data.get('recommendation', ''),
            cwe_id=data.get('cwe_id'),
            created_at=datetime.fromisoformat(data['created_at']) if data.get('created_at') else None
        )


@dataclass
class MigrationPlanModel:
    """Database model for migration plans."""
    
    id: Optional[int] = None
    scan_result_id: int = 0
    plan_data: Dict[str, Any] = None
    created_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.plan_data is None:
            self.plan_data = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage."""
        return {
            'id': self.id,
            'scan_result_id': self.scan_result_id,
            'plan_data': json.dumps(self.plan_data),
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MigrationPlanModel':
        """Create instance from dictionary."""
        plan_data = json.loads(data.get('plan_data', '{}'))
        
        return cls(
            id=data.get('id'),
            scan_result_id=data.get('scan_result_id', 0),
            plan_data=plan_data,
            created_at=datetime.fromisoformat(data['created_at']) if data.get('created_at') else None
        )


@dataclass
class RiskAssessmentModel:
    """Database model for risk assessments."""
    
    id: Optional[int] = None
    scan_result_id: int = 0
    hndl_risk_score: int = 0
    migration_hours: int = 0
    risk_level: str = ""
    assessment_data: Dict[str, Any] = None
    created_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.assessment_data is None:
            self.assessment_data = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage."""
        return {
            'id': self.id,
            'scan_result_id': self.scan_result_id,
            'hndl_risk_score': self.hndl_risk_score,
            'migration_hours': self.migration_hours,
            'risk_level': self.risk_level,
            'assessment_data': json.dumps(self.assessment_data),
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RiskAssessmentModel':
        """Create instance from dictionary."""
        assessment_data = json.loads(data.get('assessment_data', '{}'))
        
        return cls(
            id=data.get('id'),
            scan_result_id=data.get('scan_result_id', 0),
            hndl_risk_score=data.get('hndl_risk_score', 0),
            migration_hours=data.get('migration_hours', 0),
            risk_level=data.get('risk_level', ''),
            assessment_data=assessment_data,
            created_at=datetime.fromisoformat(data['created_at']) if data.get('created_at') else None
        )


@dataclass
class InventoryItemModel:
    """Database model for cryptographic inventory items."""
    
    id: Optional[int] = None
    scan_result_id: int = 0
    name: str = ""
    version: Optional[str] = None
    location: str = ""
    algorithms: List[str] = None
    key_sizes: List[int] = None
    usage_context: str = ""
    pqc_ready: bool = False
    migration_priority: str = ""
    last_updated: Optional[datetime] = None
    
    def __post_init__(self):
        if self.algorithms is None:
            self.algorithms = []
        if self.key_sizes is None:
            self.key_sizes = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage."""
        return {
            'id': self.id,
            'scan_result_id': self.scan_result_id,
            'name': self.name,
            'version': self.version,
            'location': self.location,
            'algorithms': json.dumps(self.algorithms),
            'key_sizes': json.dumps(self.key_sizes),
            'usage_context': self.usage_context,
            'pqc_ready': self.pqc_ready,
            'migration_priority': self.migration_priority,
            'last_updated': self.last_updated.isoformat() if self.last_updated else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'InventoryItemModel':
        """Create instance from dictionary."""
        algorithms = json.loads(data.get('algorithms', '[]'))
        key_sizes = json.loads(data.get('key_sizes', '[]'))
        
        return cls(
            id=data.get('id'),
            scan_result_id=data.get('scan_result_id', 0),
            name=data.get('name', ''),
            version=data.get('version'),
            location=data.get('location', ''),
            algorithms=algorithms,
            key_sizes=key_sizes,
            usage_context=data.get('usage_context', ''),
            pqc_ready=bool(data.get('pqc_ready', False)),
            migration_priority=data.get('migration_priority', ''),
            last_updated=datetime.fromisoformat(data['last_updated']) if data.get('last_updated') else None
        )


@dataclass
class ComplianceAssessmentModel:
    """Database model for compliance assessments."""
    
    id: Optional[int] = None
    scan_result_id: int = 0
    framework: str = ""
    compliance_percentage: float = 0.0
    requirements_met: List[str] = None
    requirements_pending: List[str] = None
    deadline: str = ""
    risk_level: str = ""
    created_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.requirements_met is None:
            self.requirements_met = []
        if self.requirements_pending is None:
            self.requirements_pending = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage."""
        return {
            'id': self.id,
            'scan_result_id': self.scan_result_id,
            'framework': self.framework,
            'compliance_percentage': self.compliance_percentage,
            'requirements_met': json.dumps(self.requirements_met),
            'requirements_pending': json.dumps(self.requirements_pending),
            'deadline': self.deadline,
            'risk_level': self.risk_level,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ComplianceAssessmentModel':
        """Create instance from dictionary."""
        requirements_met = json.loads(data.get('requirements_met', '[]'))
        requirements_pending = json.loads(data.get('requirements_pending', '[]'))
        
        return cls(
            id=data.get('id'),
            scan_result_id=data.get('scan_result_id', 0),
            framework=data.get('framework', ''),
            compliance_percentage=data.get('compliance_percentage', 0.0),
            requirements_met=requirements_met,
            requirements_pending=requirements_pending,
            deadline=data.get('deadline', ''),
            risk_level=data.get('risk_level', ''),
            created_at=datetime.fromisoformat(data['created_at']) if data.get('created_at') else None
        )