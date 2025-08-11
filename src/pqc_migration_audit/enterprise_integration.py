"""Enterprise-grade integrations for SIEM, SOAR, and security orchestration."""

import time
import json
import logging
import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, AsyncGenerator
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import uuid
from urllib.parse import urlparse, urljoin
import ssl
import socket
from contextlib import asynccontextmanager

# Enterprise integrations
import aiohttp
import websockets
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID

from .types import Severity, Vulnerability, ScanResults
from .exceptions import PQCAuditException
from .core import CryptoAuditor, RiskAssessment


class IntegrationType(Enum):
    """Types of enterprise integrations."""
    SIEM = "siem"
    SOAR = "soar"
    TICKETING = "ticketing"
    VULNERABILITY_MANAGEMENT = "vulnerability_management"
    THREAT_INTELLIGENCE = "threat_intelligence"
    COMPLIANCE_REPORTING = "compliance_reporting"
    ASSET_MANAGEMENT = "asset_management"
    CHANGE_MANAGEMENT = "change_management"


class AlertSeverity(Enum):
    """Alert severity levels for enterprise systems."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


@dataclass
class EnterpriseAlert:
    """Structured alert for enterprise systems."""
    alert_id: str
    title: str
    description: str
    severity: AlertSeverity
    category: str
    source_system: str
    timestamp: str
    affected_assets: List[str]
    vulnerabilities: List[Dict[str, Any]]
    remediation_steps: List[str]
    business_impact: str
    compliance_implications: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IntegrationConfig:
    """Configuration for enterprise integrations."""
    integration_type: IntegrationType
    endpoint_url: str
    authentication: Dict[str, Any]
    encryption_config: Dict[str, Any]
    retry_config: Dict[str, Any]
    rate_limiting: Dict[str, Any]
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True


class SIEMConnector:
    """Connector for SIEM (Security Information and Event Management) systems."""
    
    def __init__(self, config: IntegrationConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = None
        self.connection_pool = None
        
        # SIEM-specific configuration
        self.event_format = config.custom_fields.get('event_format', 'CEF')  # CEF, LEEF, JSON
        self.facility = config.custom_fields.get('syslog_facility', 16)  # Local use 0
        self.priority = config.custom_fields.get('syslog_priority', 6)  # Info level
        
        # Message formatting templates
        self.cef_template = "CEF:0|TerragonLabs|PQC-Migration-Audit|1.0|{signature_id}|{name}|{severity}|{extensions}"
        
    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.disconnect()
    
    async def connect(self):
        """Establish connection to SIEM system."""
        try:
            # Create SSL context for secure connections
            ssl_context = ssl.create_default_context()
            if self.config.encryption_config.get('verify_ssl', True) is False:
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            
            # Configure client certificates if provided
            cert_file = self.config.encryption_config.get('client_cert')
            key_file = self.config.encryption_config.get('client_key')
            if cert_file and key_file:
                ssl_context.load_cert_chain(cert_file, key_file)
            
            # Create HTTP session with proper timeouts and retries
            timeout = aiohttp.ClientTimeout(
                total=self.config.retry_config.get('timeout', 30),
                connect=self.config.retry_config.get('connect_timeout', 10)
            )
            
            connector = aiohttp.TCPConnector(
                ssl=ssl_context,
                limit=self.config.rate_limiting.get('max_connections', 10),
                limit_per_host=self.config.rate_limiting.get('max_per_host', 5)
            )
            
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers=self._get_auth_headers()
            )
            
            # Test connection
            await self._test_connection()
            
            self.logger.info(f"Successfully connected to SIEM system: {self.config.endpoint_url}")
            
        except Exception as e:
            self.logger.error(f"Failed to connect to SIEM system: {e}")
            raise PQCAuditException(f"SIEM connection failed: {e}", error_code="SIEM_CONNECTION_ERROR")
    
    async def disconnect(self):
        """Close connection to SIEM system."""
        if self.session:
            await self.session.close()
            self.session = None
            self.logger.info("Disconnected from SIEM system")
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers based on config."""
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'PQC-Migration-Audit/1.0'
        }
        
        auth_config = self.config.authentication
        auth_type = auth_config.get('type', 'none')
        
        if auth_type == 'bearer':
            headers['Authorization'] = f"Bearer {auth_config['token']}"
        elif auth_type == 'api_key':
            headers[auth_config.get('header_name', 'X-API-Key')] = auth_config['api_key']
        elif auth_type == 'basic':
            import base64
            credentials = f"{auth_config['username']}:{auth_config['password']}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            headers['Authorization'] = f"Basic {encoded_credentials}"
        
        return headers
    
    async def _test_connection(self):
        """Test connection to SIEM system."""
        health_endpoint = self.config.custom_fields.get('health_endpoint', '/health')
        test_url = urljoin(self.config.endpoint_url, health_endpoint)
        
        async with self.session.get(test_url) as response:
            if response.status >= 400:
                raise PQCAuditException(
                    f"SIEM health check failed: HTTP {response.status}",
                    error_code="SIEM_HEALTH_CHECK_FAILED"
                )
    
    async def send_pqc_scan_results(self, scan_results: ScanResults, 
                                   scan_metadata: Dict[str, Any] = None) -> bool:
        """Send PQC scan results to SIEM system."""
        try:
            # Generate enterprise alert from scan results
            alert = self._create_pqc_alert(scan_results, scan_metadata or {})
            
            # Format message based on SIEM requirements
            if self.event_format == 'CEF':
                message = self._format_cef_message(alert)
            elif self.event_format == 'LEEF':
                message = self._format_leef_message(alert)
            else:  # JSON
                message = self._format_json_message(alert)
            
            # Send to SIEM endpoint
            success = await self._send_message(message, alert)
            
            if success:
                self.logger.info(f"Successfully sent PQC scan results to SIEM (Alert ID: {alert.alert_id})")
            else:
                self.logger.error(f"Failed to send PQC scan results to SIEM (Alert ID: {alert.alert_id})")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error sending scan results to SIEM: {e}")
            return False
    
    def _create_pqc_alert(self, scan_results: ScanResults, metadata: Dict[str, Any]) -> EnterpriseAlert:
        """Create enterprise alert from PQC scan results."""
        # Calculate alert severity based on findings
        severity = self._calculate_alert_severity(scan_results.vulnerabilities)
        
        # Identify affected assets
        affected_files = list(set(vuln.file_path for vuln in scan_results.vulnerabilities))
        
        # Create vulnerability summaries
        vuln_summaries = []
        for vuln in scan_results.vulnerabilities[:10]:  # Limit to first 10 for SIEM
            vuln_summaries.append({
                'file': vuln.file_path,
                'line': vuln.line_number,
                'algorithm': vuln.algorithm.value,
                'severity': vuln.severity.value,
                'description': vuln.description,
                'cwe_id': vuln.cwe_id
            })
        
        # Generate remediation steps
        remediation_steps = [
            "Review identified quantum-vulnerable cryptographic implementations",
            "Plan migration to post-quantum cryptographic algorithms (ML-KEM, ML-DSA)",
            "Implement crypto-agility framework for future algorithm transitions",
            "Conduct security architecture review for affected systems",
            "Update threat models to include quantum computing risks"
        ]
        
        # Assess business impact
        critical_count = len([v for v in scan_results.vulnerabilities if v.severity == Severity.CRITICAL])
        high_count = len([v for v in scan_results.vulnerabilities if v.severity == Severity.HIGH])
        
        if critical_count > 0:
            business_impact = f"CRITICAL: {critical_count} critical quantum vulnerabilities found"
        elif high_count > 5:
            business_impact = f"HIGH: {high_count} high-severity quantum vulnerabilities found"
        else:
            business_impact = "MEDIUM: Quantum-vulnerable cryptography detected"
        
        # Compliance implications
        compliance_implications = []
        if critical_count > 0 or high_count > 10:
            compliance_implications.extend([
                "NIST Cybersecurity Framework: Impact on Protect function",
                "ISO 27001: Cryptographic controls may need updating",
                "PCI DSS: Payment systems may require crypto-agility assessment"
            ])
        
        alert = EnterpriseAlert(
            alert_id=f"PQC-{uuid.uuid4().hex[:8]}",
            title=f"Post-Quantum Cryptography Vulnerability Scan Results",
            description=f"Detected {len(scan_results.vulnerabilities)} quantum-vulnerable cryptographic implementations across {scan_results.scanned_files} files",
            severity=severity,
            category="Cryptographic Vulnerability",
            source_system="PQC-Migration-Audit",
            timestamp=datetime.now().isoformat(),
            affected_assets=affected_files,
            vulnerabilities=vuln_summaries,
            remediation_steps=remediation_steps,
            business_impact=business_impact,
            compliance_implications=compliance_implications,
            metadata={
                'scan_path': scan_results.scan_path,
                'scan_timestamp': scan_results.timestamp,
                'scan_duration': scan_results.scan_time,
                'languages_detected': scan_results.languages_detected,
                'total_lines_scanned': scan_results.total_lines,
                **metadata
            }
        )
        
        return alert
    
    def _calculate_alert_severity(self, vulnerabilities: List[Vulnerability]) -> AlertSeverity:
        """Calculate SIEM alert severity from vulnerabilities."""
        if not vulnerabilities:
            return AlertSeverity.INFO
        
        critical_count = len([v for v in vulnerabilities if v.severity == Severity.CRITICAL])
        high_count = len([v for v in vulnerabilities if v.severity == Severity.HIGH])
        
        if critical_count >= 5:
            return AlertSeverity.EMERGENCY
        elif critical_count >= 1:
            return AlertSeverity.CRITICAL
        elif high_count >= 10:
            return AlertSeverity.HIGH
        elif high_count >= 1:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW
    
    def _format_cef_message(self, alert: EnterpriseAlert) -> str:
        """Format alert as CEF (Common Event Format) message."""
        # CEF extensions
        extensions = [
            f"deviceVendor=TerragonLabs",
            f"deviceProduct=PQC-Migration-Audit",
            f"deviceVersion=1.0",
            f"start={int(datetime.fromisoformat(alert.timestamp).timestamp() * 1000)}",
            f"cnt={len(alert.vulnerabilities)}",
            f"cs1Label=BusinessImpact",
            f"cs1={alert.business_impact}",
            f"cs2Label=Category",
            f"cs2={alert.category}",
            f"cs3Label=AffectedAssets",
            f"cs3={len(alert.affected_assets)}",
            f"msg={alert.description[:512]}",  # Limit message length
        ]
        
        cef_message = self.cef_template.format(
            signature_id=f"PQC_{alert.severity.value.upper()}",
            name=alert.title,
            severity=self._map_severity_to_cef(alert.severity),
            extensions=" ".join(extensions)
        )
        
        return cef_message
    
    def _format_leef_message(self, alert: EnterpriseAlert) -> str:
        """Format alert as LEEF (Log Event Extended Format) message."""
        # LEEF 2.0 format
        leef_fields = {
            'devTime': alert.timestamp,
            'devTimeFormat': 'ISO',
            'cat': alert.category,
            'sev': str(self._map_severity_to_leef(alert.severity)),
            'src': alert.source_system,
            'srcPort': '443',
            'dst': 'SIEM',
            'msg': alert.description,
            'usrName': 'pqc-audit-system',
            'domain': 'security',
            'resource': f"{len(alert.affected_assets)} files",
            'proto': 'HTTPS',
            'identSrc': alert.alert_id
        }
        
        leef_extensions = "\t".join(f"{k}={v}" for k, v in leef_fields.items())
        leef_message = f"LEEF:2.0|TerragonLabs|PQC-Migration-Audit|1.0|PQC_SCAN|{leef_extensions}"
        
        return leef_message
    
    def _format_json_message(self, alert: EnterpriseAlert) -> Dict[str, Any]:
        """Format alert as JSON message."""
        return {
            'alert_id': alert.alert_id,
            'timestamp': alert.timestamp,
            'source': alert.source_system,
            'event_type': 'pqc_vulnerability_scan',
            'severity': alert.severity.value,
            'category': alert.category,
            'title': alert.title,
            'description': alert.description,
            'affected_assets': alert.affected_assets,
            'vulnerability_count': len(alert.vulnerabilities),
            'vulnerabilities': alert.vulnerabilities,
            'business_impact': alert.business_impact,
            'compliance_implications': alert.compliance_implications,
            'remediation_steps': alert.remediation_steps,
            'metadata': alert.metadata
        }
    
    def _map_severity_to_cef(self, severity: AlertSeverity) -> str:
        """Map alert severity to CEF severity scale (0-10)."""
        severity_map = {
            AlertSeverity.INFO: "2",
            AlertSeverity.LOW: "3",
            AlertSeverity.MEDIUM: "5",
            AlertSeverity.HIGH: "7",
            AlertSeverity.CRITICAL: "9",
            AlertSeverity.EMERGENCY: "10"
        }
        return severity_map.get(severity, "5")
    
    def _map_severity_to_leef(self, severity: AlertSeverity) -> int:
        """Map alert severity to LEEF severity scale (0-10)."""
        severity_map = {
            AlertSeverity.INFO: 2,
            AlertSeverity.LOW: 3,
            AlertSeverity.MEDIUM: 5,
            AlertSeverity.HIGH: 7,
            AlertSeverity.CRITICAL: 9,
            AlertSeverity.EMERGENCY: 10
        }
        return severity_map.get(severity, 5)
    
    async def _send_message(self, message: str, alert: EnterpriseAlert) -> bool:
        """Send formatted message to SIEM endpoint."""
        try:
            # Determine endpoint based on SIEM type
            endpoint = self.config.custom_fields.get('events_endpoint', '/api/events')
            url = urljoin(self.config.endpoint_url, endpoint)
            
            # Prepare payload based on format
            if self.event_format == 'JSON':
                payload = message  # Already a dict
                headers = {'Content-Type': 'application/json'}
            else:
                # CEF/LEEF as string payload
                payload = {'message': message}
                headers = {'Content-Type': 'application/json'}
            
            # Add custom headers
            headers.update(self.config.custom_fields.get('custom_headers', {}))
            
            # Send with retry logic
            max_retries = self.config.retry_config.get('max_retries', 3)
            retry_delay = self.config.retry_config.get('retry_delay', 1)
            
            for attempt in range(max_retries + 1):
                try:
                    async with self.session.post(url, json=payload, headers=headers) as response:
                        if response.status < 400:
                            response_data = await response.text()
                            self.logger.debug(f"SIEM response: {response.status} - {response_data[:200]}...")
                            return True
                        else:
                            error_text = await response.text()
                            self.logger.warning(f"SIEM request failed: {response.status} - {error_text}")
                            
                            if response.status < 500 and attempt == max_retries:
                                # Client error, don't retry
                                return False
                                
                except aiohttp.ClientError as e:
                    self.logger.warning(f"SIEM connection error (attempt {attempt + 1}): {e}")
                    
                    if attempt < max_retries:
                        await asyncio.sleep(retry_delay * (2 ** attempt))  # Exponential backoff
                    else:
                        return False
            
            return False
            
        except Exception as e:
            self.logger.error(f"Unexpected error sending to SIEM: {e}")
            return False


class SOARConnector:
    """Connector for SOAR (Security Orchestration, Automation, and Response) systems."""
    
    def __init__(self, config: IntegrationConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = None
        
        # SOAR-specific configuration
        self.playbook_templates = config.custom_fields.get('playbook_templates', {})
        self.incident_types = config.custom_fields.get('incident_types', {
            'pqc_vulnerability': 'Post-Quantum Cryptography Vulnerability',
            'crypto_migration': 'Cryptographic Migration Required'
        })
        
    async def create_pqc_incident(self, scan_results: ScanResults, 
                                 metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """Create incident in SOAR system for PQC vulnerabilities."""
        try:
            # Analyze scan results to determine incident characteristics
            incident_data = self._analyze_scan_for_incident(scan_results, metadata or {})
            
            # Create incident payload
            incident_payload = {
                'title': incident_data['title'],
                'description': incident_data['description'],
                'severity': incident_data['severity'],
                'type': incident_data['type'],
                'source': 'PQC-Migration-Audit',
                'created_by': 'pqc-audit-system',
                'priority': incident_data['priority'],
                'tags': incident_data['tags'],
                'artifacts': incident_data['artifacts'],
                'custom_fields': {
                    'pqc_scan_path': scan_results.scan_path,
                    'vulnerability_count': len(scan_results.vulnerabilities),
                    'files_affected': scan_results.scanned_files,
                    'languages_detected': ','.join(scan_results.languages_detected),
                    'scan_duration': scan_results.scan_time,
                    'quantum_threat_level': incident_data['quantum_threat_level']
                }
            }
            
            # Send to SOAR
            response = await self._create_incident(incident_payload)
            
            # Trigger automated playbooks if configured
            if response.get('incident_id') and self.playbook_templates:
                await self._trigger_playbooks(response['incident_id'], incident_data)
            
            return response
            
        except Exception as e:
            self.logger.error(f"Error creating SOAR incident: {e}")
            raise PQCAuditException(f"SOAR incident creation failed: {e}", error_code="SOAR_INCIDENT_ERROR")
    
    def _analyze_scan_for_incident(self, scan_results: ScanResults, 
                                  metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze scan results to determine incident characteristics."""
        # Calculate risk metrics
        critical_count = len([v for v in scan_results.vulnerabilities if v.severity == Severity.CRITICAL])
        high_count = len([v for v in scan_results.vulnerabilities if v.severity == Severity.HIGH])
        total_count = len(scan_results.vulnerabilities)
        
        # Determine incident severity and priority
        if critical_count >= 5:
            severity = 'Critical'
            priority = 'P1'
            quantum_threat_level = 'Imminent'
        elif critical_count >= 1 or high_count >= 10:
            severity = 'High'
            priority = 'P2' 
            quantum_threat_level = 'High'
        elif high_count >= 1 or total_count >= 20:
            severity = 'Medium'
            priority = 'P3'
            quantum_threat_level = 'Medium'
        else:
            severity = 'Low'
            priority = 'P4'
            quantum_threat_level = 'Low'
        
        # Generate incident title and description
        title = f"Post-Quantum Cryptography Vulnerabilities Detected - {total_count} Issues Found"
        
        description = f"""PQC Migration Audit has identified quantum-vulnerable cryptographic implementations requiring attention.

**Scan Summary:**
- Scan Path: {scan_results.scan_path}
- Files Scanned: {scan_results.scanned_files}
- Total Vulnerabilities: {total_count}
- Critical: {critical_count}
- High: {high_count}
- Languages: {', '.join(scan_results.languages_detected)}

**Quantum Threat Assessment:**
- Threat Level: {quantum_threat_level}
- Harvest Now, Decrypt Later (HNDL) Risk: Active
- Migration Timeline: Critical vulnerabilities require immediate attention

**Business Impact:**
Quantum-vulnerable cryptographic implementations pose long-term security risks as quantum computing capabilities advance. Organizations must begin migration planning to maintain data confidentiality and integrity.

**Next Steps:**
1. Review identified vulnerabilities in priority order
2. Assess business impact of affected systems
3. Develop post-quantum cryptography migration plan
4. Implement crypto-agility framework
5. Begin testing of NIST-standardized PQC algorithms
"""
        
        # Generate tags
        tags = ['pqc', 'quantum-vulnerability', 'cryptography', 'migration-required']
        if critical_count > 0:
            tags.append('critical-risk')
        if 'rsa' in str(scan_results.vulnerabilities).lower():
            tags.append('rsa-vulnerable')
        if 'ecc' in str(scan_results.vulnerabilities).lower():
            tags.append('ecc-vulnerable')
        
        # Create artifacts (evidence)
        artifacts = []
        for vuln in scan_results.vulnerabilities[:10]:  # Limit artifacts
            artifacts.append({
                'type': 'file',
                'value': vuln.file_path,
                'description': f"File containing {vuln.algorithm.value} vulnerability at line {vuln.line_number}",
                'metadata': {
                    'line_number': vuln.line_number,
                    'algorithm': vuln.algorithm.value,
                    'severity': vuln.severity.value,
                    'cwe_id': vuln.cwe_id
                }
            })
        
        return {
            'title': title,
            'description': description,
            'severity': severity,
            'priority': priority,
            'type': self.incident_types.get('pqc_vulnerability', 'Security Incident'),
            'quantum_threat_level': quantum_threat_level,
            'tags': tags,
            'artifacts': artifacts
        }
    
    async def _create_incident(self, incident_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Create incident in SOAR system."""
        # Implementation would depend on specific SOAR platform (Phantom, Demisto, etc.)
        # This is a generic REST API approach
        
        incidents_endpoint = self.config.custom_fields.get('incidents_endpoint', '/api/incidents')
        url = urljoin(self.config.endpoint_url, incidents_endpoint)
        
        headers = self._get_auth_headers()
        headers['Content-Type'] = 'application/json'
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=incident_payload, headers=headers) as response:
                if response.status < 400:
                    result = await response.json()
                    self.logger.info(f"Created SOAR incident: {result.get('incident_id', 'unknown')}")
                    return result
                else:
                    error_text = await response.text()
                    raise PQCAuditException(
                        f"SOAR incident creation failed: {response.status} - {error_text}",
                        error_code="SOAR_API_ERROR"
                    )
    
    async def _trigger_playbooks(self, incident_id: str, incident_data: Dict[str, Any]):
        """Trigger automated playbooks for the incident."""
        try:
            playbooks_to_trigger = []
            
            # Determine which playbooks to trigger based on incident characteristics
            if incident_data['severity'] in ['Critical', 'High']:
                playbooks_to_trigger.append('pqc_critical_response')
            
            if 'critical-risk' in incident_data['tags']:
                playbooks_to_trigger.append('emergency_crypto_assessment')
            
            # Always trigger the standard PQC playbook
            playbooks_to_trigger.append('pqc_standard_workflow')
            
            # Execute playbooks
            for playbook_name in playbooks_to_trigger:
                if playbook_name in self.playbook_templates:
                    await self._execute_playbook(incident_id, playbook_name)
                    
        except Exception as e:
            self.logger.warning(f"Error triggering playbooks for incident {incident_id}: {e}")
    
    async def _execute_playbook(self, incident_id: str, playbook_name: str):
        """Execute a specific playbook."""
        playbook_endpoint = self.config.custom_fields.get('playbooks_endpoint', '/api/playbooks')
        url = urljoin(self.config.endpoint_url, f"{playbook_endpoint}/{playbook_name}/execute")
        
        payload = {
            'incident_id': incident_id,
            'parameters': self.playbook_templates.get(playbook_name, {})
        }
        
        headers = self._get_auth_headers()
        headers['Content-Type'] = 'application/json'
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers) as response:
                if response.status < 400:
                    self.logger.info(f"Triggered playbook {playbook_name} for incident {incident_id}")
                else:
                    self.logger.warning(f"Failed to trigger playbook {playbook_name}: {response.status}")
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for SOAR API."""
        headers = {'User-Agent': 'PQC-Migration-Audit/1.0'}
        
        auth_config = self.config.authentication
        auth_type = auth_config.get('type', 'none')
        
        if auth_type == 'bearer':
            headers['Authorization'] = f"Bearer {auth_config['token']}"
        elif auth_type == 'api_key':
            headers[auth_config.get('header_name', 'X-API-Key')] = auth_config['api_key']
        elif auth_type == 'basic':
            import base64
            credentials = f"{auth_config['username']}:{auth_config['password']}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            headers['Authorization'] = f"Basic {encoded_credentials}"
        
        return headers


class EnterpriseOrchestrator:
    """Main orchestrator for all enterprise integrations."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.integrations: Dict[IntegrationType, Any] = {}
        self.integration_configs: Dict[IntegrationType, IntegrationConfig] = {}
        self.health_status: Dict[IntegrationType, str] = {}
        
    def register_integration(self, integration_type: IntegrationType, 
                           config: IntegrationConfig):
        """Register an enterprise integration."""
        self.integration_configs[integration_type] = config
        
        if integration_type == IntegrationType.SIEM:
            self.integrations[integration_type] = SIEMConnector(config)
        elif integration_type == IntegrationType.SOAR:
            self.integrations[integration_type] = SOARConnector(config)
        # Add other integration types as needed
        
        self.health_status[integration_type] = 'registered'
        self.logger.info(f"Registered {integration_type.value} integration")
    
    async def process_scan_results(self, scan_results: ScanResults, 
                                 metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """Process scan results through all configured integrations."""
        processing_results = {
            'timestamp': datetime.now().isoformat(),
            'scan_summary': {
                'vulnerabilities_found': len(scan_results.vulnerabilities),
                'files_scanned': scan_results.scanned_files,
                'scan_path': scan_results.scan_path
            },
            'integration_results': {},
            'errors': []
        }
        
        # Process through each integration
        for integration_type, connector in self.integrations.items():
            if not self.integration_configs[integration_type].enabled:
                continue
                
            try:
                if integration_type == IntegrationType.SIEM:
                    async with connector:
                        success = await connector.send_pqc_scan_results(scan_results, metadata)
                        processing_results['integration_results'][integration_type.value] = {
                            'status': 'success' if success else 'failed',
                            'message': 'Scan results sent to SIEM' if success else 'Failed to send to SIEM'
                        }
                        
                elif integration_type == IntegrationType.SOAR:
                    incident_result = await connector.create_pqc_incident(scan_results, metadata)
                    processing_results['integration_results'][integration_type.value] = {
                        'status': 'success',
                        'incident_id': incident_result.get('incident_id'),
                        'message': f"Created SOAR incident: {incident_result.get('incident_id')}"
                    }
                
                self.health_status[integration_type] = 'healthy'
                
            except Exception as e:
                error_message = f"Integration {integration_type.value} failed: {str(e)}"
                self.logger.error(error_message)
                processing_results['errors'].append(error_message)
                processing_results['integration_results'][integration_type.value] = {
                    'status': 'error',
                    'message': str(e)
                }
                self.health_status[integration_type] = 'unhealthy'
        
        return processing_results
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on all integrations."""
        health_report = {
            'timestamp': datetime.now().isoformat(),
            'overall_status': 'healthy',
            'integrations': {}
        }
        
        unhealthy_count = 0
        
        for integration_type, connector in self.integrations.items():
            try:
                # Perform integration-specific health check
                if hasattr(connector, 'health_check'):
                    health_status = await connector.health_check()
                else:
                    health_status = 'unknown'
                
                health_report['integrations'][integration_type.value] = {
                    'status': health_status,
                    'last_check': datetime.now().isoformat(),
                    'enabled': self.integration_configs[integration_type].enabled
                }
                
                if health_status != 'healthy':
                    unhealthy_count += 1
                    
            except Exception as e:
                health_report['integrations'][integration_type.value] = {
                    'status': 'error',
                    'error': str(e),
                    'last_check': datetime.now().isoformat()
                }
                unhealthy_count += 1
        
        # Determine overall status
        if unhealthy_count == 0:
            health_report['overall_status'] = 'healthy'
        elif unhealthy_count < len(self.integrations):
            health_report['overall_status'] = 'degraded'
        else:
            health_report['overall_status'] = 'unhealthy'
        
        return health_report
    
    def get_integration_metrics(self) -> Dict[str, Any]:
        """Get metrics for all integrations."""
        metrics = {
            'total_integrations': len(self.integrations),
            'enabled_integrations': len([c for c in self.integration_configs.values() if c.enabled]),
            'healthy_integrations': len([s for s in self.health_status.values() if s == 'healthy']),
            'integration_types': [t.value for t in self.integrations.keys()],
            'health_summary': dict(self.health_status)
        }
        
        return metrics
