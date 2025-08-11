"""Comprehensive compliance engine for regulatory frameworks and standards."""

import time
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import statistics
from collections import defaultdict
import re
from urllib.parse import quote, unquote

from .types import Severity, Vulnerability, ScanResults
from .core import CryptoAuditor, RiskAssessment
from .exceptions import PQCAuditException


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    NIST_CSF = "nist_csf"  # NIST Cybersecurity Framework
    ISO_27001 = "iso_27001"  # ISO/IEC 27001
    PCI_DSS = "pci_dss"  # Payment Card Industry Data Security Standard
    SOX = "sox"  # Sarbanes-Oxley Act
    HIPAA = "hipaa"  # Health Insurance Portability and Accountability Act
    GDPR = "gdpr"  # General Data Protection Regulation
    CCPA = "ccpa"  # California Consumer Privacy Act
    FISMA = "fisma"  # Federal Information Security Management Act
    SOC2 = "soc2"  # Service Organization Control 2
    FFIEC = "ffiec"  # Federal Financial Institutions Examination Council
    NERC_CIP = "nerc_cip"  # North American Electric Reliability Corporation Critical Infrastructure Protection
    COBIT = "cobit"  # Control Objectives for Information and Related Technologies
    FedRAMP = "fedramp"  # Federal Risk and Authorization Management Program


class ComplianceStatus(Enum):
    """Compliance assessment status."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_APPLICABLE = "not_applicable"
    UNDER_REVIEW = "under_review"
    REMEDIATION_REQUIRED = "remediation_required"


class RiskLevel(Enum):
    """Risk levels for compliance assessment."""
    MINIMAL = "minimal"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ComplianceControl:
    """Individual compliance control definition."""
    control_id: str
    framework: ComplianceFramework
    title: str
    description: str
    category: str
    subcategory: str
    requirements: List[str]
    assessment_criteria: List[str]
    related_controls: List[str] = field(default_factory=list)
    priority_level: str = "medium"
    applicable_systems: List[str] = field(default_factory=list)
    maturity_levels: Dict[str, str] = field(default_factory=dict)


@dataclass
class ComplianceAssessment:
    """Results of compliance assessment for a specific control."""
    control_id: str
    framework: ComplianceFramework
    status: ComplianceStatus
    risk_level: RiskLevel
    score: float  # 0-100 compliance score
    findings: List[str]
    evidence: List[Dict[str, Any]]
    gaps: List[str]
    recommendations: List[str]
    affected_assets: List[str]
    assessment_date: str
    assessor: str
    next_review_date: str
    remediation_timeline: Optional[str] = None
    business_justification: Optional[str] = None


@dataclass
class ComplianceReport:
    """Comprehensive compliance report."""
    report_id: str
    frameworks: List[ComplianceFramework]
    assessment_date: str
    scope: Dict[str, Any]
    overall_status: ComplianceStatus
    overall_score: float
    control_assessments: List[ComplianceAssessment]
    executive_summary: str
    detailed_findings: Dict[str, Any]
    remediation_plan: Dict[str, Any]
    risk_matrix: Dict[str, Any]
    attestation: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)


class NISTCybersecurityFramework:
    """NIST Cybersecurity Framework compliance assessor."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # NIST CSF Core Functions and Categories
        self.csf_controls = {
            "PR.AC-1": ComplianceControl(
                control_id="PR.AC-1",
                framework=ComplianceFramework.NIST_CSF,
                title="Identity and Access Management",
                description="Identities and credentials are issued, managed, verified, revoked, and audited for authorized devices, users and processes",
                category="PROTECT",
                subcategory="Access Control",
                requirements=[
                    "Implement identity and access management systems",
                    "Maintain inventory of authorized users and devices",
                    "Implement multi-factor authentication where appropriate",
                    "Regular access reviews and audits"
                ],
                assessment_criteria=[
                    "Access controls are implemented and documented",
                    "User access is regularly reviewed",
                    "Authentication mechanisms are appropriate for risk level"
                ],
                priority_level="high"
            ),
            "PR.DS-1": ComplianceControl(
                control_id="PR.DS-1",
                framework=ComplianceFramework.NIST_CSF,
                title="Data-at-rest Protection",
                description="Data-at-rest is protected using appropriate encryption",
                category="PROTECT",
                subcategory="Data Security",
                requirements=[
                    "Implement encryption for sensitive data at rest",
                    "Use approved cryptographic algorithms",
                    "Implement key management procedures",
                    "Regular review of encryption implementations"
                ],
                assessment_criteria=[
                    "Data classification scheme is implemented",
                    "Appropriate encryption is applied to sensitive data",
                    "Cryptographic controls meet industry standards",
                    "Key management follows best practices"
                ],
                priority_level="critical"
            ),
            "PR.DS-2": ComplianceControl(
                control_id="PR.DS-2",
                framework=ComplianceFramework.NIST_CSF,
                title="Data-in-transit Protection",
                description="Data-in-transit is protected using appropriate encryption",
                category="PROTECT",
                subcategory="Data Security",
                requirements=[
                    "Implement encryption for data in transit",
                    "Use secure communication protocols",
                    "Implement certificate management",
                    "Monitor and validate secure communications"
                ],
                assessment_criteria=[
                    "Network traffic is encrypted using approved protocols",
                    "Certificate management is implemented",
                    "Secure communication standards are enforced"
                ],
                priority_level="critical"
            ),
            "DE.CM-7": ComplianceControl(
                control_id="DE.CM-7",
                framework=ComplianceFramework.NIST_CSF,
                title="Monitoring for Unauthorized Personnel",
                description="Monitoring for unauthorized personnel, connections, devices, and software is performed",
                category="DETECT",
                subcategory="Security Continuous Monitoring",
                requirements=[
                    "Implement continuous monitoring systems",
                    "Monitor for unauthorized access attempts",
                    "Detect abnormal network activity",
                    "Alert on security policy violations"
                ],
                assessment_criteria=[
                    "Security monitoring tools are deployed",
                    "Monitoring covers critical assets",
                    "Alerts are generated for security events"
                ],
                priority_level="high"
            ),
            "RS.RP-1": ComplianceControl(
                control_id="RS.RP-1",
                framework=ComplianceFramework.NIST_CSF,
                title="Response Plan",
                description="Response plan is executed during or after an incident",
                category="RESPOND",
                subcategory="Response Planning",
                requirements=[
                    "Develop incident response procedures",
                    "Define roles and responsibilities",
                    "Establish communication procedures",
                    "Regular testing and updates"
                ],
                assessment_criteria=[
                    "Incident response plan is documented",
                    "Plan is regularly tested and updated",
                    "Staff are trained on response procedures"
                ],
                priority_level="medium"
            )
        }
    
    def assess_pqc_compliance(self, scan_results: ScanResults, 
                            organization_context: Dict[str, Any]) -> List[ComplianceAssessment]:
        """Assess PQC compliance against NIST CSF controls."""
        assessments = []
        
        # Assess each relevant control
        for control_id, control in self.csf_controls.items():
            if self._is_control_relevant_to_pqc(control):
                assessment = self._assess_control(control, scan_results, organization_context)
                assessments.append(assessment)
        
        return assessments
    
    def _is_control_relevant_to_pqc(self, control: ComplianceControl) -> bool:
        """Determine if a control is relevant to PQC assessment."""
        pqc_relevant_keywords = [
            'encryption', 'cryptographic', 'data protection', 
            'key management', 'certificate', 'authentication'
        ]
        
        control_text = f"{control.title} {control.description}".lower()
        return any(keyword in control_text for keyword in pqc_relevant_keywords)
    
    def _assess_control(self, control: ComplianceControl, scan_results: ScanResults,
                      context: Dict[str, Any]) -> ComplianceAssessment:
        """Assess a specific NIST CSF control."""
        findings = []
        evidence = []
        gaps = []
        recommendations = []
        affected_assets = []
        
        # Analyze scan results for this control
        if control.control_id in ["PR.DS-1", "PR.DS-2"]:
            # Data protection controls - directly impacted by PQC vulnerabilities
            
            critical_vulns = [v for v in scan_results.vulnerabilities if v.severity == Severity.CRITICAL]
            high_vulns = [v for v in scan_results.vulnerabilities if v.severity == Severity.HIGH]
            
            if critical_vulns:
                findings.append(f"Found {len(critical_vulns)} critical quantum-vulnerable cryptographic implementations")
                gaps.append("Current cryptographic controls are vulnerable to quantum attacks")
                recommendations.append("Implement post-quantum cryptographic algorithms (ML-KEM, ML-DSA)")
                
            if high_vulns:
                findings.append(f"Found {len(high_vulns)} high-risk quantum-vulnerable implementations")
                
            # Calculate compliance score
            total_vulns = len(scan_results.vulnerabilities)
            if total_vulns == 0:
                score = 100.0
                status = ComplianceStatus.COMPLIANT
                risk_level = RiskLevel.MINIMAL
            elif critical_vulns:
                score = max(0, 50 - len(critical_vulns) * 5)
                status = ComplianceStatus.NON_COMPLIANT
                risk_level = RiskLevel.CRITICAL
            elif high_vulns:
                score = max(30, 70 - len(high_vulns) * 2)
                status = ComplianceStatus.PARTIALLY_COMPLIANT
                risk_level = RiskLevel.HIGH
            else:
                score = 85
                status = ComplianceStatus.PARTIALLY_COMPLIANT
                risk_level = RiskLevel.MODERATE
            
            # Collect affected assets
            affected_assets = list(set(v.file_path for v in scan_results.vulnerabilities))
            
            # Generate evidence
            evidence.append({
                'type': 'scan_results',
                'description': 'PQC vulnerability scan results',
                'data': {
                    'total_vulnerabilities': len(scan_results.vulnerabilities),
                    'files_scanned': scan_results.scanned_files,
                    'scan_date': scan_results.timestamp
                }
            })
        
        else:
            # Other controls - indirectly impacted
            score = 75  # Assume partial compliance for non-crypto controls
            status = ComplianceStatus.PARTIALLY_COMPLIANT
            risk_level = RiskLevel.MODERATE
            findings.append("Control assessment requires additional manual review")
            recommendations.append("Review control implementation in context of quantum computing threats")
        
        return ComplianceAssessment(
            control_id=control.control_id,
            framework=control.framework,
            status=status,
            risk_level=risk_level,
            score=score,
            findings=findings,
            evidence=evidence,
            gaps=gaps,
            recommendations=recommendations,
            affected_assets=affected_assets,
            assessment_date=datetime.now().isoformat(),
            assessor="PQC-Migration-Audit",
            next_review_date=(datetime.now() + timedelta(days=90)).isoformat(),
            remediation_timeline="6-12 months" if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL] else "12-24 months"
        )


class ISO27001Assessor:
    """ISO/IEC 27001 compliance assessor."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # ISO 27001 Annex A controls relevant to cryptography
        self.iso_controls = {
            "A.10.1.1": ComplianceControl(
                control_id="A.10.1.1",
                framework=ComplianceFramework.ISO_27001,
                title="Cryptographic Policy",
                description="A policy on the use of cryptographic controls for protection of information shall be developed and implemented",
                category="Cryptography",
                subcategory="Cryptographic Controls",
                requirements=[
                    "Develop cryptographic policy",
                    "Define approved algorithms and key lengths",
                    "Specify key management requirements",
                    "Regular policy review and updates"
                ],
                assessment_criteria=[
                    "Cryptographic policy is documented and approved",
                    "Policy addresses quantum computing threats",
                    "Policy is regularly reviewed and updated"
                ],
                priority_level="critical"
            ),
            "A.10.1.2": ComplianceControl(
                control_id="A.10.1.2",
                framework=ComplianceFramework.ISO_27001,
                title="Key Management",
                description="A policy on the use, protection and lifetime of cryptographic keys shall be developed and implemented through their whole lifecycle",
                category="Cryptography",
                subcategory="Key Management",
                requirements=[
                    "Implement secure key generation",
                    "Establish key distribution procedures",
                    "Define key storage requirements",
                    "Implement key rotation and retirement"
                ],
                assessment_criteria=[
                    "Key management procedures are documented",
                    "Keys are protected throughout lifecycle",
                    "Key management system meets security requirements"
                ],
                priority_level="critical"
            ),
            "A.13.1.1": ComplianceControl(
                control_id="A.13.1.1",
                framework=ComplianceFramework.ISO_27001,
                title="Network Controls",
                description="Networks shall be managed and controlled to protect information in systems and applications",
                category="Communications Security",
                subcategory="Network Security Management",
                requirements=[
                    "Implement network segmentation",
                    "Control network access",
                    "Monitor network traffic",
                    "Use secure communication protocols"
                ],
                assessment_criteria=[
                    "Network security controls are implemented",
                    "Secure protocols are used for sensitive communications",
                    "Network monitoring is in place"
                ],
                priority_level="high"
            ),
            "A.13.2.1": ComplianceControl(
                control_id="A.13.2.1",
                framework=ComplianceFramework.ISO_27001,
                title="Information Transfer Policies",
                description="Formal transfer policies, procedures and controls shall be in place to protect the transfer of information through the use of all types of communication facilities",
                category="Communications Security",
                subcategory="Information Transfer",
                requirements=[
                    "Develop information transfer policies",
                    "Implement secure transfer mechanisms",
                    "Protect information in transit",
                    "Monitor and log transfers"
                ],
                assessment_criteria=[
                    "Information transfer policies are documented",
                    "Secure transfer mechanisms are used",
                    "Transfer activities are monitored"
                ],
                priority_level="high"
            )
        }
    
    def assess_pqc_compliance(self, scan_results: ScanResults,
                            organization_context: Dict[str, Any]) -> List[ComplianceAssessment]:
        """Assess PQC compliance against ISO 27001 controls."""
        assessments = []
        
        for control_id, control in self.iso_controls.items():
            assessment = self._assess_iso_control(control, scan_results, organization_context)
            assessments.append(assessment)
        
        return assessments
    
    def _assess_iso_control(self, control: ComplianceControl, scan_results: ScanResults,
                          context: Dict[str, Any]) -> ComplianceAssessment:
        """Assess a specific ISO 27001 control."""
        findings = []
        evidence = []
        gaps = []
        recommendations = []
        affected_assets = []
        
        # Analyze scan results for cryptographic controls
        if control.control_id in ["A.10.1.1", "A.10.1.2"]:
            # Direct cryptographic controls
            total_vulns = len(scan_results.vulnerabilities)
            critical_vulns = len([v for v in scan_results.vulnerabilities if v.severity == Severity.CRITICAL])
            high_vulns = len([v for v in scan_results.vulnerabilities if v.severity == Severity.HIGH])
            
            if total_vulns > 0:
                findings.append(f"Quantum-vulnerable cryptographic implementations detected: {total_vulns} total")
                gaps.append("Current cryptographic policy does not address quantum computing threats")
                gaps.append("Cryptographic implementations use quantum-vulnerable algorithms")
                
                recommendations.extend([
                    "Update cryptographic policy to include post-quantum requirements",
                    "Plan migration to NIST-standardized post-quantum algorithms",
                    "Implement crypto-agility in key management systems",
                    "Conduct regular quantum threat assessments"
                ])
            
            # Calculate compliance score
            if total_vulns == 0:
                score = 100.0
                status = ComplianceStatus.COMPLIANT
                risk_level = RiskLevel.MINIMAL
            elif critical_vulns >= 5:
                score = 20.0
                status = ComplianceStatus.NON_COMPLIANT
                risk_level = RiskLevel.CRITICAL
            elif critical_vulns >= 1 or high_vulns >= 10:
                score = 45.0
                status = ComplianceStatus.NON_COMPLIANT
                risk_level = RiskLevel.HIGH
            else:
                score = 65.0
                status = ComplianceStatus.PARTIALLY_COMPLIANT
                risk_level = RiskLevel.MODERATE
        
        else:
            # Communication security controls
            score = 70.0
            status = ComplianceStatus.PARTIALLY_COMPLIANT
            risk_level = RiskLevel.MODERATE
            findings.append("Manual assessment required for communication security controls")
            recommendations.append("Review secure communication protocols for quantum resistance")
        
        affected_assets = list(set(v.file_path for v in scan_results.vulnerabilities))
        
        evidence.append({
            'type': 'vulnerability_scan',
            'description': 'PQC vulnerability assessment results',
            'data': {
                'scan_coverage': f"{scan_results.scanned_files} files",
                'vulnerabilities_found': len(scan_results.vulnerabilities),
                'assessment_date': scan_results.timestamp
            }
        })
        
        return ComplianceAssessment(
            control_id=control.control_id,
            framework=control.framework,
            status=status,
            risk_level=risk_level,
            score=score,
            findings=findings,
            evidence=evidence,
            gaps=gaps,
            recommendations=recommendations,
            affected_assets=affected_assets,
            assessment_date=datetime.now().isoformat(),
            assessor="PQC-Migration-Audit",
            next_review_date=(datetime.now() + timedelta(days=180)).isoformat(),
            remediation_timeline="3-9 months" if risk_level == RiskLevel.CRITICAL else "6-18 months"
        )


class PCIDSSAssessor:
    """PCI DSS (Payment Card Industry Data Security Standard) compliance assessor."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # PCI DSS requirements relevant to cryptography
        self.pci_controls = {
            "3.4": ComplianceControl(
                control_id="3.4",
                framework=ComplianceFramework.PCI_DSS,
                title="Cryptographic Key Protection",
                description="Render Primary Account Numbers (PAN) unreadable anywhere it is stored by using strong cryptography",
                category="Protect Cardholder Data",
                subcategory="Data Protection",
                requirements=[
                    "Use strong cryptography to protect stored PAN",
                    "Implement proper key management",
                    "Use industry-tested algorithms",
                    "Protect cryptographic keys"
                ],
                assessment_criteria=[
                    "Strong cryptography is used for PAN protection",
                    "Cryptographic keys are properly managed",
                    "Algorithms meet industry standards"
                ],
                priority_level="critical"
            ),
            "4.1": ComplianceControl(
                control_id="4.1",
                framework=ComplianceFramework.PCI_DSS,
                title="Transmission Encryption",
                description="Use strong cryptography and security protocols to safeguard sensitive cardholder data during transmission over open, public networks",
                category="Protect Cardholder Data",
                subcategory="Network Protection",
                requirements=[
                    "Encrypt cardholder data during transmission",
                    "Use strong cryptographic protocols",
                    "Implement certificate management",
                    "Monitor secure transmission channels"
                ],
                assessment_criteria=[
                    "Transmission encryption is implemented",
                    "Strong protocols are used (TLS 1.2+)",
                    "Certificate management is in place"
                ],
                priority_level="critical"
            ),
            "8.2.3": ComplianceControl(
                control_id="8.2.3",
                framework=ComplianceFramework.PCI_DSS,
                title="Strong Authentication",
                description="Incorporate multi-factor authentication for all non-console access into the CDE",
                category="Access Control",
                subcategory="Authentication",
                requirements=[
                    "Implement multi-factor authentication",
                    "Use strong authentication mechanisms",
                    "Protect authentication credentials",
                    "Regular authentication system review"
                ],
                assessment_criteria=[
                    "Multi-factor authentication is implemented",
                    "Authentication mechanisms are secure",
                    "Credentials are properly protected"
                ],
                priority_level="high"
            )
        }
    
    def assess_pqc_compliance(self, scan_results: ScanResults,
                            organization_context: Dict[str, Any]) -> List[ComplianceAssessment]:
        """Assess PQC compliance against PCI DSS requirements."""
        assessments = []
        
        # Only assess if organization handles payment card data
        if organization_context.get('handles_payment_cards', False):
            for control_id, control in self.pci_controls.items():
                assessment = self._assess_pci_control(control, scan_results, organization_context)
                assessments.append(assessment)
        
        return assessments
    
    def _assess_pci_control(self, control: ComplianceControl, scan_results: ScanResults,
                          context: Dict[str, Any]) -> ComplianceAssessment:
        """Assess a specific PCI DSS control."""
        findings = []
        evidence = []
        gaps = []
        recommendations = []
        affected_assets = []
        
        total_vulns = len(scan_results.vulnerabilities)
        critical_vulns = len([v for v in scan_results.vulnerabilities if v.severity == Severity.CRITICAL])
        high_vulns = len([v for v in scan_results.vulnerabilities if v.severity == Severity.HIGH])
        
        # PCI DSS has strict requirements for cryptography
        if total_vulns > 0:
            findings.append(f"Quantum-vulnerable cryptographic implementations in payment environment: {total_vulns}")
            gaps.append("Payment card data protection may be compromised by quantum attacks")
            gaps.append("Current cryptographic controls do not meet future PCI DSS quantum-resistant requirements")
            
            recommendations.extend([
                "URGENT: Plan immediate assessment of payment card data protection",
                "Implement quantum-resistant cryptography for PAN protection",
                "Update key management systems for crypto-agility",
                "Coordinate with payment processor for quantum-safe transition",
                "Engage QSA (Qualified Security Assessor) for quantum readiness review"
            ])
        
        # Calculate compliance score (PCI DSS is strict - any quantum vulnerability is serious)
        if total_vulns == 0:
            score = 100.0
            status = ComplianceStatus.COMPLIANT
            risk_level = RiskLevel.MINIMAL
        elif critical_vulns >= 1:
            score = 25.0
            status = ComplianceStatus.NON_COMPLIANT
            risk_level = RiskLevel.CRITICAL
            recommendations.insert(0, "IMMEDIATE ACTION REQUIRED: Critical quantum vulnerabilities in payment environment")
        elif high_vulns >= 1:
            score = 40.0
            status = ComplianceStatus.NON_COMPLIANT
            risk_level = RiskLevel.HIGH
        else:
            score = 60.0
            status = ComplianceStatus.PARTIALLY_COMPLIANT
            risk_level = RiskLevel.MODERATE
        
        affected_assets = list(set(v.file_path for v in scan_results.vulnerabilities))
        
        evidence.append({
            'type': 'pci_assessment',
            'description': 'Quantum vulnerability assessment for PCI environment',
            'data': {
                'cardholder_data_environment': context.get('cde_scope', 'unknown'),
                'vulnerabilities_in_scope': total_vulns,
                'assessment_methodology': 'Automated PQC vulnerability scan'
            }
        })
        
        return ComplianceAssessment(
            control_id=control.control_id,
            framework=control.framework,
            status=status,
            risk_level=risk_level,
            score=score,
            findings=findings,
            evidence=evidence,
            gaps=gaps,
            recommendations=recommendations,
            affected_assets=affected_assets,
            assessment_date=datetime.now().isoformat(),
            assessor="PQC-Migration-Audit",
            next_review_date=(datetime.now() + timedelta(days=90)).isoformat(),  # Quarterly for PCI
            remediation_timeline="1-3 months" if risk_level == RiskLevel.CRITICAL else "3-6 months",
            business_justification="Payment card industry compliance requires quantum-resistant cryptography"
        )


class ComplianceEngine:
    """Main compliance assessment engine."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Initialize framework assessors
        self.assessors = {
            ComplianceFramework.NIST_CSF: NISTCybersecurityFramework(),
            ComplianceFramework.ISO_27001: ISO27001Assessor(),
            ComplianceFramework.PCI_DSS: PCIDSSAssessor()
        }
        
        # Compliance reporting templates
        self.report_templates = {
            'executive_summary': {
                'compliant': "Organization demonstrates strong compliance posture with quantum-ready cryptographic controls.",
                'partially_compliant': "Organization has partial compliance with identified gaps requiring attention before quantum threats emerge.",
                'non_compliant': "Organization has significant compliance gaps that require immediate remediation to address quantum computing risks."
            }
        }
        
        # Risk scoring matrix
        self.risk_matrix = {
            (RiskLevel.CRITICAL, 'high'): 'Extreme Risk - Immediate Action Required',
            (RiskLevel.CRITICAL, 'medium'): 'High Risk - Urgent Attention Needed',
            (RiskLevel.HIGH, 'high'): 'High Risk - Priority Remediation',
            (RiskLevel.HIGH, 'medium'): 'Medium-High Risk - Planned Remediation',
            (RiskLevel.MODERATE, 'high'): 'Medium Risk - Scheduled Review',
            (RiskLevel.MODERATE, 'medium'): 'Medium Risk - Standard Process',
            (RiskLevel.LOW, 'high'): 'Low-Medium Risk - Monitor',
            (RiskLevel.LOW, 'medium'): 'Low Risk - Routine Oversight'
        }
    
    def assess_compliance(self, scan_results: ScanResults, 
                        frameworks: List[ComplianceFramework],
                        organization_context: Dict[str, Any] = None) -> ComplianceReport:
        """Perform comprehensive compliance assessment."""
        if organization_context is None:
            organization_context = {}
        
        assessment_start = time.time()
        all_assessments = []
        
        self.logger.info(f"Starting compliance assessment for frameworks: {[f.value for f in frameworks]}")
        
        # Run assessments for each framework
        for framework in frameworks:
            if framework in self.assessors:
                try:
                    framework_assessments = self.assessors[framework].assess_pqc_compliance(
                        scan_results, organization_context
                    )
                    all_assessments.extend(framework_assessments)
                    self.logger.info(f"Completed {framework.value} assessment: {len(framework_assessments)} controls")
                except Exception as e:
                    self.logger.error(f"Error assessing {framework.value}: {e}")
        
        # Calculate overall compliance status and score
        overall_status, overall_score = self._calculate_overall_compliance(all_assessments)
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(all_assessments, overall_status)
        
        # Create detailed findings
        detailed_findings = self._compile_detailed_findings(all_assessments)
        
        # Generate remediation plan
        remediation_plan = self._generate_remediation_plan(all_assessments)
        
        # Create risk matrix
        risk_matrix = self._create_risk_matrix(all_assessments)
        
        # Generate attestation information
        attestation = self._generate_attestation_info(all_assessments, organization_context)
        
        # Create comprehensive report
        report = ComplianceReport(
            report_id=f"COMP-{hashlib.md5(f'{scan_results.scan_path}{datetime.now().isoformat()}'.encode()).hexdigest()[:8]}",
            frameworks=frameworks,
            assessment_date=datetime.now().isoformat(),
            scope={
                'scan_path': scan_results.scan_path,
                'files_assessed': scan_results.scanned_files,
                'languages_covered': scan_results.languages_detected,
                'assessment_duration': time.time() - assessment_start
            },
            overall_status=overall_status,
            overall_score=overall_score,
            control_assessments=all_assessments,
            executive_summary=executive_summary,
            detailed_findings=detailed_findings,
            remediation_plan=remediation_plan,
            risk_matrix=risk_matrix,
            attestation=attestation,
            metadata={
                'assessor': 'PQC-Migration-Audit',
                'methodology': 'Automated quantum vulnerability assessment',
                'standards_version': 'Current as of assessment date',
                'next_assessment_due': (datetime.now() + timedelta(days=365)).isoformat()
            }
        )
        
        self.logger.info(f"Compliance assessment completed: {overall_status.value} ({overall_score:.1f}/100)")
        
        return report
    
    def _calculate_overall_compliance(self, assessments: List[ComplianceAssessment]) -> Tuple[ComplianceStatus, float]:
        """Calculate overall compliance status and score."""
        if not assessments:
            return ComplianceStatus.NOT_APPLICABLE, 0.0
        
        # Weight scores by framework importance and control criticality
        weighted_scores = []
        status_counts = defaultdict(int)
        
        for assessment in assessments:
            # Weight critical controls higher
            weight = 1.0
            if 'critical' in assessment.control_id or assessment.risk_level == RiskLevel.CRITICAL:
                weight = 2.0
            elif 'high' in assessment.control_id or assessment.risk_level == RiskLevel.HIGH:
                weight = 1.5
            
            weighted_scores.append(assessment.score * weight)
            status_counts[assessment.status] += 1
        
        # Calculate weighted average score
        overall_score = statistics.mean(weighted_scores) if weighted_scores else 0.0
        
        # Determine overall status
        if status_counts[ComplianceStatus.NON_COMPLIANT] > 0:
            if status_counts[ComplianceStatus.NON_COMPLIANT] >= len(assessments) * 0.5:
                overall_status = ComplianceStatus.NON_COMPLIANT
            else:
                overall_status = ComplianceStatus.PARTIALLY_COMPLIANT
        elif status_counts[ComplianceStatus.PARTIALLY_COMPLIANT] > 0:
            overall_status = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            overall_status = ComplianceStatus.COMPLIANT
        
        return overall_status, overall_score
    
    def _generate_executive_summary(self, assessments: List[ComplianceAssessment],
                                  overall_status: ComplianceStatus) -> str:
        """Generate executive summary for compliance report."""
        if not assessments:
            return "No compliance assessments were performed."
        
        # Base summary from template
        base_summary = self.report_templates['executive_summary'].get(
            overall_status.value.replace('_', '_'), 
            "Compliance assessment completed."
        )
        
        # Add specific metrics
        total_controls = len(assessments)
        critical_findings = len([a for a in assessments if a.risk_level == RiskLevel.CRITICAL])
        high_findings = len([a for a in assessments if a.risk_level == RiskLevel.HIGH])
        
        frameworks_assessed = list(set(a.framework.value for a in assessments))
        
        summary = f"""{base_summary}

**Assessment Overview:**
- Frameworks Assessed: {', '.join(frameworks_assessed)}
- Total Controls Evaluated: {total_controls}
- Critical Risk Findings: {critical_findings}
- High Risk Findings: {high_findings}

**Quantum Cryptography Impact:**
This assessment specifically evaluates organizational readiness for the post-quantum cryptography transition. Identified vulnerabilities represent current quantum-vulnerable cryptographic implementations that require migration to quantum-resistant algorithms before quantum computers become capable of breaking current encryption.

**Key Recommendations:**
1. Prioritize remediation of critical risk findings
2. Develop comprehensive post-quantum cryptography migration plan
3. Implement crypto-agility frameworks for future algorithm transitions
4. Establish regular quantum threat monitoring and assessment procedures

**Timeline Considerations:**
Quantum computing threats are projected to emerge within the next 5-15 years. Organizations should begin migration planning immediately to ensure adequate preparation time for testing, validation, and deployment of quantum-resistant cryptographic systems.
"""
        
        return summary
    
    def _compile_detailed_findings(self, assessments: List[ComplianceAssessment]) -> Dict[str, Any]:
        """Compile detailed findings from all assessments."""
        findings = {
            'by_framework': {},
            'by_risk_level': defaultdict(list),
            'by_control_category': defaultdict(list),
            'summary_statistics': {}
        }
        
        # Group findings by framework
        for assessment in assessments:
            framework = assessment.framework.value
            if framework not in findings['by_framework']:
                findings['by_framework'][framework] = []
            
            findings['by_framework'][framework].append({
                'control_id': assessment.control_id,
                'status': assessment.status.value,
                'score': assessment.score,
                'findings': assessment.findings,
                'recommendations': assessment.recommendations
            })
            
            # Group by risk level
            findings['by_risk_level'][assessment.risk_level.value].append({
                'control_id': assessment.control_id,
                'framework': framework,
                'findings': assessment.findings
            })
        
        # Calculate summary statistics
        findings['summary_statistics'] = {
            'total_controls': len(assessments),
            'compliant_controls': len([a for a in assessments if a.status == ComplianceStatus.COMPLIANT]),
            'non_compliant_controls': len([a for a in assessments if a.status == ComplianceStatus.NON_COMPLIANT]),
            'partially_compliant_controls': len([a for a in assessments if a.status == ComplianceStatus.PARTIALLY_COMPLIANT]),
            'average_score': statistics.mean([a.score for a in assessments]) if assessments else 0.0,
            'risk_distribution': {
                risk.value: len([a for a in assessments if a.risk_level == risk])
                for risk in RiskLevel
            }
        }
        
        return findings
    
    def _generate_remediation_plan(self, assessments: List[ComplianceAssessment]) -> Dict[str, Any]:
        """Generate comprehensive remediation plan."""
        plan = {
            'priority_matrix': {},
            'timeline': {},
            'resource_requirements': {},
            'quick_wins': [],
            'strategic_initiatives': []
        }
        
        # Prioritize remediation based on risk level and compliance impact
        high_priority = [a for a in assessments if a.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]]
        medium_priority = [a for a in assessments if a.risk_level == RiskLevel.MODERATE]
        low_priority = [a for a in assessments if a.risk_level == RiskLevel.LOW]
        
        plan['priority_matrix'] = {
            'immediate_action': [{
                'control_id': a.control_id,
                'framework': a.framework.value,
                'recommendations': a.recommendations[:3],  # Top 3 recommendations
                'timeline': a.remediation_timeline
            } for a in high_priority],
            'planned_remediation': [{
                'control_id': a.control_id,
                'framework': a.framework.value,
                'recommendations': a.recommendations[:2]
            } for a in medium_priority],
            'ongoing_monitoring': [{
                'control_id': a.control_id,
                'framework': a.framework.value
            } for a in low_priority]
        }
        
        # Generate timeline
        plan['timeline'] = {
            '0-3_months': [
                'Address all critical risk findings',
                'Develop post-quantum cryptography migration strategy',
                'Implement crypto-agility framework design'
            ],
            '3-6_months': [
                'Begin pilot implementation of quantum-resistant algorithms',
                'Update cryptographic policies and procedures',
                'Staff training on post-quantum cryptography'
            ],
            '6-12_months': [
                'Complete high-priority cryptographic system migrations',
                'Implement comprehensive quantum threat monitoring',
                'Conduct follow-up compliance assessments'
            ],
            '12-24_months': [
                'Complete organization-wide PQC migration',
                'Achieve full compliance across all frameworks',
                'Establish ongoing quantum readiness program'
            ]
        }
        
        # Identify quick wins
        plan['quick_wins'] = [
            'Update cryptographic policies to address quantum threats',
            'Implement automated vulnerability scanning for quantum risks',
            'Establish quantum threat intelligence monitoring',
            'Create cross-functional PQC migration team'
        ]
        
        # Strategic initiatives
        plan['strategic_initiatives'] = [
            'Enterprise-wide crypto-agility implementation',
            'Quantum-safe architecture design and deployment',
            'Industry collaboration on quantum-safe standards',
            'Research and development of novel quantum-resistant approaches'
        ]
        
        return plan
    
    def _create_risk_matrix(self, assessments: List[ComplianceAssessment]) -> Dict[str, Any]:
        """Create risk matrix visualization data."""
        matrix = {
            'risk_levels': {},
            'impact_likelihood': {},
            'mitigation_priorities': []
        }
        
        # Count assessments by risk level
        for risk_level in RiskLevel:
            count = len([a for a in assessments if a.risk_level == risk_level])
            matrix['risk_levels'][risk_level.value] = count
        
        # Create impact/likelihood matrix (simplified)
        for assessment in assessments:
            impact = 'high' if assessment.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH] else 'medium'
            likelihood = 'high'  # Quantum threats are inevitable
            key = (assessment.risk_level, impact)
            
            matrix_description = self.risk_matrix.get(key, 'Standard Risk Management')
            
            if key not in matrix['impact_likelihood']:
                matrix['impact_likelihood'][key] = {
                    'description': matrix_description,
                    'controls': []
                }
            
            matrix['impact_likelihood'][key]['controls'].append({
                'control_id': assessment.control_id,
                'framework': assessment.framework.value,
                'score': assessment.score
            })
        
        # Prioritize mitigation efforts
        critical_assessments = [a for a in assessments if a.risk_level == RiskLevel.CRITICAL]
        high_assessments = [a for a in assessments if a.risk_level == RiskLevel.HIGH]
        
        matrix['mitigation_priorities'] = [
            {
                'priority': 1,
                'description': 'Critical Risk Controls',
                'controls': [a.control_id for a in critical_assessments],
                'action_required': 'Immediate remediation required'
            },
            {
                'priority': 2,
                'description': 'High Risk Controls',
                'controls': [a.control_id for a in high_assessments],
                'action_required': 'Remediation within 6 months'
            }
        ]
        
        return matrix
    
    def _generate_attestation_info(self, assessments: List[ComplianceAssessment],
                                 context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate attestation and certification information."""
        return {
            'assessment_methodology': 'Automated quantum cryptography vulnerability assessment',
            'assessment_scope': 'Cryptographic controls and quantum readiness',
            'assessment_limitations': [
                'Automated assessment focuses on technical vulnerabilities',
                'Manual review required for policy and procedural controls',
                'Quantum threat timeline assumptions based on current research'
            ],
            'assessor_qualifications': 'PQC-Migration-Audit automated assessment tool',
            'assessment_standards': [
                'NIST Post-Quantum Cryptography standards',
                'Framework-specific control requirements',
                'Industry best practices for quantum readiness'
            ],
            'reliability_factors': {
                'technical_accuracy': 'High - based on established vulnerability patterns',
                'coverage_completeness': 'Good - covers primary cryptographic implementations',
                'assessment_consistency': 'High - standardized assessment methodology'
            },
            'follow_up_requirements': [
                'Manual review of identified high-risk findings',
                'Validation of automated assessment results',
                'Development of organization-specific remediation plans',
                'Regular reassessment as quantum threats evolve'
            ]
        }
    
    def generate_compliance_dashboard_data(self, report: ComplianceReport) -> Dict[str, Any]:
        """Generate data for compliance dashboard visualization."""
        dashboard_data = {
            'summary_metrics': {
                'overall_score': report.overall_score,
                'overall_status': report.overall_status.value,
                'total_controls': len(report.control_assessments),
                'assessment_date': report.assessment_date
            },
            'framework_breakdown': {},
            'risk_distribution': {},
            'compliance_trends': {},
            'action_items': []
        }
        
        # Framework-specific metrics
        for framework in report.frameworks:
            framework_assessments = [a for a in report.control_assessments if a.framework == framework]
            if framework_assessments:
                avg_score = statistics.mean([a.score for a in framework_assessments])
                dashboard_data['framework_breakdown'][framework.value] = {
                    'average_score': avg_score,
                    'control_count': len(framework_assessments),
                    'status_distribution': {
                        status.value: len([a for a in framework_assessments if a.status == status])
                        for status in ComplianceStatus
                    }
                }
        
        # Risk distribution
        for risk_level in RiskLevel:
            count = len([a for a in report.control_assessments if a.risk_level == risk_level])
            dashboard_data['risk_distribution'][risk_level.value] = count
        
        # Top action items
        critical_assessments = [a for a in report.control_assessments if a.risk_level == RiskLevel.CRITICAL]
        high_assessments = [a for a in report.control_assessments if a.risk_level == RiskLevel.HIGH]
        
        action_items = []
        for assessment in (critical_assessments + high_assessments)[:10]:  # Top 10
            action_items.append({
                'control_id': assessment.control_id,
                'framework': assessment.framework.value,
                'risk_level': assessment.risk_level.value,
                'primary_recommendation': assessment.recommendations[0] if assessment.recommendations else 'Review required',
                'timeline': assessment.remediation_timeline
            })
        
        dashboard_data['action_items'] = action_items
        
        return dashboard_data
    
    def export_compliance_report(self, report: ComplianceReport, 
                               format: str = 'json') -> str:
        """Export compliance report in specified format."""
        if format.lower() == 'json':
            return json.dumps(report, indent=2, default=str)
        elif format.lower() == 'csv':
            return self._export_csv_report(report)
        elif format.lower() == 'html':
            return self._export_html_report(report)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def _export_csv_report(self, report: ComplianceReport) -> str:
        """Export compliance report as CSV."""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Headers
        writer.writerow([
            'Control ID', 'Framework', 'Status', 'Risk Level', 'Score',
            'Findings Count', 'Recommendations Count', 'Affected Assets',
            'Assessment Date', 'Remediation Timeline'
        ])
        
        # Data rows
        for assessment in report.control_assessments:
            writer.writerow([
                assessment.control_id,
                assessment.framework.value,
                assessment.status.value,
                assessment.risk_level.value,
                assessment.score,
                len(assessment.findings),
                len(assessment.recommendations),
                len(assessment.affected_assets),
                assessment.assessment_date,
                assessment.remediation_timeline or 'TBD'
            ])
        
        return output.getvalue()
    
    def _export_html_report(self, report: ComplianceReport) -> str:
        """Export compliance report as HTML."""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Compliance Assessment Report - {report.report_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; }}
        .summary {{ background-color: #e3f2fd; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .control {{ background-color: #fff; border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .critical {{ border-left: 5px solid #f44336; }}
        .high {{ border-left: 5px solid #ff9800; }}
        .moderate {{ border-left: 5px solid #ffeb3b; }}
        .low {{ border-left: 5px solid #4caf50; }}
        .score {{ float: right; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Compliance Assessment Report</h1>
        <p><strong>Report ID:</strong> {report.report_id}</p>
        <p><strong>Assessment Date:</strong> {report.assessment_date}</p>
        <p><strong>Overall Status:</strong> {report.overall_status.value.replace('_', ' ').title()}</p>
        <p><strong>Overall Score:</strong> {report.overall_score:.1f}/100</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>{report.executive_summary.replace(chr(10), '<br>').replace('**', '<strong>').replace('**', '</strong>')}</p>
    </div>
    
    <h2>Control Assessments</h2>
"""
        
        for assessment in report.control_assessments:
            risk_class = assessment.risk_level.value.lower()
            html += f"""
    <div class="control {risk_class}">
        <h3>{assessment.control_id} - {assessment.framework.value.upper()}<span class="score">{assessment.score:.1f}/100</span></h3>
        <p><strong>Status:</strong> {assessment.status.value.replace('_', ' ').title()}</p>
        <p><strong>Risk Level:</strong> {assessment.risk_level.value.title()}</p>
        
        <h4>Findings:</h4>
        <ul>
"""
            for finding in assessment.findings:
                html += f"<li>{finding}</li>"
                
            html += "</ul><h4>Recommendations:</h4><ul>"
            
            for rec in assessment.recommendations:
                html += f"<li>{rec}</li>"
                
            html += "</ul></div>"
        
        html += """
    <div class="summary">
        <h2>Risk Matrix</h2>
        <table>
            <tr><th>Risk Level</th><th>Control Count</th><th>Action Required</th></tr>
"""
        
        risk_counts = defaultdict(int)
        for assessment in report.control_assessments:
            risk_counts[assessment.risk_level] += 1
            
        for risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MODERATE, RiskLevel.LOW]:
            count = risk_counts[risk_level]
            if count > 0:
                action = {
                    RiskLevel.CRITICAL: 'Immediate Action Required',
                    RiskLevel.HIGH: 'Priority Remediation',
                    RiskLevel.MODERATE: 'Planned Remediation',
                    RiskLevel.LOW: 'Routine Monitoring'
                }[risk_level]
                html += f"<tr><td>{risk_level.value.title()}</td><td>{count}</td><td>{action}</td></tr>"
        
        html += """
        </table>
    </div>
</body>
</html>
"""
        
        return html

    def get_compliance_metrics(self) -> Dict[str, Any]:
        """Get compliance engine metrics and statistics."""
        return {
            'supported_frameworks': [f.value for f in ComplianceFramework],
            'active_assessors': len(self.assessors),
            'assessment_capabilities': {
                'automated_control_assessment': True,
                'risk_level_calculation': True,
                'remediation_planning': True,
                'compliance_reporting': True,
                'dashboard_integration': True
            },
            'supported_export_formats': ['json', 'csv', 'html'],
            'quantum_readiness_focus': True
        }
