"""Compliance and regulatory framework service."""

from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import json

from ..core import ScanResults, Vulnerability, Severity
from ..models import ComplianceMetrics


class ComplianceService:
    """Service for compliance assessment and regulatory framework mapping."""
    
    def __init__(self):
        """Initialize compliance service."""
        self.frameworks = self._init_compliance_frameworks()
    
    def assess_compliance(self, results: ScanResults, 
                         framework: str = "NIST") -> ComplianceMetrics:
        """Assess compliance against a regulatory framework.
        
        Args:
            results: Scan results containing vulnerabilities
            framework: Compliance framework (NIST, BSI, ANSSI, etc.)
            
        Returns:
            Compliance metrics and assessment
        """
        if framework not in self.frameworks:
            raise ValueError(f"Unsupported framework: {framework}")
        
        framework_config = self.frameworks[framework]
        
        # Assess requirements
        requirements_met = []
        requirements_pending = []
        
        for req_id, requirement in framework_config["requirements"].items():
            if self._is_requirement_met(requirement, results):
                requirements_met.append(req_id)
            else:
                requirements_pending.append(req_id)
        
        # Calculate compliance percentage
        total_requirements = len(framework_config["requirements"])
        compliance_percentage = (len(requirements_met) / total_requirements) * 100 if total_requirements > 0 else 0
        
        # Determine risk level
        risk_level = self._determine_compliance_risk_level(compliance_percentage, results)
        
        return ComplianceMetrics(
            framework=framework,
            compliance_percentage=compliance_percentage,
            requirements_met=requirements_met,
            requirements_pending=requirements_pending,
            deadline=framework_config["deadline"],
            risk_level=risk_level
        )
    
    def generate_compliance_report(self, results: ScanResults, 
                                 frameworks: Optional[List[str]] = None) -> Dict[str, Any]:
        """Generate comprehensive compliance report.
        
        Args:
            results: Scan results
            frameworks: List of frameworks to assess (default: all)
            
        Returns:
            Compliance report with multiple framework assessments
        """
        if frameworks is None:
            frameworks = list(self.frameworks.keys())
        
        assessments = {}
        for framework in frameworks:
            if framework in self.frameworks:
                assessments[framework] = self.assess_compliance(results, framework)
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(assessments, results)
        
        # Create action plan
        action_plan = self._create_compliance_action_plan(assessments, results)
        
        # Calculate timeline to compliance
        timeline = self._calculate_compliance_timeline(assessments)
        
        report = {
            "metadata": {
                "generated_date": datetime.now().isoformat(),
                "scan_path": results.scan_path,
                "frameworks_assessed": frameworks
            },
            "executive_summary": executive_summary,
            "framework_assessments": {
                framework: self._compliance_metrics_to_dict(metrics)
                for framework, metrics in assessments.items()
            },
            "action_plan": action_plan,
            "timeline_to_compliance": timeline,
            "regulatory_guidance": self._get_regulatory_guidance(assessments)
        }
        
        return report
    
    def _init_compliance_frameworks(self) -> Dict[str, Dict[str, Any]]:
        """Initialize compliance framework definitions."""
        return {
            "NIST": {
                "name": "NIST Post-Quantum Cryptography",
                "deadline": "2027-01-01",
                "description": "NIST SP 800-208 and related PQC migration guidance",
                "requirements": {
                    "PQC-1": {
                        "title": "Cryptographic Inventory",
                        "description": "Maintain complete inventory of cryptographic implementations",
                        "check": "inventory_complete"
                    },
                    "PQC-2": {
                        "title": "Vulnerability Assessment", 
                        "description": "Regular assessment of quantum-vulnerable cryptography",
                        "check": "vulnerability_scanning"
                    },
                    "PQC-3": {
                        "title": "Migration Planning",
                        "description": "Documented migration plan with timelines",
                        "check": "migration_plan_exists"
                    },
                    "PQC-4": {
                        "title": "Algorithm Standardization",
                        "description": "Use only NIST-approved PQC algorithms",
                        "check": "nist_approved_algorithms"
                    },
                    "PQC-5": {
                        "title": "Crypto-Agility",
                        "description": "Implement crypto-agility for future transitions",
                        "check": "crypto_agility_framework"
                    },
                    "PQC-6": {
                        "title": "High-Value Assets",
                        "description": "Priority migration of high-value asset cryptography",
                        "check": "high_value_assets_protected"
                    },
                    "PQC-7": {
                        "title": "Testing and Validation",
                        "description": "Comprehensive testing of PQC implementations",
                        "check": "testing_framework"
                    },
                    "PQC-8": {
                        "title": "Supply Chain Security",
                        "description": "Assess and secure cryptographic supply chain",
                        "check": "supply_chain_assessment"
                    }
                }
            },
            "BSI": {
                "name": "German BSI Technical Guideline TR-02102",
                "deadline": "2026-12-31",
                "description": "German Federal Office for Information Security PQC guidelines",
                "requirements": {
                    "TR-1": {
                        "title": "Transition Strategy",
                        "description": "Defined transition strategy to quantum-safe cryptography",
                        "check": "transition_strategy"
                    },
                    "TR-2": {
                        "title": "Risk Assessment",
                        "description": "Risk assessment of quantum threats",
                        "check": "quantum_risk_assessment"
                    },
                    "TR-3": {
                        "title": "Implementation Guidelines",
                        "description": "Follow BSI implementation guidelines",
                        "check": "bsi_guidelines_compliance"
                    },
                    "TR-4": {
                        "title": "Certificate Management",
                        "description": "Quantum-safe certificate management",
                        "check": "quantum_safe_certificates"
                    }
                }
            },
            "ANSSI": {
                "name": "French ANSSI Quantum-Safe Cryptography",
                "deadline": "2027-06-30",
                "description": "French National Cybersecurity Agency PQC requirements",
                "requirements": {
                    "ANSSI-1": {
                        "title": "Cryptographic State Assessment",
                        "description": "Complete assessment of current cryptographic state",
                        "check": "crypto_state_assessment"
                    },
                    "ANSSI-2": {
                        "title": "Migration Roadmap",
                        "description": "Detailed migration roadmap with milestones",
                        "check": "migration_roadmap"
                    },
                    "ANSSI-3": {
                        "title": "Security Monitoring",
                        "description": "Continuous monitoring of cryptographic security",
                        "check": "security_monitoring"
                    }
                }
            },
            "CNSS": {
                "name": "US CNSS Policy 15 - Quantum-Safe Cryptography",
                "deadline": "2030-12-31",
                "description": "Committee on National Security Systems quantum-safe policy",
                "requirements": {
                    "CNSS-1": {
                        "title": "National Security Systems",
                        "description": "Quantum-safe cryptography for NSS",
                        "check": "nss_protection"
                    },
                    "CNSS-2": {
                        "title": "Classified Information",
                        "description": "Protection of classified information",
                        "check": "classified_info_protection"
                    },
                    "CNSS-3": {
                        "title": "Supply Chain Risk",
                        "description": "Quantum-safe supply chain management",
                        "check": "supply_chain_quantum_safe"
                    }
                }
            }
        }
    
    def _is_requirement_met(self, requirement: Dict[str, str], 
                           results: ScanResults) -> bool:
        """Check if a specific requirement is met."""
        check_type = requirement["check"]
        
        if check_type == "inventory_complete":
            # Basic inventory exists if we have scan results
            return results.scanned_files > 0
        
        elif check_type == "vulnerability_scanning":
            # Vulnerability scanning performed (we have this tool!)
            return True
        
        elif check_type == "migration_plan_exists":
            # This would require checking for migration plan documentation
            # For now, we consider it not met if vulnerabilities exist
            return len(results.vulnerabilities) == 0
        
        elif check_type == "nist_approved_algorithms":
            # Check if any non-NIST approved algorithms are in use
            # All current vulnerabilities are non-approved
            return len(results.vulnerabilities) == 0
        
        elif check_type == "crypto_agility_framework":
            # This requires implementation assessment
            # Consider not met if many different algorithms are used
            algorithms = set(v.algorithm for v in results.vulnerabilities)
            return len(algorithms) <= 2  # Simple heuristic
        
        elif check_type == "high_value_assets_protected":
            # Check if critical/high severity vulns exist
            critical_vulns = [v for v in results.vulnerabilities 
                             if v.severity in [Severity.CRITICAL, Severity.HIGH]]
            return len(critical_vulns) == 0
        
        elif check_type == "testing_framework":
            # Would need to check for test files/frameworks
            return False  # Conservative assumption
        
        elif check_type == "supply_chain_assessment":
            # Would need SBOM analysis
            return False  # Conservative assumption
        
        else:
            # Unknown check type - assume not met
            return False
    
    def _determine_compliance_risk_level(self, compliance_percentage: float,
                                       results: ScanResults) -> str:
        """Determine compliance risk level."""
        
        # Factor in vulnerability severity
        critical_vulns = len([v for v in results.vulnerabilities if v.severity == Severity.CRITICAL])
        high_vulns = len([v for v in results.vulnerabilities if v.severity == Severity.HIGH])
        
        if compliance_percentage < 30 or critical_vulns > 0:
            return "CRITICAL"
        elif compliance_percentage < 50 or high_vulns > 5:
            return "HIGH" 
        elif compliance_percentage < 70:
            return "MEDIUM"
        elif compliance_percentage < 90:
            return "LOW"
        else:
            return "MINIMAL"
    
    def _generate_executive_summary(self, assessments: Dict[str, ComplianceMetrics],
                                  results: ScanResults) -> Dict[str, Any]:
        """Generate executive summary of compliance status."""
        
        # Calculate overall compliance
        if assessments:
            avg_compliance = sum(a.compliance_percentage for a in assessments.values()) / len(assessments)
        else:
            avg_compliance = 0.0
        
        # Identify most critical gaps
        critical_gaps = []
        for framework, metrics in assessments.items():
            if metrics.compliance_percentage < 50:
                critical_gaps.append(f"{framework}: {metrics.compliance_percentage:.1f}% compliant")
        
        # Calculate time to compliance deadlines
        nearest_deadline = None
        if assessments:
            deadlines = [datetime.strptime(a.deadline, "%Y-%m-%d") for a in assessments.values()]
            nearest_deadline = min(deadlines)
            days_to_deadline = (nearest_deadline - datetime.now()).days
        else:
            days_to_deadline = 0
        
        return {
            "overall_compliance_percentage": avg_compliance,
            "compliance_status": "COMPLIANT" if avg_compliance >= 90 else "NON-COMPLIANT",
            "critical_gaps": critical_gaps,
            "frameworks_assessed": len(assessments),
            "total_vulnerabilities": len(results.vulnerabilities),
            "days_to_nearest_deadline": days_to_deadline,
            "recommended_action": self._get_recommended_action(avg_compliance, days_to_deadline)
        }
    
    def _get_recommended_action(self, compliance_percentage: float, 
                               days_to_deadline: int) -> str:
        """Get recommended action based on compliance status."""
        
        if compliance_percentage < 30:
            return "IMMEDIATE ACTION REQUIRED - Begin emergency compliance initiative"
        elif compliance_percentage < 50:
            return "URGENT - Accelerate compliance efforts with dedicated resources"
        elif compliance_percentage < 70:
            return "HIGH PRIORITY - Maintain steady progress toward compliance"
        elif days_to_deadline < 365:
            return "MONITOR - Continue planned compliance activities"
        else:
            return "MAINTAIN - Sustain current compliance levels"
    
    def _create_compliance_action_plan(self, assessments: Dict[str, ComplianceMetrics],
                                     results: ScanResults) -> Dict[str, Any]:
        """Create compliance action plan."""
        
        # Collect all pending requirements
        all_pending = {}
        for framework, metrics in assessments.items():
            for req in metrics.requirements_pending:
                if req not in all_pending:
                    all_pending[req] = []
                all_pending[req].append(framework)
        
        # Prioritize actions
        high_priority_actions = []
        medium_priority_actions = []
        low_priority_actions = []
        
        for req, frameworks in all_pending.items():
            action = {
                "requirement": req,
                "affected_frameworks": frameworks,
                "description": self._get_requirement_description(req, frameworks[0]),
                "estimated_effort": self._estimate_requirement_effort(req),
                "dependencies": self._get_requirement_dependencies(req)
            }
            
            # Prioritize based on number of frameworks and requirement type
            if len(frameworks) >= 2 or "PQC-1" in req or "PQC-6" in req:
                high_priority_actions.append(action)
            elif "TR-" in req or "ANSSI-" in req:
                medium_priority_actions.append(action)
            else:
                low_priority_actions.append(action)
        
        return {
            "high_priority": high_priority_actions,
            "medium_priority": medium_priority_actions,
            "low_priority": low_priority_actions,
            "immediate_actions": [
                "Complete cryptographic inventory assessment",
                "Establish PQC migration team and governance",
                "Begin pilot PQC implementation in non-critical systems"
            ],
            "success_metrics": [
                "Monthly compliance percentage improvement",
                "Reduction in critical vulnerabilities",
                "Framework requirement completion rate"
            ]
        }
    
    def _get_requirement_description(self, req_id: str, framework: str) -> str:
        """Get description for a requirement."""
        if framework in self.frameworks:
            requirements = self.frameworks[framework]["requirements"]
            if req_id in requirements:
                return requirements[req_id]["description"]
        return "Unknown requirement"
    
    def _estimate_requirement_effort(self, req_id: str) -> str:
        """Estimate effort required for a requirement."""
        effort_map = {
            "PQC-1": "2-4 weeks",
            "PQC-2": "1-2 weeks", 
            "PQC-3": "4-6 weeks",
            "PQC-4": "8-12 weeks",
            "PQC-5": "12-16 weeks",
            "PQC-6": "6-8 weeks",
            "PQC-7": "4-6 weeks",
            "PQC-8": "6-10 weeks"
        }
        return effort_map.get(req_id, "2-4 weeks")
    
    def _get_requirement_dependencies(self, req_id: str) -> List[str]:
        """Get dependencies for a requirement."""
        dependencies_map = {
            "PQC-3": ["PQC-1", "PQC-2"],  # Migration planning needs inventory and assessment
            "PQC-4": ["PQC-1", "PQC-3"],  # Algorithm implementation needs planning
            "PQC-5": ["PQC-4"],           # Crypto-agility needs algorithms
            "PQC-6": ["PQC-1", "PQC-2"],  # High-value protection needs assessment
            "PQC-7": ["PQC-4"],           # Testing needs implementations
            "PQC-8": ["PQC-1"]            # Supply chain needs inventory
        }
        return dependencies_map.get(req_id, [])
    
    def _calculate_compliance_timeline(self, assessments: Dict[str, ComplianceMetrics]) -> Dict[str, Any]:
        """Calculate timeline to achieve compliance."""
        
        timelines = {}
        
        for framework, metrics in assessments.items():
            deadline = datetime.strptime(metrics.deadline, "%Y-%m-%d")
            days_remaining = (deadline - datetime.now()).days
            
            # Estimate time needed based on current compliance
            pending_count = len(metrics.requirements_pending)
            weeks_needed = pending_count * 3  # Assume 3 weeks per requirement
            
            status = "ON_TRACK"
            if weeks_needed * 7 > days_remaining:
                status = "AT_RISK"
            if weeks_needed * 7 > days_remaining * 1.5:
                status = "CRITICAL"
            
            timelines[framework] = {
                "deadline": metrics.deadline,
                "days_remaining": days_remaining,
                "estimated_weeks_needed": weeks_needed,
                "status": status,
                "compliance_percentage": metrics.compliance_percentage
            }
        
        return timelines
    
    def _get_regulatory_guidance(self, assessments: Dict[str, ComplianceMetrics]) -> Dict[str, Any]:
        """Get regulatory guidance and best practices."""
        
        guidance = {
            "NIST": {
                "primary_documents": [
                    "NIST SP 800-208: Recommendation for Stateful Hash-Based Signature Schemes",
                    "NIST SP 800-56C: Recommendation for Key Derivation",
                    "NIST IR 8413: Status Report on the Third Round of NIST PQC Standardization"
                ],
                "key_recommendations": [
                    "Begin migration planning immediately",
                    "Prioritize algorithms with strong security proofs",
                    "Implement hybrid approaches during transition"
                ]
            },
            "BSI": {
                "primary_documents": [
                    "BSI TR-02102-1: Cryptographic Mechanisms",
                    "BSI Technical Guideline TR-03116: Quantum-Safe Cryptography"
                ],
                "key_recommendations": [
                    "Follow conservative security parameters",
                    "Ensure interoperability with European systems",
                    "Implement rigorous testing procedures"
                ]
            },
            "general_best_practices": [
                "Maintain crypto-agility for future algorithm updates",
                "Implement defense-in-depth strategies",
                "Regular security audits and assessments",
                "Staff training on post-quantum cryptography",
                "Establish incident response procedures for crypto failures"
            ],
            "migration_phases": [
                "Phase 1: Inventory and risk assessment (3-6 months)",
                "Phase 2: Pilot implementations and testing (6-12 months)",
                "Phase 3: Production migration of critical systems (12-24 months)",
                "Phase 4: Complete migration and optimization (24-36 months)"
            ]
        }
        
        return guidance
    
    def _compliance_metrics_to_dict(self, metrics: ComplianceMetrics) -> Dict[str, Any]:
        """Convert compliance metrics to dictionary."""
        return {
            "framework": metrics.framework,
            "compliance_percentage": metrics.compliance_percentage,
            "requirements_met": metrics.requirements_met,
            "requirements_pending": metrics.requirements_pending,
            "deadline": metrics.deadline,
            "risk_level": metrics.risk_level
        }
    
    def export_compliance_report(self, report: Dict[str, Any], 
                                output_path: str, format: str = "json") -> None:
        """Export compliance report to file.
        
        Args:
            report: Compliance report data
            output_path: Output file path
            format: Export format (json, html, pdf)
        """
        if format.lower() == "json":
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
        elif format.lower() == "html":
            html_content = self._generate_compliance_html(report)
            with open(output_path, 'w') as f:
                f.write(html_content)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def _generate_compliance_html(self, report: Dict[str, Any]) -> str:
        """Generate HTML compliance report."""
        
        # Extract key data
        summary = report.get("executive_summary", {})
        assessments = report.get("framework_assessments", {})
        action_plan = report.get("action_plan", {})
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>PQC Compliance Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; }}
                .summary {{ background: #f5f5f5; padding: 20px; margin: 20px 0; border-radius: 5px; }}
                .framework {{ margin: 20px 0; border: 1px solid #ddd; padding: 15px; }}
                .compliant {{ background: #d4edda; }}
                .non-compliant {{ background: #f8d7da; }}
                .action-item {{ margin: 10px 0; padding: 10px; background: #fff3cd; border-radius: 3px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔐 Post-Quantum Cryptography Compliance Report</h1>
                <p>Generated: {report.get('metadata', {}).get('generated_date', 'Unknown')}</p>
            </div>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <p><strong>Overall Compliance:</strong> {summary.get('overall_compliance_percentage', 0):.1f}%</p>
                <p><strong>Status:</strong> {summary.get('compliance_status', 'Unknown')}</p>
                <p><strong>Days to Nearest Deadline:</strong> {summary.get('days_to_nearest_deadline', 0)}</p>
                <p><strong>Recommended Action:</strong> {summary.get('recommended_action', 'Unknown')}</p>
            </div>
            
            <h2>Framework Assessments</h2>
        """
        
        for framework, assessment in assessments.items():
            compliance_class = "compliant" if assessment["compliance_percentage"] >= 70 else "non-compliant"
            html += f"""
            <div class="framework {compliance_class}">
                <h3>{framework}</h3>
                <p><strong>Compliance:</strong> {assessment['compliance_percentage']:.1f}%</p>
                <p><strong>Risk Level:</strong> {assessment['risk_level']}</p>
                <p><strong>Deadline:</strong> {assessment['deadline']}</p>
                <p><strong>Requirements Met:</strong> {len(assessment['requirements_met'])}</p>
                <p><strong>Requirements Pending:</strong> {len(assessment['requirements_pending'])}</p>
            </div>
            """
        
        html += "<h2>High Priority Actions</h2>"
        for action in action_plan.get("high_priority", []):
            html += f"""
            <div class="action-item">
                <strong>{action['requirement']}</strong>: {action['description']}
                <br><em>Estimated Effort: {action['estimated_effort']}</em>
            </div>
            """
        
        html += "</body></html>"
        return html