"""Report generation functionality for different output formats."""

import json
from pathlib import Path
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from .core import ScanResults, Vulnerability, Severity, CryptoAlgorithm


class BaseReporter(ABC):
    """Base class for report generators."""
    
    @abstractmethod
    def generate_report(self, results: ScanResults, output_path: Path, **kwargs) -> None:
        """Generate a report from scan results."""
        pass


class JSONReporter(BaseReporter):
    """Generate JSON format reports."""
    
    def generate_report(self, results: ScanResults, output_path: Path, 
                       migration_plan: Optional[Dict[str, Any]] = None) -> None:
        """Generate JSON report."""
        
        # Convert dataclass objects to dictionaries
        report_data = {
            "scan_metadata": {
                "scan_path": results.scan_path,
                "timestamp": results.timestamp,
                "scan_time": results.scan_time,
                "scanned_files": results.scanned_files,
                "total_lines": results.total_lines,
                "languages_detected": results.languages_detected
            },
            "summary": {
                "total_vulnerabilities": len(results.vulnerabilities),
                "by_severity": self._get_severity_counts(results.vulnerabilities),
                "by_algorithm": self._get_algorithm_counts(results.vulnerabilities)
            },
            "vulnerabilities": [
                {
                    "file_path": vuln.file_path,
                    "line_number": vuln.line_number,
                    "algorithm": vuln.algorithm.value,
                    "severity": vuln.severity.value,
                    "key_size": vuln.key_size,
                    "description": vuln.description,
                    "code_snippet": vuln.code_snippet,
                    "recommendation": vuln.recommendation,
                    "cwe_id": vuln.cwe_id
                }
                for vuln in results.vulnerabilities
            ]
        }
        
        if migration_plan:
            report_data["migration_plan"] = migration_plan
        
        with open(output_path, 'w') as f:
            json.dump(report_data, f, indent=2)
    
    def _get_severity_counts(self, vulnerabilities) -> Dict[str, int]:
        """Count vulnerabilities by severity."""
        counts = {severity.value: 0 for severity in Severity}
        for vuln in vulnerabilities:
            counts[vuln.severity.value] += 1
        return counts
    
    def _get_algorithm_counts(self, vulnerabilities) -> Dict[str, int]:
        """Count vulnerabilities by algorithm."""
        counts = {}
        for vuln in vulnerabilities:
            algo = vuln.algorithm.value
            counts[algo] = counts.get(algo, 0) + 1
        return counts


class HTMLReporter(BaseReporter):
    """Generate HTML format reports."""
    
    def generate_report(self, results: ScanResults, output_path: Path,
                       migration_plan: Optional[Dict[str, Any]] = None) -> None:
        """Generate HTML report."""
        
        severity_counts = self._get_severity_counts(results.vulnerabilities)
        algorithm_counts = self._get_algorithm_counts(results.vulnerabilities)
        
        html_content = self._generate_html_template(
            results, severity_counts, algorithm_counts, migration_plan
        )
        
        with open(output_path, 'w') as f:
            f.write(html_content)
    
    def _generate_html_template(self, results: ScanResults, 
                               severity_counts: Dict[str, int],
                               algorithm_counts: Dict[str, int],
                               migration_plan: Optional[Dict[str, Any]]) -> str:
        """Generate complete HTML report."""
        
        # Generate vulnerability table rows
        vuln_rows = ""
        for vuln in results.vulnerabilities:
            severity_class = f"severity-{vuln.severity.value}"
            vuln_rows += f"""
            <tr class="{severity_class}">
                <td>{vuln.file_path}</td>
                <td>{vuln.line_number}</td>
                <td>{vuln.algorithm.value}</td>
                <td><span class="badge {severity_class}">{vuln.severity.value.upper()}</span></td>
                <td>{vuln.key_size or 'N/A'}</td>
                <td>{vuln.description}</td>
                <td><code>{vuln.code_snippet}</code></td>
                <td>{vuln.recommendation}</td>
            </tr>
            """
        
        # Generate charts data
        severity_chart_data = json.dumps(severity_counts)
        algorithm_chart_data = json.dumps(algorithm_counts)
        
        # Migration plan section
        migration_section = ""
        if migration_plan:
            migration_section = self._generate_migration_plan_html(migration_plan)
        
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>PQC Migration Audit Report</title>
            <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
            <style>
                {self._get_css_styles()}
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <h1>🔐 PQC Migration Audit Report</h1>
                    <div class="meta-info">
                        <p><strong>Scan Path:</strong> {results.scan_path}</p>
                        <p><strong>Scan Date:</strong> {results.timestamp}</p>
                        <p><strong>Files Scanned:</strong> {results.scanned_files}</p>
                        <p><strong>Lines Analyzed:</strong> {results.total_lines:,}</p>
                        <p><strong>Scan Duration:</strong> {results.scan_time:.2f}s</p>
                        <p><strong>Languages:</strong> {', '.join(results.languages_detected)}</p>
                    </div>
                </header>
                
                <section class="summary">
                    <h2>Executive Summary</h2>
                    <div class="metrics">
                        <div class="metric critical">
                            <h3>{severity_counts.get('critical', 0)}</h3>
                            <p>Critical</p>
                        </div>
                        <div class="metric high">
                            <h3>{severity_counts.get('high', 0)}</h3>
                            <p>High</p>
                        </div>
                        <div class="metric medium">
                            <h3>{severity_counts.get('medium', 0)}</h3>
                            <p>Medium</p>
                        </div>
                        <div class="metric low">
                            <h3>{severity_counts.get('low', 0)}</h3>
                            <p>Low</p>
                        </div>
                    </div>
                </section>
                
                <section class="charts">
                    <div class="chart-container">
                        <div id="severityChart"></div>
                    </div>
                    <div class="chart-container">
                        <div id="algorithmChart"></div>
                    </div>
                </section>
                
                {migration_section}
                
                <section class="vulnerabilities">
                    <h2>Detailed Vulnerabilities</h2>
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>File</th>
                                    <th>Line</th>
                                    <th>Algorithm</th>
                                    <th>Severity</th>
                                    <th>Key Size</th>
                                    <th>Description</th>
                                    <th>Code</th>
                                    <th>Recommendation</th>
                                </tr>
                            </thead>
                            <tbody>
                                {vuln_rows}
                            </tbody>
                        </table>
                    </div>
                </section>
            </div>
            
            <script>
                // Severity distribution chart
                var severityData = [{
                    x: Object.keys({severity_chart_data}),
                    y: Object.values({severity_chart_data}),
                    type: 'bar',
                    marker: {{
                        color: ['#d32f2f', '#f57c00', '#fbc02d', '#388e3c']
                    }}
                }];
                
                Plotly.newPlot('severityChart', severityData, {{
                    title: 'Vulnerabilities by Severity',
                    xaxis: {{title: 'Severity Level'}},
                    yaxis: {{title: 'Count'}}
                }});
                
                // Algorithm distribution chart
                var algorithmData = [{
                    labels: Object.keys({algorithm_chart_data}),
                    values: Object.values({algorithm_chart_data}),
                    type: 'pie',
                    textinfo: 'label+percent',
                    textposition: 'outside'
                }];
                
                Plotly.newPlot('algorithmChart', algorithmData, {{
                    title: 'Vulnerabilities by Algorithm'
                }});
            </script>
        </body>
        </html>
        """
    
    def _generate_migration_plan_html(self, migration_plan: Dict[str, Any]) -> str:
        """Generate HTML for migration plan section."""
        phases_html = ""
        for phase in migration_plan.get('migration_phases', []):
            phases_html += f"""
            <div class="phase">
                <h4>Phase {phase['phase']}: {phase['name']}</h4>
                <p>{phase['description']}</p>
                <p><strong>Estimated Effort:</strong> {phase['estimated_effort']}</p>
                <p><strong>Items:</strong> {len(phase.get('vulnerabilities', []))}</p>
            </div>
            """
        
        return f"""
        <section class="migration-plan">
            <h2>Migration Plan</h2>
            <div class="plan-summary">
                <h3>Summary</h3>
                <ul>
                    <li>Total Vulnerabilities: {migration_plan['summary']['total_vulnerabilities']}</li>
                    <li>Critical: {migration_plan['summary']['critical']}</li>
                    <li>High: {migration_plan['summary']['high']}</li>
                    <li>Medium: {migration_plan['summary']['medium']}</li>
                    <li>Low: {migration_plan['summary']['low']}</li>
                </ul>
            </div>
            <div class="phases">
                <h3>Migration Phases</h3>
                {phases_html}
            </div>
        </section>
        """
    
    def _get_css_styles(self) -> str:
        """Get CSS styles for HTML report."""
        return """
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: white;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        
        header {
            text-align: center;
            margin-bottom: 30px;
            border-bottom: 2px solid #e0e0e0;
            padding-bottom: 20px;
        }
        
        h1 {
            color: #1976d2;
            margin-bottom: 10px;
        }
        
        .meta-info {
            color: #666;
            font-size: 0.9em;
        }
        
        .summary {
            margin-bottom: 30px;
        }
        
        .metrics {
            display: flex;
            justify-content: space-around;
            margin: 20px 0;
        }
        
        .metric {
            text-align: center;
            padding: 20px;
            border-radius: 8px;
            color: white;
            min-width: 120px;
        }
        
        .metric.critical { background-color: #d32f2f; }
        .metric.high { background-color: #f57c00; }
        .metric.medium { background-color: #fbc02d; color: #333; }
        .metric.low { background-color: #388e3c; }
        
        .metric h3 {
            font-size: 2em;
            margin: 0;
        }
        
        .metric p {
            margin: 5px 0 0 0;
            font-size: 0.9em;
        }
        
        .charts {
            display: flex;
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .chart-container {
            flex: 1;
            height: 400px;
        }
        
        .migration-plan {
            margin-bottom: 30px;
            padding: 20px;
            background-color: #f8f9fa;
            border-radius: 8px;
        }
        
        .phase {
            margin-bottom: 15px;
            padding: 15px;
            background: white;
            border-radius: 4px;
            border-left: 4px solid #1976d2;
        }
        
        .table-container {
            overflow-x: auto;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        th {
            background-color: #f5f5f5;
            font-weight: 600;
        }
        
        .severity-critical { background-color: #ffebee; }
        .severity-high { background-color: #fff3e0; }
        .severity-medium { background-color: #f3e5f5; }
        .severity-low { background-color: #e8f5e8; }
        
        .badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            color: white;
        }
        
        .badge.severity-critical { background-color: #d32f2f; }
        .badge.severity-high { background-color: #f57c00; }
        .badge.severity-medium { background-color: #fbc02d; color: #333; }
        .badge.severity-low { background-color: #388e3c; }
        
        code {
            background-color: #f5f5f5;
            padding: 2px 4px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
        """
    
    def _get_severity_counts(self, vulnerabilities) -> Dict[str, int]:
        """Count vulnerabilities by severity."""
        counts = {severity.value: 0 for severity in Severity}
        for vuln in vulnerabilities:
            counts[vuln.severity.value] += 1
        return counts
    
    def _get_algorithm_counts(self, vulnerabilities) -> Dict[str, int]:
        """Count vulnerabilities by algorithm."""
        counts = {}
        for vuln in vulnerabilities:
            algo = vuln.algorithm.value
            counts[algo] = counts.get(algo, 0) + 1
        return counts


class SARIFReporter(BaseReporter):
    """Generate SARIF format reports for CI/CD integration."""
    
    def generate_report(self, results: ScanResults, output_path: Path, **kwargs) -> None:
        """Generate SARIF report."""
        
        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "pqc-migration-audit",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/terragonlabs/pqc-migration-audit",
                            "rules": self._get_sarif_rules()
                        }
                    },
                    "results": [
                        self._vulnerability_to_sarif_result(vuln)
                        for vuln in results.vulnerabilities
                    ]
                }
            ]
        }
        
        with open(output_path, 'w') as f:
            json.dump(sarif_data, f, indent=2)
    
    def _get_sarif_rules(self) -> list:
        """Get SARIF rule definitions."""
        return [
            {
                "id": "quantum-vulnerable-crypto",
                "name": "QuantumVulnerableCryptography",
                "shortDescription": {
                    "text": "Quantum-vulnerable cryptographic algorithm detected"
                },
                "fullDescription": {
                    "text": "This rule identifies cryptographic implementations that are vulnerable to quantum computer attacks."
                },
                "defaultConfiguration": {
                    "level": "warning"
                },
                "help": {
                    "text": "Replace with post-quantum cryptographic alternatives.",
                    "markdown": "Replace with post-quantum cryptographic alternatives such as ML-KEM (Kyber) or ML-DSA (Dilithium)."
                }
            }
        ]
    
    def _vulnerability_to_sarif_result(self, vuln: Vulnerability) -> Dict[str, Any]:
        """Convert vulnerability to SARIF result format."""
        
        # Map severity levels to SARIF levels
        level_map = {
            Severity.LOW: "note",
            Severity.MEDIUM: "warning", 
            Severity.HIGH: "error",
            Severity.CRITICAL: "error"
        }
        
        return {
            "ruleId": "quantum-vulnerable-crypto",
            "level": level_map.get(vuln.severity, "warning"),
            "message": {
                "text": f"{vuln.algorithm.value} {vuln.description}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": vuln.file_path
                        },
                        "region": {
                            "startLine": vuln.line_number,
                            "snippet": {
                                "text": vuln.code_snippet
                            }
                        }
                    }
                }
            ],
            "properties": {
                "algorithm": vuln.algorithm.value,
                "severity": vuln.severity.value,
                "key_size": vuln.key_size,
                "cwe_id": vuln.cwe_id,
                "recommendation": vuln.recommendation
            }
        }


class ConsoleReporter(BaseReporter):
    """Generate console output reports."""
    
    def generate_report(self, results: ScanResults, output_path: Path = None, 
                       console: Console = None, **kwargs) -> None:
        """Generate console report."""
        
        if console is None:
            console = Console()
        
        # Summary
        total_vulns = len(results.vulnerabilities)
        if total_vulns == 0:
            console.print("✅ No quantum-vulnerable cryptography found!", style="green bold")
            return
        
        console.print(f"\n🔍 Scan Results for {results.scan_path}", style="bold blue")
        console.print(f"   Files scanned: {results.scanned_files}")
        console.print(f"   Lines analyzed: {results.total_lines:,}")
        console.print(f"   Scan time: {results.scan_time:.2f}s")
        console.print(f"   Languages: {', '.join(results.languages_detected)}")
        
        # Severity summary
        severity_counts = self._get_severity_counts(results.vulnerabilities)
        
        summary_table = Table(title=f"Found {total_vulns} Vulnerabilities")
        summary_table.add_column("Severity", style="cyan")
        summary_table.add_column("Count", justify="right", style="magenta")
        summary_table.add_column("Risk Level", style="yellow")
        
        risk_levels = {
            'critical': 'IMMEDIATE ACTION REQUIRED',
            'high': 'High Priority',
            'medium': 'Medium Priority', 
            'low': 'Low Priority'
        }
        
        for severity in ['critical', 'high', 'medium', 'low']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                summary_table.add_row(
                    severity.title(),
                    str(count),
                    risk_levels[severity]
                )
        
        console.print(summary_table)
        
        # Algorithm breakdown
        algorithm_counts = self._get_algorithm_counts(results.vulnerabilities)
        if algorithm_counts:
            console.print(f"\n🔒 Algorithms Found:")
            for algo, count in algorithm_counts.items():
                console.print(f"   {algo}: {count} instances")
        
        # Risk assessment
        from .core import RiskAssessment
        risk_assessment = RiskAssessment(results)
        risk_score = risk_assessment.calculate_harvest_now_decrypt_later_risk()
        migration_hours = risk_assessment.migration_hours
        
        risk_panel = Panel(
            f"HNDL Risk Score: {risk_score}/100\n"
            f"Estimated Migration Effort: {migration_hours} hours\n"
            f"Recommended Action: {'URGENT' if risk_score >= 80 else 'PLANNED'} migration",
            title="Risk Assessment",
            border_style="red" if risk_score >= 80 else "yellow" if risk_score >= 40 else "green"
        )
        console.print(risk_panel)
        
        # Top vulnerabilities
        if results.vulnerabilities:
            console.print(f"\n🚨 Top Vulnerabilities:")
            
            # Sort by severity (critical first)
            severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
            sorted_vulns = sorted(results.vulnerabilities, key=lambda v: severity_order[v.severity])
            
            vuln_table = Table()
            vuln_table.add_column("File", style="cyan", overflow="fold")
            vuln_table.add_column("Line", justify="right")
            vuln_table.add_column("Algorithm", style="red")
            vuln_table.add_column("Severity")
            vuln_table.add_column("Description", overflow="fold")
            
            # Show top 10 vulnerabilities
            for vuln in sorted_vulns[:10]:
                severity_style = {
                    Severity.CRITICAL: "red bold",
                    Severity.HIGH: "red", 
                    Severity.MEDIUM: "yellow",
                    Severity.LOW: "green"
                }.get(vuln.severity, "white")
                
                vuln_table.add_row(
                    vuln.file_path,
                    str(vuln.line_number),
                    vuln.algorithm.value,
                    Text(vuln.severity.value.upper(), style=severity_style),
                    vuln.description[:80] + "..." if len(vuln.description) > 80 else vuln.description
                )
            
            console.print(vuln_table)
            
            if len(results.vulnerabilities) > 10:
                console.print(f"\n... and {len(results.vulnerabilities) - 10} more vulnerabilities")
        
        # Recommendations
        console.print("\n💡 Immediate Recommendations:", style="bold green")
        console.print("   1. Prioritize critical and high-severity vulnerabilities")
        console.print("   2. Begin testing ML-KEM (Kyber) and ML-DSA (Dilithium)")
        console.print("   3. Plan gradual migration with hybrid approach")
        console.print("   4. Establish crypto-agility framework")
        
        if risk_score >= 80:
            console.print("\n⚠️  HIGH RISK: Consider immediate action for critical systems", style="red bold")
    
    def _get_severity_counts(self, vulnerabilities) -> Dict[str, int]:
        """Count vulnerabilities by severity."""
        counts = {severity.value: 0 for severity in Severity}
        for vuln in vulnerabilities:
            counts[vuln.severity.value] += 1
        return counts
    
    def _get_algorithm_counts(self, vulnerabilities) -> Dict[str, int]:
        """Count vulnerabilities by algorithm."""
        counts = {}
        for vuln in vulnerabilities:
            algo = vuln.algorithm.value
            counts[algo] = counts.get(algo, 0) + 1
        return counts