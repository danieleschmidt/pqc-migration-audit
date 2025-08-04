"""Interactive web dashboard for PQC migration tracking."""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import base64

from .types import ScanResults, Vulnerability, Severity, CryptoAlgorithm


class MigrationDashboard:
    """Generate interactive web dashboard for PQC migration tracking."""
    
    def __init__(self):
        """Initialize dashboard generator."""
        self.template_dir = Path(__file__).parent / "templates"
    
    def generate_dashboard(self, scan_results: ScanResults, 
                          historical_data: Optional[List[Dict]] = None,
                          migration_plan: Optional[Dict] = None,
                          output_path: Path = None) -> str:
        """Generate complete interactive dashboard.
        
        Args:
            scan_results: Current scan results
            historical_data: Historical scan data for trend analysis
            migration_plan: Migration plan data
            output_path: Path to save dashboard HTML
            
        Returns:
            Generated HTML dashboard content
        """
        # Prepare dashboard data
        dashboard_data = self._prepare_dashboard_data(scan_results, historical_data, migration_plan)
        
        # Generate HTML content
        html_content = self._generate_dashboard_html(dashboard_data)
        
        # Save to file if path provided
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
        
        return html_content
    
    def _prepare_dashboard_data(self, scan_results: ScanResults,
                               historical_data: Optional[List[Dict]],
                               migration_plan: Optional[Dict]) -> Dict[str, Any]:
        """Prepare data for dashboard visualization."""
        
        # Basic metrics
        vulnerabilities = scan_results.vulnerabilities
        total_vulns = len(vulnerabilities)
        
        severity_counts = {
            'critical': len([v for v in vulnerabilities if v.severity == Severity.CRITICAL]),
            'high': len([v for v in vulnerabilities if v.severity == Severity.HIGH]),
            'medium': len([v for v in vulnerabilities if v.severity == Severity.MEDIUM]),
            'low': len([v for v in vulnerabilities if v.severity == Severity.LOW])
        }
        
        algorithm_counts = {}
        for vuln in vulnerabilities:
            algo = vuln.algorithm.value
            algorithm_counts[algo] = algorithm_counts.get(algo, 0) + 1
        
        # Risk assessment
        from .core import RiskAssessment
        risk_assessment = RiskAssessment(scan_results)
        hndl_risk = risk_assessment.calculate_harvest_now_decrypt_later_risk()
        migration_hours = risk_assessment.migration_hours
        
        # File analysis
        file_vulnerability_map = {}
        for vuln in vulnerabilities:
            if vuln.file_path not in file_vulnerability_map:
                file_vulnerability_map[vuln.file_path] = []
            file_vulnerability_map[vuln.file_path].append(vuln)
        
        # Language distribution
        language_counts = {}
        for lang in scan_results.languages_detected:
            lang_vulns = [v for v in vulnerabilities 
                         if self._detect_language_from_file(v.file_path) == lang]
            language_counts[lang] = len(lang_vulns)
        
        # Timeline data for quantum threat
        timeline_data = self._generate_timeline_data()
        
        # Progress calculation if historical data available
        progress_data = None
        if historical_data:
            progress_data = self._calculate_progress_metrics(historical_data, scan_results)
        
        return {
            'scan_metadata': {
                'scan_path': scan_results.scan_path,
                'timestamp': scan_results.timestamp,
                'scan_time': scan_results.scan_time,
                'files_scanned': scan_results.scanned_files,
                'lines_analyzed': scan_results.total_lines,
                'languages_detected': scan_results.languages_detected
            },
            'vulnerability_summary': {
                'total_vulnerabilities': total_vulns,
                'severity_distribution': severity_counts,
                'algorithm_distribution': algorithm_counts,
                'language_distribution': language_counts
            },
            'risk_metrics': {
                'hndl_risk_score': hndl_risk,
                'risk_level': self._get_risk_level(hndl_risk),
                'migration_effort_hours': migration_hours,
                'estimated_cost': migration_hours * 150,  # Assuming $150/hour
                'completion_date': self._estimate_completion_date(migration_hours)
            },
            'file_analysis': {
                'most_vulnerable_files': self._get_most_vulnerable_files(file_vulnerability_map),
                'vulnerability_density': self._calculate_vulnerability_density(file_vulnerability_map, scan_results)
            },
            'timeline_data': timeline_data,
            'progress_data': progress_data,
            'migration_plan': migration_plan,
            'recommendations': self._generate_recommendations(hndl_risk, vulnerabilities)
        }
    
    def _generate_dashboard_html(self, data: Dict[str, Any]) -> str:
        """Generate complete HTML dashboard."""
        
        # Convert data to JSON for JavaScript
        dashboard_json = json.dumps(data, indent=2, default=str)
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PQC Migration Dashboard</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        {self._get_dashboard_css()}
    </style>
</head>
<body>
    <div class="container-fluid">
        <!-- Header -->
        <header class="dashboard-header">
            <div class="row align-items-center">
                <div class="col-md-8">
                    <h1><i class="fas fa-shield-alt"></i> Post-Quantum Cryptography Migration Dashboard</h1>
                    <p class="text-muted">Scan Path: {data['scan_metadata']['scan_path']} | Last Updated: {data['scan_metadata']['timestamp']}</p>
                </div>
                <div class="col-md-4 text-end">
                    <div class="risk-indicator risk-{data['risk_metrics']['risk_level'].lower()}">
                        <i class="fas fa-exclamation-triangle"></i>
                        Risk Level: {data['risk_metrics']['risk_level']}
                    </div>
                </div>
            </div>
        </header>

        <!-- Key Metrics Cards -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="metric-card critical">
                    <div class="metric-icon"><i class="fas fa-exclamation-circle"></i></div>
                    <div class="metric-content">
                        <h3>{data['vulnerability_summary']['severity_distribution']['critical']}</h3>
                        <p>Critical Vulnerabilities</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="metric-card high">
                    <div class="metric-icon"><i class="fas fa-exclamation-triangle"></i></div>
                    <div class="metric-content">
                        <h3>{data['vulnerability_summary']['severity_distribution']['high']}</h3>
                        <p>High Priority</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="metric-card info">
                    <div class="metric-icon"><i class="fas fa-clock"></i></div>
                    <div class="metric-content">
                        <h3>{data['risk_metrics']['migration_effort_hours']}</h3>
                        <p>Migration Hours</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="metric-card success">
                    <div class="metric-icon"><i class="fas fa-dollar-sign"></i></div>
                    <div class="metric-content">
                        <h3>${data['risk_metrics']['estimated_cost']:,}</h3>
                        <p>Estimated Cost</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Charts Row -->
        <div class="row mb-4">
            <div class="col-md-6">
                <div class="chart-container">
                    <h4>Vulnerability Distribution by Severity</h4>
                    <div id="severityChart"></div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="chart-container">
                    <h4>Algorithm Distribution</h4>
                    <div id="algorithmChart"></div>
                </div>
            </div>
        </div>

        <div class="row mb-4">
            <div class="col-md-8">
                <div class="chart-container">
                    <h4>Quantum Threat Timeline</h4>
                    <div id="timelineChart"></div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="chart-container">
                    <h4>Risk Score Gauge</h4>
                    <div id="riskGauge"></div>
                </div>
            </div>
        </div>

        <!-- File Analysis -->
        <div class="row mb-4">
            <div class="col-md-6">
                <div class="analysis-panel">
                    <h4><i class="fas fa-file-code"></i> Most Vulnerable Files</h4>
                    <div class="vulnerable-files-list">
                        {self._generate_vulnerable_files_html(data['file_analysis']['most_vulnerable_files'])}
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="analysis-panel">
                    <h4><i class="fas fa-lightbulb"></i> Immediate Recommendations</h4>
                    <div class="recommendations-list">
                        {self._generate_recommendations_html(data['recommendations'])}
                    </div>
                </div>
            </div>
        </div>

        <!-- Migration Plan -->
        {self._generate_migration_plan_html(data.get('migration_plan'))}

        <!-- Progress Tracking -->
        {self._generate_progress_tracking_html(data.get('progress_data'))}

        <!-- Footer -->
        <footer class="dashboard-footer">
            <div class="row">
                <div class="col-md-6">
                    <p>&copy; 2025 Terragon Labs - PQC Migration Audit Tool</p>
                </div>
                <div class="col-md-6 text-end">
                    <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
            </div>
        </footer>
    </div>

    <script>
        // Dashboard data
        const dashboardData = {dashboard_json};
        
        // Initialize charts
        document.addEventListener('DOMContentLoaded', function() {{
            initializeSeverityChart();
            initializeAlgorithmChart();
            initializeTimelineChart();
            initializeRiskGauge();
        }});

        {self._generate_dashboard_javascript()}
    </script>
</body>
</html>"""
    
    def _get_dashboard_css(self) -> str:
        """Get CSS styles for dashboard."""
        return """
        body {
            background-color: #f8f9fa;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        
        .dashboard-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            margin-bottom: 2rem;
            border-radius: 10px;
        }
        
        .dashboard-header h1 {
            margin-bottom: 0.5rem;
            font-weight: 700;
        }
        
        .risk-indicator {
            padding: 0.5rem 1rem;
            border-radius: 25px;
            font-weight: bold;
            text-align: center;
        }
        
        .risk-critical { background-color: #dc3545; color: white; }
        .risk-high { background-color: #fd7e14; color: white; }
        .risk-medium { background-color: #ffc107; color: #212529; }
        .risk-low { background-color: #28a745; color: white; }
        .risk-minimal { background-color: #6c757d; color: white; }
        
        .metric-card {
            background: white;
            border-radius: 10px;
            padding: 1.5rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            display: flex;
            align-items: center;
            margin-bottom: 1rem;
        }
        
        .metric-card.critical { border-left: 5px solid #dc3545; }
        .metric-card.high { border-left: 5px solid #fd7e14; }
        .metric-card.info { border-left: 5px solid #17a2b8; }
        .metric-card.success { border-left: 5px solid #28a745; }
        
        .metric-icon {
            font-size: 2rem;
            margin-right: 1rem;
            opacity: 0.7;
        }
        
        .metric-content h3 {
            margin-bottom: 0.25rem;
            font-size: 2rem;
            font-weight: 700;
        }
        
        .metric-content p {
            margin-bottom: 0;
            color: #6c757d;
            font-size: 0.9rem;
        }
        
        .chart-container {
            background: white;
            border-radius: 10px;
            padding: 1.5rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            margin-bottom: 1rem;
        }
        
        .chart-container h4 {
            margin-bottom: 1rem;
            color: #495057;
            font-weight: 600;
        }
        
        .analysis-panel {
            background: white;
            border-radius: 10px;
            padding: 1.5rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            height: 100%;
        }
        
        .analysis-panel h4 {
            margin-bottom: 1rem;
            color: #495057;
            font-weight: 600;
        }
        
        .vulnerable-file-item {
            display: flex;
            justify-content: between;
            align-items: center;
            padding: 0.75rem;
            margin-bottom: 0.5rem;
            background-color: #f8f9fa;
            border-radius: 5px;
            border-left: 3px solid #dc3545;
        }
        
        .file-path {
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
            flex-grow: 1;
        }
        
        .vuln-count {
            background-color: #dc3545;
            color: white;
            padding: 0.25rem 0.5rem;
            border-radius: 15px;
            font-size: 0.75rem;
            font-weight: bold;
        }
        
        .recommendation-item {
            padding: 0.75rem;
            margin-bottom: 0.5rem;
            background-color: #e3f2fd;
            border-radius: 5px;
            border-left: 3px solid #2196f3;
        }
        
        .recommendation-priority {
            font-weight: bold;
            color: #1976d2;
        }
        
        .migration-phase {
            background: white;
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            border-left: 5px solid #007bff;
        }
        
        .phase-header {
            display: flex;
            justify-content: between;
            align-items: center;
            margin-bottom: 1rem;
        }
        
        .phase-number {
            background-color: #007bff;
            color: white;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 1.2rem;
        }
        
        .progress-bar-container {
            margin: 1rem 0;
        }
        
        .dashboard-footer {
            background-color: #343a40;
            color: white;
            padding: 2rem;
            margin-top: 3rem;
            border-radius: 10px;
        }
        
        .alert-quantum {
            background: linear-gradient(45deg, #ff6b6b, #feca57);
            color: white;
            border: none;
            border-radius: 10px;
            padding: 1rem;
            margin-bottom: 2rem;
        }
        
        @media (max-width: 768px) {
            .metric-card {
                margin-bottom: 1rem;
            }
            
            .chart-container {
                margin-bottom: 2rem;
            }
        }
        """
    
    def _generate_vulnerable_files_html(self, vulnerable_files: List[Dict]) -> str:
        """Generate HTML for most vulnerable files list."""
        if not vulnerable_files:
            return "<p class='text-muted'>No vulnerable files found.</p>"
        
        html_items = []
        for file_info in vulnerable_files[:10]:  # Top 10 files
            html_items.append(f"""
            <div class="vulnerable-file-item">
                <div class="file-path">{file_info['file_path']}</div>
                <span class="vuln-count">{file_info['vulnerability_count']}</span>
            </div>
            """)
        
        return "\n".join(html_items)
    
    def _generate_recommendations_html(self, recommendations: List[str]) -> str:
        """Generate HTML for recommendations list."""
        if not recommendations:
            return "<p class='text-muted'>No specific recommendations available.</p>"
        
        html_items = []
        priorities = ['High', 'Medium', 'Low']
        
        for i, rec in enumerate(recommendations[:6]):  # Top 6 recommendations
            priority = priorities[i % len(priorities)]
            html_items.append(f"""
            <div class="recommendation-item">
                <div class="recommendation-priority">{priority} Priority:</div>
                <div>{rec}</div>
            </div>
            """)
        
        return "\n".join(html_items)
    
    def _generate_migration_plan_html(self, migration_plan: Optional[Dict]) -> str:
        """Generate HTML for migration plan section."""
        if not migration_plan:
            return ""
        
        phases_html = []
        for phase in migration_plan.get('migration_phases', []):
            phases_html.append(f"""
            <div class="migration-phase">
                <div class="phase-header">
                    <div class="d-flex align-items-center">
                        <div class="phase-number">{phase['phase']}</div>
                        <div class="ms-3">
                            <h5 class="mb-1">{phase['name']}</h5>
                            <p class="text-muted mb-0">{phase['description']}</p>
                        </div>
                    </div>
                    <div class="text-end">
                        <small class="text-muted">Est. {phase['estimated_effort']}</small>
                    </div>
                </div>
                <div class="progress-bar-container">
                    <div class="progress">
                        <div class="progress-bar" role="progressbar" style="width: 0%"></div>
                    </div>
                </div>
                <p><strong>Items:</strong> {len(phase.get('vulnerabilities', []))} vulnerabilities</p>
            </div>
            """)
        
        return f"""
        <div class="row mb-4">
            <div class="col-12">
                <div class="chart-container">
                    <h4><i class="fas fa-road"></i> Migration Roadmap</h4>
                    <div class="alert alert-quantum">
                        <i class="fas fa-exclamation-triangle"></i>
                        <strong>Quantum Computing Threat:</strong> Experts estimate that quantum computers capable of breaking current cryptography could emerge by 2030-2035. Begin migration planning now to stay ahead of the threat.
                    </div>
                    {"".join(phases_html)}
                </div>
            </div>
        </div>
        """
    
    def _generate_progress_tracking_html(self, progress_data: Optional[Dict]) -> str:
        """Generate HTML for progress tracking section."""
        if not progress_data:
            return ""
        
        return f"""
        <div class="row mb-4">
            <div class="col-12">
                <div class="chart-container">
                    <h4><i class="fas fa-chart-line"></i> Migration Progress Tracking</h4>
                    <div id="progressChart"></div>
                    <div class="row mt-3">
                        <div class="col-md-3">
                            <div class="text-center">
                                <h5>{progress_data.get('vulnerabilities_fixed', 0)}</h5>
                                <p class="text-muted">Vulnerabilities Fixed</p>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="text-center">
                                <h5>{progress_data.get('current_vulnerabilities', 0)}</h5>
                                <p class="text-muted">Remaining</p>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="text-center">
                                <h5>{progress_data.get('progress_percentage', 0):.1f}%</h5>
                                <p class="text-muted">Complete</p>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="text-center">
                                <h5>{progress_data.get('days_remaining', 'N/A')}</h5>
                                <p class="text-muted">Days to Target</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """
    
    def _generate_dashboard_javascript(self) -> str:
        """Generate JavaScript for dashboard interactivity."""
        return """
        function initializeSeverityChart() {
            const severityData = dashboardData.vulnerability_summary.severity_distribution;
            
            const data = [{
                x: Object.keys(severityData),
                y: Object.values(severityData),
                type: 'bar',
                marker: {
                    color: ['#dc3545', '#fd7e14', '#ffc107', '#28a745']
                }
            }];
            
            const layout = {
                title: false,
                xaxis: { title: 'Severity Level' },
                yaxis: { title: 'Count' },
                margin: { t: 20, r: 20, b: 40, l: 40 }
            };
            
            Plotly.newPlot('severityChart', data, layout, {responsive: true});
        }
        
        function initializeAlgorithmChart() {
            const algorithmData = dashboardData.vulnerability_summary.algorithm_distribution;
            
            const data = [{
                labels: Object.keys(algorithmData),
                values: Object.values(algorithmData),
                type: 'pie',
                textinfo: 'label+percent',
                textposition: 'outside',
                marker: {
                    colors: ['#007bff', '#28a745', '#ffc107', '#dc3545', '#6f42c1']
                }
            }];
            
            const layout = {
                title: false,
                margin: { t: 20, r: 20, b: 20, l: 20 }
            };
            
            Plotly.newPlot('algorithmChart', data, layout, {responsive: true});
        }
        
        function initializeTimelineChart() {
            const timelineData = dashboardData.timeline_data;
            
            const trace1 = {
                x: timelineData.years,
                y: timelineData.threat_levels,
                type: 'scatter',
                mode: 'lines+markers',
                name: 'Quantum Threat Level',
                line: { color: '#dc3545', width: 3 }
            };
            
            const trace2 = {
                x: timelineData.years,
                y: timelineData.migration_targets,
                type: 'scatter',
                mode: 'lines+markers',
                name: 'Migration Target',
                line: { color: '#28a745', width: 3 }
            };
            
            const layout = {
                title: false,
                xaxis: { title: 'Year' },
                yaxis: { title: 'Progress %' },
                margin: { t: 20, r: 20, b: 40, l: 40 }
            };
            
            Plotly.newPlot('timelineChart', [trace1, trace2], layout, {responsive: true});
        }
        
        function initializeRiskGauge() {
            const riskScore = dashboardData.risk_metrics.hndl_risk_score;
            
            const data = [{
                domain: { x: [0, 1], y: [0, 1] },
                value: riskScore,
                title: { text: "HNDL Risk Score" },
                type: "indicator",
                mode: "gauge+number",
                gauge: {
                    axis: { range: [null, 100] },
                    bar: { color: "#1f77b4" },
                    steps: [
                        { range: [0, 20], color: "#d4edda" },
                        { range: [20, 40], color: "#fff3cd" },
                        { range: [40, 60], color: "#ffeaa7" },
                        { range: [60, 80], color: "#fdcb6e" },
                        { range: [80, 100], color: "#e17055" }
                    ],
                    threshold: {
                        line: { color: "red", width: 4 },
                        thickness: 0.75,
                        value: 80
                    }
                }
            }];
            
            const layout = {
                margin: { t: 20, r: 20, b: 20, l: 20 }
            };
            
            Plotly.newPlot('riskGauge', data, layout, {responsive: true});
        }
        
        // Add interactivity
        document.addEventListener('DOMContentLoaded', function() {
            // Add click handlers for metric cards
            document.querySelectorAll('.metric-card').forEach(card => {
                card.addEventListener('click', function() {
                    card.style.transform = 'scale(0.98)';
                    setTimeout(() => {
                        card.style.transform = 'scale(1)';
                    }, 100);
                });
            });
            
            // Add hover effects for charts
            document.querySelectorAll('.chart-container').forEach(container => {
                container.addEventListener('mouseenter', function() {
                    this.style.boxShadow = '0 8px 16px rgba(0, 0, 0, 0.15)';
                });
                
                container.addEventListener('mouseleave', function() {
                    this.style.boxShadow = '0 4px 6px rgba(0, 0, 0, 0.1)';
                });
            });
        });
        """
    
    def _detect_language_from_file(self, file_path: str) -> str:
        """Detect programming language from file extension."""
        ext = Path(file_path).suffix.lower()
        ext_map = {
            '.py': 'python',
            '.java': 'java',
            '.go': 'go',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.c': 'c',
            '.cpp': 'cpp',
            '.h': 'c'
        }
        return ext_map.get(ext, 'unknown')
    
    def _get_risk_level(self, risk_score: int) -> str:
        """Convert numeric risk score to risk level."""
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 60:
            return "HIGH"
        elif risk_score >= 40:
            return "MEDIUM"
        elif risk_score >= 20:
            return "LOW"
        else:
            return "MINIMAL"
    
    def _estimate_completion_date(self, migration_hours: int) -> str:
        """Estimate completion date based on migration hours."""
        # Assuming 40 hours per week, 1 developer
        weeks_needed = max(1, migration_hours / 40)
        completion_date = datetime.now() + timedelta(weeks=weeks_needed)
        return completion_date.strftime('%Y-%m-%d')
    
    def _get_most_vulnerable_files(self, file_vulnerability_map: Dict) -> List[Dict]:
        """Get list of most vulnerable files."""
        file_list = []
        for file_path, vulnerabilities in file_vulnerability_map.items():
            file_list.append({
                'file_path': file_path,
                'vulnerability_count': len(vulnerabilities),
                'max_severity': max(v.severity.value for v in vulnerabilities)
            })
        
        # Sort by vulnerability count and severity
        file_list.sort(key=lambda x: (x['vulnerability_count'], x['max_severity']), reverse=True)
        return file_list
    
    def _calculate_vulnerability_density(self, file_vulnerability_map: Dict, scan_results: ScanResults) -> float:
        """Calculate vulnerability density (vulnerabilities per 1000 lines)."""
        if scan_results.total_lines == 0:
            return 0.0
        
        total_vulnerabilities = sum(len(vulns) for vulns in file_vulnerability_map.values())
        return (total_vulnerabilities / scan_results.total_lines) * 1000
    
    def _generate_timeline_data(self) -> Dict[str, List]:
        """Generate quantum threat timeline data."""
        return {
            'years': [2025, 2026, 2027, 2028, 2029, 2030, 2031, 2032, 2033, 2034, 2035],
            'threat_levels': [10, 15, 25, 35, 50, 65, 75, 85, 90, 95, 100],
            'migration_targets': [0, 20, 40, 60, 80, 100, 100, 100, 100, 100, 100]
        }
    
    def _calculate_progress_metrics(self, historical_data: List[Dict], current_results: ScanResults) -> Dict:
        """Calculate progress metrics from historical data."""
        if not historical_data:
            return {}
        
        # Get baseline (oldest data)
        baseline = historical_data[0]
        baseline_vulns = len(baseline.get('vulnerabilities', []))
        current_vulns = len(current_results.vulnerabilities)
        
        # Calculate progress
        vulnerabilities_fixed = max(0, baseline_vulns - current_vulns)
        progress_percentage = (vulnerabilities_fixed / baseline_vulns * 100) if baseline_vulns > 0 else 0
        
        return {
            'baseline_vulnerabilities': baseline_vulns,
            'current_vulnerabilities': current_vulns,
            'vulnerabilities_fixed': vulnerabilities_fixed,
            'progress_percentage': progress_percentage,
            'days_remaining': self._calculate_days_remaining(progress_percentage)
        }
    
    def _calculate_days_remaining(self, progress_percentage: float) -> int:
        """Calculate estimated days remaining for completion."""
        if progress_percentage >= 100:
            return 0
        
        # Assume current pace continues
        # This is a simplified calculation
        target_date = datetime(2027, 1, 1)  # Target completion by 2027
        days_to_target = (target_date - datetime.now()).days
        
        return max(0, days_to_target)
    
    def _generate_recommendations(self, risk_score: int, vulnerabilities: List[Vulnerability]) -> List[str]:
        """Generate contextual recommendations based on scan results."""
        recommendations = []
        
        if risk_score >= 80:
            recommendations.extend([
                "URGENT: Address critical vulnerabilities within 30 days",
                "Implement emergency crypto-agility framework",
                "Consider hybrid classical+PQC approach immediately",
                "Establish dedicated PQC migration team"
            ])
        elif risk_score >= 60:
            recommendations.extend([
                "Begin immediate planning for PQC migration",
                "Start pilot implementation in non-critical systems",
                "Establish regular security scanning pipeline",
                "Train development team on PQC implementations"
            ])
        else:
            recommendations.extend([
                "Develop comprehensive PQC migration timeline",
                "Begin evaluation of PQC libraries and tools",
                "Establish baseline cryptographic inventory",
                "Plan for future crypto-agility requirements"
            ])
        
        # Algorithm-specific recommendations
        algorithms = set(v.algorithm for v in vulnerabilities)
        if CryptoAlgorithm.RSA in algorithms:
            recommendations.append("Replace RSA with ML-KEM (Kyber) for key exchange")
        if CryptoAlgorithm.ECC in algorithms:
            recommendations.append("Replace ECC with ML-DSA (Dilithium) for signatures")
        
        return recommendations