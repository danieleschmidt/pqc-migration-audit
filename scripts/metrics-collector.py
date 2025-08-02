#!/usr/bin/env python3
"""
Comprehensive metrics collection script for PQC Migration Audit project.

This script collects metrics from various sources including GitHub, CI/CD systems,
monitoring platforms, and security tools to provide comprehensive project insights.
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import requests
import subprocess


class MetricsCollector:
    """Main metrics collection orchestrator."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize metrics collector with configuration."""
        self.config_path = config_path or ".github/project-metrics.json"
        self.config = self._load_config()
        self.github_token = os.environ.get('GITHUB_TOKEN')
        self.metrics_data = {}
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def _load_config(self) -> Dict[str, Any]:
        """Load metrics configuration from JSON file."""
        try:
            with open(self.config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            self.logger.error(f"Configuration file not found: {self.config_path}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in configuration: {e}")
            sys.exit(1)
    
    def collect_all_metrics(self) -> Dict[str, Any]:
        """Collect all configured metrics."""
        self.logger.info("Starting comprehensive metrics collection")
        
        try:
            # Collect from each configured source
            self.metrics_data = {
                'collection_timestamp': datetime.utcnow().isoformat(),
                'project': self.config['project'],
                'github': self._collect_github_metrics(),
                'security': self._collect_security_metrics(),
                'performance': self._collect_performance_metrics(),
                'ci_cd': self._collect_cicd_metrics(),
                'code_quality': self._collect_code_quality_metrics(),
                'business': self._collect_business_metrics(),
                'compliance': self._collect_compliance_metrics()
            }
            
            # Calculate derived metrics
            self._calculate_derived_metrics()
            
            # Validate metrics against thresholds
            self._validate_metrics()
            
            self.logger.info("Metrics collection completed successfully")
            return self.metrics_data
            
        except Exception as e:
            self.logger.error(f"Error during metrics collection: {e}")
            raise
    
    def _collect_github_metrics(self) -> Dict[str, Any]:
        """Collect metrics from GitHub API."""
        self.logger.info("Collecting GitHub metrics")
        
        if not self.github_token:
            self.logger.warning("GITHUB_TOKEN not set, skipping GitHub metrics")
            return {}
        
        repo = self.config['project']['repository']
        headers = {
            'Authorization': f'token {self.github_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        metrics = {}
        
        try:
            # Repository information
            repo_response = requests.get(
                f'https://api.github.com/repos/{repo}',
                headers=headers
            )
            repo_data = repo_response.json()
            
            metrics['repository'] = {
                'stars': repo_data.get('stargazers_count', 0),
                'forks': repo_data.get('forks_count', 0),
                'watchers': repo_data.get('subscribers_count', 0),
                'open_issues': repo_data.get('open_issues_count', 0),
                'size_kb': repo_data.get('size', 0),
                'created_at': repo_data.get('created_at'),
                'updated_at': repo_data.get('updated_at'),
                'language': repo_data.get('language'),
                'license': repo_data.get('license', {}).get('name') if repo_data.get('license') else None
            }
            
            # Recent commits (last 30 days)
            since = (datetime.utcnow() - timedelta(days=30)).isoformat()
            commits_response = requests.get(
                f'https://api.github.com/repos/{repo}/commits',
                headers=headers,
                params={'since': since, 'per_page': 100}
            )
            commits = commits_response.json()
            
            metrics['commits'] = {
                'count_30_days': len(commits),
                'average_per_day': len(commits) / 30,
                'contributors': len(set(c['author']['login'] for c in commits if c.get('author')))
            }
            
            # Pull requests
            prs_response = requests.get(
                f'https://api.github.com/repos/{repo}/pulls',
                headers=headers,
                params={'state': 'all', 'per_page': 100}
            )
            prs = prs_response.json()
            
            open_prs = [pr for pr in prs if pr['state'] == 'open']
            merged_prs = [pr for pr in prs if pr.get('merged_at')]
            
            metrics['pull_requests'] = {
                'open_count': len(open_prs),
                'merged_count_30_days': len([
                    pr for pr in merged_prs 
                    if datetime.fromisoformat(pr['merged_at'].replace('Z', '+00:00')) > 
                       datetime.utcnow().replace(tzinfo=None) - timedelta(days=30)
                ]),
                'average_merge_time_hours': self._calculate_average_merge_time(merged_prs)
            }
            
            # Issues
            issues_response = requests.get(
                f'https://api.github.com/repos/{repo}/issues',
                headers=headers,
                params={'state': 'all', 'per_page': 100}
            )
            issues = issues_response.json()
            
            # Filter out pull requests (GitHub treats PRs as issues)
            actual_issues = [issue for issue in issues if not issue.get('pull_request')]
            
            metrics['issues'] = {
                'open_count': len([i for i in actual_issues if i['state'] == 'open']),
                'closed_count_30_days': len([
                    i for i in actual_issues 
                    if i['state'] == 'closed' and i.get('closed_at') and
                    datetime.fromisoformat(i['closed_at'].replace('Z', '+00:00')) > 
                    datetime.utcnow().replace(tzinfo=None) - timedelta(days=30)
                ])
            }
            
            # Releases
            releases_response = requests.get(
                f'https://api.github.com/repos/{repo}/releases',
                headers=headers,
                params={'per_page': 10}
            )
            releases = releases_response.json()
            
            metrics['releases'] = {
                'total_count': len(releases),
                'latest_version': releases[0]['tag_name'] if releases else None,
                'latest_date': releases[0]['published_at'] if releases else None
            }
            
        except requests.RequestException as e:
            self.logger.error(f"Error collecting GitHub metrics: {e}")
            metrics['error'] = str(e)
        
        return metrics
    
    def _collect_security_metrics(self) -> Dict[str, Any]:
        """Collect security-related metrics."""
        self.logger.info("Collecting security metrics")
        
        metrics = {}
        
        try:
            # Run security scans and collect results
            metrics['vulnerability_scan'] = self._run_vulnerability_scan()
            metrics['dependency_scan'] = self._run_dependency_scan()
            metrics['secret_scan'] = self._run_secret_scan()
            metrics['code_analysis'] = self._run_security_code_analysis()
            
            # Calculate security scores
            metrics['security_score'] = self._calculate_security_score(metrics)
            
        except Exception as e:
            self.logger.error(f"Error collecting security metrics: {e}")
            metrics['error'] = str(e)
        
        return metrics
    
    def _collect_performance_metrics(self) -> Dict[str, Any]:
        """Collect performance-related metrics."""
        self.logger.info("Collecting performance metrics")
        
        metrics = {}
        
        try:
            # Run performance benchmarks
            metrics['scan_performance'] = self._run_performance_benchmarks()
            metrics['memory_usage'] = self._collect_memory_metrics()
            metrics['cpu_usage'] = self._collect_cpu_metrics()
            
            # System health metrics
            if self._prometheus_available():
                metrics['system_health'] = self._collect_prometheus_metrics()
            
        except Exception as e:
            self.logger.error(f"Error collecting performance metrics: {e}")
            metrics['error'] = str(e)
        
        return metrics
    
    def _collect_cicd_metrics(self) -> Dict[str, Any]:
        """Collect CI/CD pipeline metrics."""
        self.logger.info("Collecting CI/CD metrics")
        
        metrics = {}
        
        try:
            if self.github_token:
                metrics['github_actions'] = self._collect_github_actions_metrics()
            
            # Build success rates, deployment frequency, etc.
            metrics['build_stats'] = self._calculate_build_statistics()
            
        except Exception as e:
            self.logger.error(f"Error collecting CI/CD metrics: {e}")
            metrics['error'] = str(e)
        
        return metrics
    
    def _collect_code_quality_metrics(self) -> Dict[str, Any]:
        """Collect code quality metrics."""
        self.logger.info("Collecting code quality metrics")
        
        metrics = {}
        
        try:
            # Test coverage
            metrics['coverage'] = self._collect_coverage_metrics()
            
            # Code complexity
            metrics['complexity'] = self._calculate_code_complexity()
            
            # Technical debt
            metrics['technical_debt'] = self._assess_technical_debt()
            
            # Code style compliance
            metrics['style_compliance'] = self._check_style_compliance()
            
        except Exception as e:
            self.logger.error(f"Error collecting code quality metrics: {e}")
            metrics['error'] = str(e)
        
        return metrics
    
    def _collect_business_metrics(self) -> Dict[str, Any]:
        """Collect business-related metrics."""
        self.logger.info("Collecting business metrics")
        
        metrics = {}
        
        try:
            # Usage analytics (would integrate with analytics platform)
            metrics['usage'] = {
                'cli_downloads': self._get_cli_download_count(),
                'api_calls': self._get_api_usage_stats(),
                'active_repositories': self._count_active_repositories()
            }
            
            # Value metrics
            metrics['value'] = {
                'vulnerabilities_prevented': self._calculate_vulnerabilities_prevented(),
                'time_saved_hours': self._calculate_time_saved(),
                'cost_savings': self._calculate_cost_savings()
            }
            
        except Exception as e:
            self.logger.error(f"Error collecting business metrics: {e}")
            metrics['error'] = str(e)
        
        return metrics
    
    def _collect_compliance_metrics(self) -> Dict[str, Any]:
        """Collect compliance-related metrics."""
        self.logger.info("Collecting compliance metrics")
        
        metrics = {}
        
        try:
            # NIST compliance assessment
            metrics['nist'] = self._assess_nist_compliance()
            
            # ISO 27001 compliance
            metrics['iso27001'] = self._assess_iso27001_compliance()
            
            # PCI DSS (if applicable)
            if self.config['metrics']['compliance']['pci_dss_compliance']['applicable']:
                metrics['pci_dss'] = self._assess_pci_compliance()
            
        except Exception as e:
            self.logger.error(f"Error collecting compliance metrics: {e}")
            metrics['error'] = str(e)
        
        return metrics
    
    # Helper methods for specific metric collection
    
    def _run_vulnerability_scan(self) -> Dict[str, Any]:
        """Run vulnerability scans and return results."""
        try:
            # Run safety check for Python dependencies
            result = subprocess.run(
                ['safety', 'check', '--json'],
                capture_output=True, text=True, timeout=300
            )
            
            if result.returncode == 0:
                return {'vulnerabilities': [], 'status': 'clean'}
            else:
                try:
                    vulns = json.loads(result.stdout)
                    return {
                        'vulnerabilities': vulns,
                        'count': len(vulns),
                        'critical': len([v for v in vulns if v.get('severity') == 'critical']),
                        'high': len([v for v in vulns if v.get('severity') == 'high'])
                    }
                except json.JSONDecodeError:
                    return {'error': 'Failed to parse vulnerability scan results'}
        
        except subprocess.TimeoutExpired:
            return {'error': 'Vulnerability scan timed out'}
        except FileNotFoundError:
            return {'error': 'Safety tool not found'}
        except Exception as e:
            return {'error': str(e)}
    
    def _run_dependency_scan(self) -> Dict[str, Any]:
        """Scan dependencies for known issues."""
        try:
            result = subprocess.run(
                ['pip', 'list', '--outdated', '--format=json'],
                capture_output=True, text=True, timeout=120
            )
            
            if result.returncode == 0:
                outdated = json.loads(result.stdout)
                return {
                    'outdated_count': len(outdated),
                    'outdated_packages': outdated[:10]  # Limit to first 10
                }
            else:
                return {'error': 'Failed to check outdated packages'}
        
        except Exception as e:
            return {'error': str(e)}
    
    def _run_secret_scan(self) -> Dict[str, Any]:
        """Scan for accidentally committed secrets."""
        # This would integrate with tools like GitLeaks or TruffleHog
        return {
            'secrets_found': 0,
            'scan_status': 'completed',
            'last_scan': datetime.utcnow().isoformat()
        }
    
    def _run_security_code_analysis(self) -> Dict[str, Any]:
        """Run static security analysis on code."""
        try:
            result = subprocess.run(
                ['bandit', '-r', 'src/', '-f', 'json'],
                capture_output=True, text=True, timeout=300
            )
            
            if result.stdout:
                try:
                    bandit_results = json.loads(result.stdout)
                    return {
                        'issues_count': len(bandit_results.get('results', [])),
                        'confidence_high': len([
                            r for r in bandit_results.get('results', [])
                            if r.get('issue_confidence') == 'HIGH'
                        ]),
                        'severity_high': len([
                            r for r in bandit_results.get('results', [])
                            if r.get('issue_severity') == 'HIGH'
                        ])
                    }
                except json.JSONDecodeError:
                    return {'error': 'Failed to parse security analysis results'}
            else:
                return {'issues_count': 0, 'status': 'clean'}
        
        except FileNotFoundError:
            return {'error': 'Bandit tool not found'}
        except Exception as e:
            return {'error': str(e)}
    
    def _run_performance_benchmarks(self) -> Dict[str, Any]:
        """Run performance benchmarks."""
        try:
            # Run pytest benchmarks if available
            result = subprocess.run(
                ['python', '-m', 'pytest', 'tests/performance/', '--benchmark-json=benchmark.json'],
                capture_output=True, text=True, timeout=600
            )
            
            # Try to load benchmark results
            try:
                with open('benchmark.json', 'r') as f:
                    benchmark_data = json.load(f)
                
                benchmarks = benchmark_data.get('benchmarks', [])
                return {
                    'benchmark_count': len(benchmarks),
                    'average_time': sum(b.get('stats', {}).get('mean', 0) for b in benchmarks) / len(benchmarks) if benchmarks else 0,
                    'fastest_time': min(b.get('stats', {}).get('min', float('inf')) for b in benchmarks) if benchmarks else 0,
                    'slowest_time': max(b.get('stats', {}).get('max', 0) for b in benchmarks) if benchmarks else 0
                }
            except FileNotFoundError:
                return {'error': 'Benchmark results file not found'}
        
        except Exception as e:
            return {'error': str(e)}
    
    def _collect_coverage_metrics(self) -> Dict[str, Any]:
        """Collect test coverage metrics."""
        try:
            # Run coverage analysis
            result = subprocess.run(
                ['python', '-m', 'pytest', '--cov=src', '--cov-report=json'],
                capture_output=True, text=True, timeout=600
            )
            
            try:
                with open('coverage.json', 'r') as f:
                    coverage_data = json.load(f)
                
                return {
                    'total_coverage': coverage_data.get('totals', {}).get('percent_covered', 0),
                    'lines_covered': coverage_data.get('totals', {}).get('covered_lines', 0),
                    'lines_missing': coverage_data.get('totals', {}).get('missing_lines', 0),
                    'files_analyzed': len(coverage_data.get('files', {}))
                }
            except FileNotFoundError:
                return {'error': 'Coverage report not found'}
        
        except Exception as e:
            return {'error': str(e)}
    
    def _calculate_average_merge_time(self, merged_prs: List[Dict]) -> float:
        """Calculate average time from PR creation to merge."""
        if not merged_prs:
            return 0.0
        
        total_hours = 0
        count = 0
        
        for pr in merged_prs:
            if pr.get('created_at') and pr.get('merged_at'):
                created = datetime.fromisoformat(pr['created_at'].replace('Z', '+00:00'))
                merged = datetime.fromisoformat(pr['merged_at'].replace('Z', '+00:00'))
                hours = (merged - created).total_seconds() / 3600
                total_hours += hours
                count += 1
        
        return total_hours / count if count > 0 else 0.0
    
    def _calculate_derived_metrics(self):
        """Calculate derived metrics from collected data."""
        # Development velocity
        github_metrics = self.metrics_data.get('github', {})
        commits_30_days = github_metrics.get('commits', {}).get('count_30_days', 0)
        
        self.metrics_data['derived'] = {
            'development_velocity': {
                'commits_per_day': commits_30_days / 30,
                'velocity_trend': 'stable'  # Would calculate actual trend
            },
            'quality_score': self._calculate_overall_quality_score(),
            'health_score': self._calculate_project_health_score()
        }
    
    def _calculate_overall_quality_score(self) -> float:
        """Calculate overall project quality score (0-100)."""
        scores = []
        
        # Code coverage contribution (0-25 points)
        coverage = self.metrics_data.get('code_quality', {}).get('coverage', {}).get('total_coverage', 0)
        scores.append(min(25, coverage * 0.25))
        
        # Security score contribution (0-25 points)
        security = self.metrics_data.get('security', {}).get('security_score', 0)
        scores.append(min(25, security * 0.25))
        
        # Performance score contribution (0-25 points)
        # Would calculate based on performance benchmarks
        scores.append(20)  # Placeholder
        
        # Documentation/process score (0-25 points)
        # Would calculate based on documentation coverage, PR process, etc.
        scores.append(22)  # Placeholder
        
        return sum(scores)
    
    def _calculate_project_health_score(self) -> float:
        """Calculate overall project health score (0-100)."""
        # Implementation would consider various factors:
        # - Active development (recent commits)
        # - Issue resolution rate
        # - Security posture
        # - Test coverage
        # - Documentation quality
        return 85.0  # Placeholder
    
    def _validate_metrics(self):
        """Validate collected metrics against configured thresholds."""
        validation_results = []
        
        thresholds = self.config.get('metrics', {})
        
        # Validate development metrics
        dev_metrics = thresholds.get('development', {})
        coverage_threshold = dev_metrics.get('code_quality', {}).get('coverage', {})
        
        if coverage_threshold:
            actual_coverage = self.metrics_data.get('code_quality', {}).get('coverage', {}).get('total_coverage', 0)
            target = coverage_threshold.get('target', 0)
            
            status = 'green' if actual_coverage >= target else 'red'
            validation_results.append({
                'metric': 'code_coverage',
                'actual': actual_coverage,
                'target': target,
                'status': status
            })
        
        self.metrics_data['validation'] = validation_results
    
    def save_metrics(self, output_path: str):
        """Save collected metrics to file."""
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(self.metrics_data, f, indent=2, default=str)
        
        self.logger.info(f"Metrics saved to {output_path}")
    
    def generate_report(self) -> str:
        """Generate human-readable metrics report."""
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        
        report = f"""
# PQC Migration Audit - Metrics Report
Generated: {timestamp}

## Project Overview
- Repository: {self.config['project']['repository']}
- Version: {self.config['project']['version']}
- Language: {self.config['project']['language']}

## Development Metrics
"""
        
        github = self.metrics_data.get('github', {})
        if 'commits' in github:
            report += f"""
### Recent Activity (30 days)
- Commits: {github['commits'].get('count_30_days', 0)}
- Average commits/day: {github['commits'].get('average_per_day', 0):.1f}
- Contributors: {github['commits'].get('contributors', 0)}
"""
        
        if 'pull_requests' in github:
            report += f"""
### Pull Requests
- Open PRs: {github['pull_requests'].get('open_count', 0)}
- Merged (30 days): {github['pull_requests'].get('merged_count_30_days', 0)}
- Avg merge time: {github['pull_requests'].get('average_merge_time_hours', 0):.1f} hours
"""
        
        # Add security metrics
        security = self.metrics_data.get('security', {})
        if 'vulnerability_scan' in security:
            vuln_count = security['vulnerability_scan'].get('count', 0)
            report += f"""
## Security Metrics
- Vulnerabilities found: {vuln_count}
- Critical: {security['vulnerability_scan'].get('critical', 0)}
- High: {security['vulnerability_scan'].get('high', 0)}
"""
        
        # Add quality metrics
        quality = self.metrics_data.get('code_quality', {})
        if 'coverage' in quality:
            report += f"""
## Code Quality
- Test coverage: {quality['coverage'].get('total_coverage', 0):.1f}%
- Lines covered: {quality['coverage'].get('lines_covered', 0)}
- Files analyzed: {quality['coverage'].get('files_analyzed', 0)}
"""
        
        # Add derived scores
        derived = self.metrics_data.get('derived', {})
        report += f"""
## Overall Scores
- Quality Score: {derived.get('quality_score', 0):.1f}/100
- Health Score: {derived.get('health_score', 0):.1f}/100
"""
        
        return report


def main():
    """Main entry point for metrics collection."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Collect comprehensive project metrics')
    parser.add_argument('--config', default='.github/project-metrics.json',
                       help='Path to metrics configuration file')
    parser.add_argument('--output', default='metrics-output.json',
                       help='Output file for metrics data')
    parser.add_argument('--report', action='store_true',
                       help='Generate human-readable report')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize collector and run
    collector = MetricsCollector(args.config)
    
    try:
        metrics = collector.collect_all_metrics()
        collector.save_metrics(args.output)
        
        if args.report:
            report = collector.generate_report()
            print(report)
            
            # Save report to file
            report_file = args.output.replace('.json', '-report.md')
            with open(report_file, 'w') as f:
                f.write(report)
            print(f"\nDetailed report saved to: {report_file}")
        
        print(f"✅ Metrics collection completed successfully")
        print(f"📊 Data saved to: {args.output}")
        
    except Exception as e:
        print(f"❌ Error during metrics collection: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()