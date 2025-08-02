#!/usr/bin/env python3
"""
Integration Helper Scripts for PQC Migration Audit project.

This module provides helper functions for integrating with external tools
and services for metrics collection, monitoring, and automation.
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


class GitHubIntegration:
    """Integration helper for GitHub API operations."""
    
    def __init__(self, token: Optional[str] = None, repo: Optional[str] = None):
        """Initialize GitHub integration."""
        self.token = token or os.environ.get('GITHUB_TOKEN')
        self.repo = repo or os.environ.get('GITHUB_REPOSITORY', 'danieleschmidt/pqc-migration-audit')
        self.base_url = 'https://api.github.com'
        
        if not self.token:
            raise ValueError("GitHub token required (set GITHUB_TOKEN environment variable)")
        
        self.headers = {
            'Authorization': f'token {self.token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'PQC-Migration-Audit-Bot/1.0'
        }
        
        self.logger = logging.getLogger(__name__)
    
    def get_repository_info(self) -> Dict[str, Any]:
        """Get repository information."""
        url = f"{self.base_url}/repos/{self.repo}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()
    
    def get_recent_commits(self, days: int = 30) -> List[Dict[str, Any]]:
        """Get recent commits from the repository."""
        since = (datetime.utcnow() - timedelta(days=days)).isoformat() + 'Z'
        url = f"{self.base_url}/repos/{self.repo}/commits"
        
        params = {
            'since': since,
            'per_page': 100
        }
        
        response = requests.get(url, headers=self.headers, params=params)
        response.raise_for_status()
        return response.json()
    
    def get_pull_requests(self, state: str = 'all') -> List[Dict[str, Any]]:
        """Get pull requests from the repository."""
        url = f"{self.base_url}/repos/{self.repo}/pulls"
        
        params = {
            'state': state,
            'per_page': 100
        }
        
        response = requests.get(url, headers=self.headers, params=params)
        response.raise_for_status()
        return response.json()
    
    def get_issues(self, state: str = 'all') -> List[Dict[str, Any]]:
        """Get issues from the repository."""
        url = f"{self.base_url}/repos/{self.repo}/issues"
        
        params = {
            'state': state,
            'per_page': 100
        }
        
        response = requests.get(url, headers=self.headers, params=params)
        response.raise_for_status()
        
        # Filter out pull requests (GitHub treats PRs as issues)
        return [issue for issue in response.json() if not issue.get('pull_request')]
    
    def get_releases(self) -> List[Dict[str, Any]]:
        """Get releases from the repository."""
        url = f"{self.base_url}/repos/{self.repo}/releases"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()
    
    def get_workflow_runs(self, workflow_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get GitHub Actions workflow runs."""
        if workflow_id:
            url = f"{self.base_url}/repos/{self.repo}/actions/workflows/{workflow_id}/runs"
        else:
            url = f"{self.base_url}/repos/{self.repo}/actions/runs"
        
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json().get('workflow_runs', [])
    
    def create_issue(self, title: str, body: str, labels: List[str] = None, assignees: List[str] = None) -> Dict[str, Any]:
        """Create a new issue."""
        url = f"{self.base_url}/repos/{self.repo}/issues"
        
        data = {
            'title': title,
            'body': body
        }
        
        if labels:
            data['labels'] = labels
        if assignees:
            data['assignees'] = assignees
        
        response = requests.post(url, headers=self.headers, json=data)
        response.raise_for_status()
        return response.json()
    
    def update_issue(self, issue_number: int, title: str = None, body: str = None, 
                    state: str = None, labels: List[str] = None) -> Dict[str, Any]:
        """Update an existing issue."""
        url = f"{self.base_url}/repos/{self.repo}/issues/{issue_number}"
        
        data = {}
        if title:
            data['title'] = title
        if body:
            data['body'] = body
        if state:
            data['state'] = state
        if labels:
            data['labels'] = labels
        
        response = requests.patch(url, headers=self.headers, json=data)
        response.raise_for_status()
        return response.json()
    
    def add_comment(self, issue_number: int, comment: str) -> Dict[str, Any]:
        """Add a comment to an issue or pull request."""
        url = f"{self.base_url}/repos/{self.repo}/issues/{issue_number}/comments"
        
        data = {'body': comment}
        
        response = requests.post(url, headers=self.headers, json=data)
        response.raise_for_status()
        return response.json()
    
    def get_repository_metrics(self) -> Dict[str, Any]:
        """Get comprehensive repository metrics."""
        repo_info = self.get_repository_info()
        commits = self.get_recent_commits(30)
        prs = self.get_pull_requests()
        issues = self.get_issues()
        releases = self.get_releases()
        
        # Calculate metrics
        open_prs = [pr for pr in prs if pr['state'] == 'open']
        closed_prs = [pr for pr in prs if pr['state'] == 'closed']
        merged_prs = [pr for pr in closed_prs if pr.get('merged_at')]
        
        open_issues = [issue for issue in issues if issue['state'] == 'open']
        closed_issues = [issue for issue in issues if issue['state'] == 'closed']
        
        return {
            'repository': {
                'name': repo_info['name'],
                'full_name': repo_info['full_name'],
                'description': repo_info['description'],
                'language': repo_info['language'],
                'created_at': repo_info['created_at'],
                'updated_at': repo_info['updated_at'],
                'stars': repo_info['stargazers_count'],
                'forks': repo_info['forks_count'],
                'watchers': repo_info['subscribers_count'],
                'size_kb': repo_info['size'],
                'open_issues_count': repo_info['open_issues_count']
            },
            'activity': {
                'commits_30_days': len(commits),
                'unique_contributors': len(set(c['author']['login'] for c in commits if c.get('author'))),
                'avg_commits_per_day': len(commits) / 30
            },
            'pull_requests': {
                'total': len(prs),
                'open': len(open_prs),
                'merged': len(merged_prs),
                'merge_rate': len(merged_prs) / len(prs) if prs else 0
            },
            'issues': {
                'total': len(issues),
                'open': len(open_issues),
                'closed': len(closed_issues),
                'resolution_rate': len(closed_issues) / len(issues) if issues else 0
            },
            'releases': {
                'total': len(releases),
                'latest': releases[0] if releases else None
            }
        }


class SlackIntegration:
    """Integration helper for Slack notifications."""
    
    def __init__(self, webhook_url: Optional[str] = None):
        """Initialize Slack integration."""
        self.webhook_url = webhook_url or os.environ.get('SLACK_WEBHOOK_URL')
        
        if not self.webhook_url:
            raise ValueError("Slack webhook URL required (set SLACK_WEBHOOK_URL environment variable)")
        
        self.logger = logging.getLogger(__name__)
    
    def send_message(self, text: str, channel: str = None, username: str = "PQC Audit Bot", 
                    emoji: str = ":robot_face:") -> bool:
        """Send a simple text message to Slack."""
        payload = {
            'text': text,
            'username': username,
            'icon_emoji': emoji
        }
        
        if channel:
            payload['channel'] = channel
        
        try:
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            return True
        except Exception as e:
            self.logger.error(f"Failed to send Slack message: {e}")
            return False
    
    def send_metrics_summary(self, metrics: Dict[str, Any], channel: str = "#metrics") -> bool:
        """Send a formatted metrics summary to Slack."""
        # Create formatted message
        text = "📊 *PQC Audit Metrics Summary*\n"
        
        if 'github' in metrics:
            github = metrics['github']
            text += f"\n*Repository Activity (30 days)*\n"
            text += f"• Commits: {github.get('commits', {}).get('count_30_days', 0)}\n"
            text += f"• Contributors: {github.get('commits', {}).get('contributors', 0)}\n"
            text += f"• Open PRs: {github.get('pull_requests', {}).get('open_count', 0)}\n"
            text += f"• Open Issues: {github.get('issues', {}).get('open_count', 0)}\n"
        
        if 'security' in metrics:
            security = metrics['security']
            text += f"\n*Security Status*\n"
            text += f"• Vulnerabilities: {security.get('vulnerability_scan', {}).get('count', 0)}\n"
            text += f"• Critical: {security.get('vulnerability_scan', {}).get('critical', 0)}\n"
        
        if 'code_quality' in metrics:
            quality = metrics['code_quality']
            text += f"\n*Code Quality*\n"
            text += f"• Coverage: {quality.get('coverage', {}).get('total_coverage', 0):.1f}%\n"
        
        return self.send_message(text, channel)
    
    def send_alert(self, title: str, message: str, severity: str = "warning", 
                  channel: str = "#alerts") -> bool:
        """Send an alert message with appropriate formatting."""
        emoji_map = {
            'critical': ':red_circle:',
            'warning': ':warning:',
            'info': ':information_source:',
            'success': ':white_check_mark:'
        }
        
        emoji = emoji_map.get(severity, ':exclamation:')
        
        payload = {
            'channel': channel,
            'username': 'PQC Audit Alert',
            'icon_emoji': emoji,
            'attachments': [{
                'color': {
                    'critical': 'danger',
                    'warning': 'warning',
                    'info': 'good',
                    'success': 'good'
                }.get(severity, 'warning'),
                'title': title,
                'text': message,
                'ts': int(time.time())
            }]
        }
        
        try:
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            return True
        except Exception as e:
            self.logger.error(f"Failed to send Slack alert: {e}")
            return False


class PrometheusIntegration:
    """Integration helper for Prometheus metrics."""
    
    def __init__(self, pushgateway_url: Optional[str] = None):
        """Initialize Prometheus integration."""
        self.pushgateway_url = pushgateway_url or os.environ.get('PROMETHEUS_PUSHGATEWAY_URL')
        self.logger = logging.getLogger(__name__)
    
    def push_metrics(self, job_name: str, metrics: Dict[str, float], 
                    instance: str = "localhost", labels: Dict[str, str] = None) -> bool:
        """Push metrics to Prometheus pushgateway."""
        if not self.pushgateway_url:
            self.logger.warning("Prometheus pushgateway URL not configured")
            return False
        
        # Format metrics for pushgateway
        metric_lines = []
        
        for metric_name, value in metrics.items():
            # Add labels if provided
            label_str = ""
            if labels:
                label_pairs = [f'{k}="{v}"' for k, v in labels.items()]
                label_str = "{" + ",".join(label_pairs) + "}"
            
            metric_lines.append(f"{metric_name}{label_str} {value}")
        
        metrics_data = "\n".join(metric_lines)
        
        # Push to gateway
        url = f"{self.pushgateway_url}/metrics/job/{job_name}/instance/{instance}"
        
        try:
            response = requests.post(
                url,
                data=metrics_data,
                headers={'Content-Type': 'text/plain'},
                timeout=10
            )
            response.raise_for_status()
            self.logger.info(f"Successfully pushed {len(metrics)} metrics to Prometheus")
            return True
        except Exception as e:
            self.logger.error(f"Failed to push metrics to Prometheus: {e}")
            return False
    
    def push_scan_metrics(self, scan_results: Dict[str, Any]) -> bool:
        """Push PQC scan-specific metrics to Prometheus."""
        metrics = {}
        
        # Security metrics
        if 'vulnerabilities' in scan_results:
            vulnerabilities = scan_results['vulnerabilities']
            metrics['pqc_vulnerabilities_total'] = len(vulnerabilities)
            
            # Count by severity
            for severity in ['critical', 'high', 'medium', 'low']:
                count = len([v for v in vulnerabilities if v.get('severity', '').lower() == severity])
                metrics[f'pqc_vulnerabilities_{severity}_total'] = count
        
        # Dependency metrics
        if 'dependencies' in scan_results:
            dependencies = scan_results['dependencies']
            metrics['pqc_dependencies_total'] = len(dependencies)
        
        if 'outdated' in scan_results:
            outdated = scan_results['outdated']
            metrics['pqc_outdated_dependencies_total'] = len(outdated)
            
            # Count by urgency
            for urgency in ['major', 'minor', 'patch']:
                count = len([p for p in outdated if p.get('urgency') == urgency])
                metrics[f'pqc_outdated_{urgency}_total'] = count
        
        # Quality metrics
        if 'metrics' in scan_results:
            scan_metrics = scan_results['metrics']
            
            if 'security' in scan_metrics:
                metrics['pqc_security_score'] = scan_metrics['security'].get('security_score', 0)
            
            if 'compliance' in scan_metrics:
                metrics['pqc_compliance_score'] = scan_metrics['compliance'].get('license_compliance_score', 0)
            
            if 'overall' in scan_metrics:
                metrics['pqc_health_score'] = scan_metrics['overall'].get('health_score', 0)
                metrics['pqc_risk_score'] = scan_metrics['overall'].get('risk_score', 0)
        
        return self.push_metrics(
            job_name='pqc_audit_scan',
            metrics=metrics,
            labels={'repository': 'pqc-migration-audit'}
        )


class EmailIntegration:
    """Integration helper for email notifications."""
    
    def __init__(self, smtp_server: str = None, smtp_port: int = 587, 
                 username: str = None, password: str = None):
        """Initialize email integration."""
        self.smtp_server = smtp_server or os.environ.get('SMTP_SERVER')
        self.smtp_port = smtp_port or int(os.environ.get('SMTP_PORT', '587'))
        self.username = username or os.environ.get('SMTP_USERNAME')
        self.password = password or os.environ.get('SMTP_PASSWORD')
        
        self.logger = logging.getLogger(__name__)
    
    def send_email(self, to_addresses: List[str], subject: str, body: str, 
                  from_address: str = None, html_body: str = None) -> bool:
        """Send an email notification."""
        if not all([self.smtp_server, self.username, self.password]):
            self.logger.warning("Email configuration incomplete, skipping email")
            return False
        
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = from_address or self.username
            msg['To'] = ', '.join(to_addresses)
            
            # Add text part
            text_part = MIMEText(body, 'plain')
            msg.attach(text_part)
            
            # Add HTML part if provided
            if html_body:
                html_part = MIMEText(html_body, 'html')
                msg.attach(html_part)
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)
            
            self.logger.info(f"Email sent successfully to {len(to_addresses)} recipients")
            return True
        
        except Exception as e:
            self.logger.error(f"Failed to send email: {e}")
            return False
    
    def send_metrics_report(self, to_addresses: List[str], metrics: Dict[str, Any]) -> bool:
        """Send a formatted metrics report via email."""
        subject = f"PQC Audit Metrics Report - {datetime.now().strftime('%Y-%m-%d')}"
        
        # Create text body
        body = f"""PQC Migration Audit - Metrics Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

"""
        
        if 'github' in metrics:
            github = metrics['github']
            body += f"""Repository Activity (30 days):
- Commits: {github.get('commits', {}).get('count_30_days', 0)}
- Contributors: {github.get('commits', {}).get('contributors', 0)}
- Open PRs: {github.get('pull_requests', {}).get('open_count', 0)}
- Open Issues: {github.get('issues', {}).get('open_count', 0)}

"""
        
        if 'security' in metrics:
            security = metrics['security']
            body += f"""Security Status:
- Vulnerabilities: {security.get('vulnerability_scan', {}).get('count', 0)}
- Critical: {security.get('vulnerability_scan', {}).get('critical', 0)}

"""
        
        # Create HTML body
        html_body = f"""
<html>
<body>
<h2>PQC Migration Audit - Metrics Report</h2>
<p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

<h3>Repository Activity (30 days)</h3>
<ul>
<li>Commits: {metrics.get('github', {}).get('commits', {}).get('count_30_days', 0)}</li>
<li>Contributors: {metrics.get('github', {}).get('commits', {}).get('contributors', 0)}</li>
<li>Open PRs: {metrics.get('github', {}).get('pull_requests', {}).get('open_count', 0)}</li>
<li>Open Issues: {metrics.get('github', {}).get('issues', {}).get('open_count', 0)}</li>
</ul>

<h3>Security Status</h3>
<ul>
<li>Vulnerabilities: {metrics.get('security', {}).get('vulnerability_scan', {}).get('count', 0)}</li>
<li>Critical: {metrics.get('security', {}).get('vulnerability_scan', {}).get('critical', 0)}</li>
</ul>
</body>
</html>
"""
        
        return self.send_email(to_addresses, subject, body, html_body=html_body)


class IntegrationOrchestrator:
    """Orchestrates all integrations for comprehensive automation."""
    
    def __init__(self):
        """Initialize integration orchestrator."""
        self.github = None
        self.slack = None
        self.prometheus = None
        self.email = None
        self.logger = logging.getLogger(__name__)
        
        # Initialize available integrations
        self._initialize_integrations()
    
    def _initialize_integrations(self):
        """Initialize all available integrations."""
        try:
            self.github = GitHubIntegration()
            self.logger.info("GitHub integration initialized")
        except Exception as e:
            self.logger.warning(f"GitHub integration not available: {e}")
        
        try:
            self.slack = SlackIntegration()
            self.logger.info("Slack integration initialized")
        except Exception as e:
            self.logger.warning(f"Slack integration not available: {e}")
        
        try:
            self.prometheus = PrometheusIntegration()
            self.logger.info("Prometheus integration initialized")
        except Exception as e:
            self.logger.warning(f"Prometheus integration not available: {e}")
        
        try:
            self.email = EmailIntegration()
            self.logger.info("Email integration initialized")
        except Exception as e:
            self.logger.warning(f"Email integration not available: {e}")
    
    def collect_and_distribute_metrics(self, metrics_data: Dict[str, Any]):
        """Collect metrics and distribute to all configured integrations."""
        self.logger.info("Distributing metrics to all integrations")
        
        # Send to Slack
        if self.slack:
            try:
                self.slack.send_metrics_summary(metrics_data)
                self.logger.info("Metrics sent to Slack")
            except Exception as e:
                self.logger.error(f"Failed to send metrics to Slack: {e}")
        
        # Send to Prometheus
        if self.prometheus:
            try:
                self.prometheus.push_scan_metrics(metrics_data)
                self.logger.info("Metrics pushed to Prometheus")
            except Exception as e:
                self.logger.error(f"Failed to push metrics to Prometheus: {e}")
        
        # Send email report (if configured)
        if self.email:
            try:
                email_recipients = os.environ.get('METRICS_EMAIL_RECIPIENTS', '').split(',')
                email_recipients = [email.strip() for email in email_recipients if email.strip()]
                
                if email_recipients:
                    self.email.send_metrics_report(email_recipients, metrics_data)
                    self.logger.info(f"Metrics report sent to {len(email_recipients)} recipients")
            except Exception as e:
                self.logger.error(f"Failed to send email report: {e}")
    
    def handle_security_alert(self, alert_data: Dict[str, Any]):
        """Handle security alerts across all integrations."""
        severity = alert_data.get('severity', 'warning')
        title = alert_data.get('title', 'Security Alert')
        message = alert_data.get('message', 'Security issue detected')
        
        self.logger.warning(f"Security alert: {title}")
        
        # Send Slack alert
        if self.slack:
            try:
                self.slack.send_alert(title, message, severity, "#security-alerts")
                self.logger.info("Security alert sent to Slack")
            except Exception as e:
                self.logger.error(f"Failed to send security alert to Slack: {e}")
        
        # Create GitHub issue for critical alerts
        if self.github and severity in ['critical', 'high']:
            try:
                issue_body = f"""## Security Alert

**Severity**: {severity.upper()}

{message}

**Generated by**: PQC Audit automation
**Timestamp**: {datetime.utcnow().isoformat()}Z

This issue was automatically created due to a security alert.
"""
                
                self.github.create_issue(
                    title=f"🚨 {title}",
                    body=issue_body,
                    labels=['security', 'automated', severity]
                )
                self.logger.info("Security issue created on GitHub")
            except Exception as e:
                self.logger.error(f"Failed to create GitHub security issue: {e}")
        
        # Send email for critical alerts
        if self.email and severity == 'critical':
            try:
                email_recipients = os.environ.get('SECURITY_EMAIL_RECIPIENTS', '').split(',')
                email_recipients = [email.strip() for email in email_recipients if email.strip()]
                
                if email_recipients:
                    self.email.send_email(
                        to_addresses=email_recipients,
                        subject=f"CRITICAL SECURITY ALERT: {title}",
                        body=f"Critical security alert detected:\n\n{message}\n\nImmediate action required."
                    )
                    self.logger.info("Critical security alert sent via email")
            except Exception as e:
                self.logger.error(f"Failed to send security alert email: {e}")
    
    def get_comprehensive_metrics(self) -> Dict[str, Any]:
        """Get comprehensive metrics from all available sources."""
        all_metrics = {
            'collection_timestamp': datetime.utcnow().isoformat(),
            'integrations_available': []
        }
        
        # GitHub metrics
        if self.github:
            try:
                github_metrics = self.github.get_repository_metrics()
                all_metrics['github'] = github_metrics
                all_metrics['integrations_available'].append('github')
                self.logger.info("GitHub metrics collected")
            except Exception as e:
                self.logger.error(f"Failed to collect GitHub metrics: {e}")
        
        return all_metrics


def main():
    """Main entry point for integration helpers."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Integration helper utilities')
    parser.add_argument('command', choices=['test-github', 'test-slack', 'test-prometheus', 'test-email', 'collect-metrics'],
                       help='Command to execute')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        if args.command == 'test-github':
            github = GitHubIntegration()
            metrics = github.get_repository_metrics()
            print(json.dumps(metrics, indent=2))
        
        elif args.command == 'test-slack':
            slack = SlackIntegration()
            success = slack.send_message("🧪 Test message from PQC Audit integration helpers")
            print(f"Slack test: {'SUCCESS' if success else 'FAILED'}")
        
        elif args.command == 'test-prometheus':
            prometheus = PrometheusIntegration()
            test_metrics = {
                'pqc_test_metric': 1.0,
                'pqc_integration_test': 42.0
            }
            success = prometheus.push_metrics('test_job', test_metrics)
            print(f"Prometheus test: {'SUCCESS' if success else 'FAILED'}")
        
        elif args.command == 'test-email':
            email = EmailIntegration()
            test_recipients = os.environ.get('TEST_EMAIL_RECIPIENTS', '').split(',')
            test_recipients = [email.strip() for email in test_recipients if email.strip()]
            
            if test_recipients:
                success = email.send_email(
                    to_addresses=test_recipients,
                    subject="PQC Audit Integration Test",
                    body="This is a test email from PQC Audit integration helpers."
                )
                print(f"Email test: {'SUCCESS' if success else 'FAILED'}")
            else:
                print("Email test: SKIPPED (no TEST_EMAIL_RECIPIENTS configured)")
        
        elif args.command == 'collect-metrics':
            orchestrator = IntegrationOrchestrator()
            metrics = orchestrator.get_comprehensive_metrics()
            print(json.dumps(metrics, indent=2))
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()