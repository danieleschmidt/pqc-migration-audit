#!/usr/bin/env python3
"""
Repository Configuration Script for PQC Migration Audit project.

This script automates the final repository configuration and validation
to ensure all SDLC components are properly integrated and functional.
"""

import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any


class RepositoryConfigurator:
    """Automates repository configuration and validation."""
    
    def __init__(self, repo_root: str = "."):
        """Initialize repository configurator."""
        self.repo_root = Path(repo_root).resolve()
        self.logger = logging.getLogger(__name__)
        
        # Configuration tracking
        self.config_status = {
            'timestamp': datetime.utcnow().isoformat(),
            'checks': {},
            'configurations': {},
            'validations': {},
            'recommendations': []
        }
    
    def configure_repository(self) -> Dict[str, Any]:
        """Perform complete repository configuration."""
        self.logger.info("Starting repository configuration")
        
        try:
            # Validate repository structure
            self._validate_repository_structure()
            
            # Configure development environment
            self._configure_development_environment()
            
            # Setup automation scripts
            self._setup_automation()
            
            # Configure monitoring and metrics
            self._configure_monitoring()
            
            # Validate integrations
            self._validate_integrations()
            
            # Generate configuration report
            self._generate_configuration_report()
            
            self.logger.info("Repository configuration completed successfully")
            return self.config_status
            
        except Exception as e:
            self.logger.error(f"Error during repository configuration: {e}")
            raise
    
    def _validate_repository_structure(self):
        """Validate that all required files and directories exist."""
        self.logger.info("Validating repository structure")
        
        required_files = [
            'README.md',
            'LICENSE',
            'CONTRIBUTING.md',
            'CODE_OF_CONDUCT.md',
            'SECURITY.md',
            'CHANGELOG.md',
            'pyproject.toml',
            'requirements.txt',
            'Dockerfile',
            'docker-compose.yml',
            'Makefile',
            '.gitignore',
            '.editorconfig'
        ]
        
        required_directories = [
            'src',
            'tests',
            'docs',
            'scripts',
            'monitoring',
            '.github'
        ]
        
        # Check required files
        missing_files = []
        for file_path in required_files:
            if not (self.repo_root / file_path).exists():
                missing_files.append(file_path)
        
        # Check required directories
        missing_dirs = []
        for dir_path in required_directories:
            if not (self.repo_root / dir_path).is_dir():
                missing_dirs.append(dir_path)
        
        self.config_status['checks']['repository_structure'] = {
            'required_files': len(required_files),
            'missing_files': missing_files,
            'required_directories': len(required_directories),
            'missing_directories': missing_dirs,
            'status': 'passed' if not missing_files and not missing_dirs else 'failed'
        }
        
        if missing_files or missing_dirs:
            self.logger.warning(f"Missing files: {missing_files}")
            self.logger.warning(f"Missing directories: {missing_dirs}")
        else:
            self.logger.info("Repository structure validation passed")
    
    def _configure_development_environment(self):
        """Configure development environment settings."""
        self.logger.info("Configuring development environment")
        
        configurations = {}
        
        # Configure pre-commit hooks
        if (self.repo_root / '.pre-commit-config.yaml').exists():
            try:
                result = subprocess.run(
                    ['pre-commit', 'install'],
                    cwd=self.repo_root,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                configurations['pre_commit'] = {
                    'installed': result.returncode == 0,
                    'output': result.stdout if result.returncode == 0 else result.stderr
                }
            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                configurations['pre_commit'] = {
                    'installed': False,
                    'error': str(e)
                }
        
        # Configure Python environment
        try:
            # Check if virtual environment should be created
            if not os.environ.get('VIRTUAL_ENV'):
                self.logger.info("Creating Python virtual environment")
                subprocess.run(
                    [sys.executable, '-m', 'venv', 'venv'],
                    cwd=self.repo_root,
                    check=True,
                    timeout=120
                )
                configurations['virtual_env'] = {'created': True}
            else:
                configurations['virtual_env'] = {'existing': True}
        
        except Exception as e:
            configurations['virtual_env'] = {'error': str(e)}
        
        # Install development dependencies
        try:
            result = subprocess.run(
                [sys.executable, '-m', 'pip', 'install', '-e', '.[dev,test]'],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=300
            )
            configurations['dependencies'] = {
                'installed': result.returncode == 0,
                'output': result.stdout if result.returncode == 0 else result.stderr
            }
        except Exception as e:
            configurations['dependencies'] = {'error': str(e)}
        
        self.config_status['configurations']['development'] = configurations
    
    def _setup_automation(self):
        """Setup automation scripts and cron jobs."""
        self.logger.info("Setting up automation")
        
        automation_configs = {}
        
        # Make scripts executable
        script_files = [
            'scripts/metrics-collector.py',
            'scripts/automation/repository-maintenance.sh',
            'scripts/automation/dependency-scanner.py',
            'scripts/automation/integration-helpers.py'
        ]
        
        for script_path in script_files:
            script_file = self.repo_root / script_path
            if script_file.exists():
                try:
                    script_file.chmod(0o755)
                    automation_configs[script_path] = {'executable': True}
                except Exception as e:
                    automation_configs[script_path] = {'error': str(e)}
            else:
                automation_configs[script_path] = {'missing': True}
        
        # Setup log directories
        log_dirs = ['logs', 'backups']
        for log_dir in log_dirs:
            log_path = self.repo_root / log_dir
            try:
                log_path.mkdir(exist_ok=True)
                automation_configs[f'{log_dir}_directory'] = {'created': True}
            except Exception as e:
                automation_configs[f'{log_dir}_directory'] = {'error': str(e)}
        
        # Test automation scripts
        test_results = {}
        
        # Test metrics collector
        try:
            result = subprocess.run(
                [sys.executable, 'scripts/metrics-collector.py', '--help'],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=30
            )
            test_results['metrics_collector'] = {'working': result.returncode == 0}
        except Exception as e:
            test_results['metrics_collector'] = {'error': str(e)}
        
        # Test dependency scanner
        try:
            result = subprocess.run(
                [sys.executable, 'scripts/automation/dependency-scanner.py', '--help'],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=30
            )
            test_results['dependency_scanner'] = {'working': result.returncode == 0}
        except Exception as e:
            test_results['dependency_scanner'] = {'error': str(e)}
        
        automation_configs['test_results'] = test_results
        self.config_status['configurations']['automation'] = automation_configs
    
    def _configure_monitoring(self):
        """Configure monitoring and observability."""
        self.logger.info("Configuring monitoring")
        
        monitoring_configs = {}
        
        # Validate Prometheus configuration
        prometheus_config = self.repo_root / 'monitoring' / 'prometheus-config.yml'
        if prometheus_config.exists():
            try:
                import yaml
                with open(prometheus_config, 'r') as f:
                    config_data = yaml.safe_load(f)
                monitoring_configs['prometheus'] = {
                    'config_valid': True,
                    'scrape_configs': len(config_data.get('scrape_configs', []))
                }
            except Exception as e:
                monitoring_configs['prometheus'] = {'error': str(e)}
        
        # Validate recording rules
        recording_rules = self.repo_root / 'monitoring' / 'recording-rules.yml'
        if recording_rules.exists():
            try:
                import yaml
                with open(recording_rules, 'r') as f:
                    rules_data = yaml.safe_load(f)
                monitoring_configs['recording_rules'] = {
                    'valid': True,
                    'groups': len(rules_data.get('groups', []))
                }
            except Exception as e:
                monitoring_configs['recording_rules'] = {'error': str(e)}
        
        # Check project metrics configuration
        metrics_config = self.repo_root / '.github' / 'project-metrics.json'
        if metrics_config.exists():
            try:
                with open(metrics_config, 'r') as f:
                    metrics_data = json.load(f)
                monitoring_configs['project_metrics'] = {
                    'valid': True,
                    'metric_categories': len(metrics_data.get('metrics', {}))
                }
            except Exception as e:
                monitoring_configs['project_metrics'] = {'error': str(e)}
        
        self.config_status['configurations']['monitoring'] = monitoring_configs
    
    def _validate_integrations(self):
        """Validate integration configurations."""
        self.logger.info("Validating integrations")
        
        validations = {}
        
        # GitHub integration
        github_token = os.environ.get('GITHUB_TOKEN')
        if github_token:
            try:
                from scripts.automation.integration_helpers import GitHubIntegration
                github = GitHubIntegration()
                repo_info = github.get_repository_info()
                validations['github'] = {
                    'configured': True,
                    'repository': repo_info.get('full_name', 'unknown')
                }
            except Exception as e:
                validations['github'] = {'error': str(e)}
        else:
            validations['github'] = {'token_missing': True}
        
        # Slack integration
        slack_webhook = os.environ.get('SLACK_WEBHOOK_URL')
        if slack_webhook:
            try:
                from scripts.automation.integration_helpers import SlackIntegration
                slack = SlackIntegration()
                # Don't actually send a test message during configuration
                validations['slack'] = {'configured': True}
            except Exception as e:
                validations['slack'] = {'error': str(e)}
        else:
            validations['slack'] = {'webhook_missing': True}
        
        # Prometheus integration
        prometheus_url = os.environ.get('PROMETHEUS_PUSHGATEWAY_URL')
        if prometheus_url:
            validations['prometheus'] = {'configured': True, 'url': prometheus_url}
        else:
            validations['prometheus'] = {'url_missing': True}
        
        # Email integration
        smtp_server = os.environ.get('SMTP_SERVER')
        if smtp_server:
            validations['email'] = {'configured': True, 'server': smtp_server}
        else:
            validations['email'] = {'server_missing': True}
        
        self.config_status['validations']['integrations'] = validations
    
    def _run_quality_checks(self):
        """Run code quality checks."""
        self.logger.info("Running quality checks")
        
        quality_results = {}
        
        # Run linting
        try:
            result = subprocess.run(
                ['flake8', 'src/', 'tests/', '--max-line-length=120'],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=120
            )
            quality_results['linting'] = {
                'passed': result.returncode == 0,
                'issues': len(result.stdout.splitlines()) if result.returncode != 0 else 0
            }
        except Exception as e:
            quality_results['linting'] = {'error': str(e)}
        
        # Run type checking
        try:
            result = subprocess.run(
                ['mypy', 'src/', '--ignore-missing-imports'],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=120
            )
            quality_results['type_checking'] = {
                'passed': result.returncode == 0,
                'issues': len(result.stderr.splitlines()) if result.returncode != 0 else 0
            }
        except Exception as e:
            quality_results['type_checking'] = {'error': str(e)}
        
        # Run security scanning
        try:
            result = subprocess.run(
                ['bandit', '-r', 'src/', '-ll'],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=120
            )
            quality_results['security_scan'] = {
                'passed': result.returncode == 0,
                'issues': result.stdout.count('>> Issue:') if result.returncode != 0 else 0
            }
        except Exception as e:
            quality_results['security_scan'] = {'error': str(e)}
        
        # Run tests
        try:
            result = subprocess.run(
                [sys.executable, '-m', 'pytest', 'tests/', '-v', '--tb=short'],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=300
            )
            quality_results['tests'] = {
                'passed': result.returncode == 0,
                'output': result.stdout
            }
        except Exception as e:
            quality_results['tests'] = {'error': str(e)}
        
        self.config_status['validations']['quality'] = quality_results
    
    def _generate_recommendations(self):
        """Generate configuration recommendations."""
        recommendations = []
        
        # Check for missing integrations
        integrations = self.config_status.get('validations', {}).get('integrations', {})
        
        if integrations.get('github', {}).get('token_missing'):
            recommendations.append({
                'type': 'integration',
                'priority': 'high',
                'title': 'Configure GitHub Integration',
                'description': 'Set GITHUB_TOKEN environment variable for GitHub API access',
                'action': 'Add GITHUB_TOKEN to environment or CI/CD secrets'
            })
        
        if integrations.get('slack', {}).get('webhook_missing'):
            recommendations.append({
                'type': 'integration',
                'priority': 'medium',
                'title': 'Configure Slack Integration',
                'description': 'Set SLACK_WEBHOOK_URL for team notifications',
                'action': 'Create Slack webhook and set SLACK_WEBHOOK_URL environment variable'
            })
        
        # Check automation setup
        automation = self.config_status.get('configurations', {}).get('automation', {})
        
        for script, config in automation.get('test_results', {}).items():
            if config.get('error'):
                recommendations.append({
                    'type': 'automation',
                    'priority': 'medium',
                    'title': f'Fix {script} Script',
                    'description': f'Script {script} is not working properly',
                    'action': f'Review and fix {script} configuration'
                })
        
        # Check quality issues
        quality = self.config_status.get('validations', {}).get('quality', {})
        
        for check, result in quality.items():
            if not result.get('passed', True) and result.get('issues', 0) > 0:
                recommendations.append({
                    'type': 'quality',
                    'priority': 'medium',
                    'title': f'Fix {check.replace("_", " ").title()} Issues',
                    'description': f'Found {result["issues"]} issues in {check}',
                    'action': f'Review and fix {check} issues'
                })
        
        self.config_status['recommendations'] = recommendations
    
    def _generate_configuration_report(self):
        """Generate comprehensive configuration report."""
        self.logger.info("Generating configuration report")
        
        # Run quality checks
        self._run_quality_checks()
        
        # Generate recommendations
        self._generate_recommendations()
        
        # Calculate overall status
        checks = self.config_status.get('checks', {})
        configurations = self.config_status.get('configurations', {})
        validations = self.config_status.get('validations', {})
        
        total_checks = len(checks) + len(configurations) + len(validations)
        passed_checks = 0
        
        for category in [checks, configurations, validations]:
            for item, status in category.items():
                if isinstance(status, dict):
                    if status.get('status') == 'passed' or status.get('configured') or status.get('passed'):
                        passed_checks += 1
        
        overall_score = (passed_checks / total_checks * 100) if total_checks > 0 else 0
        
        self.config_status['summary'] = {
            'overall_score': overall_score,
            'total_checks': total_checks,
            'passed_checks': passed_checks,
            'recommendations': len(self.config_status.get('recommendations', [])),
            'status': 'excellent' if overall_score >= 90 else 'good' if overall_score >= 75 else 'needs_improvement'
        }
    
    def save_configuration_report(self, output_file: str):
        """Save configuration report to file."""
        with open(output_file, 'w') as f:
            json.dump(self.config_status, f, indent=2, default=str)
        
        self.logger.info(f"Configuration report saved to {output_file}")
    
    def generate_summary_report(self) -> str:
        """Generate human-readable summary report."""
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        summary = self.config_status.get('summary', {})
        
        report = f"""# Repository Configuration Report

Generated: {timestamp}
Repository: {self.repo_root}

## Summary

**Overall Score**: {summary.get('overall_score', 0):.1f}/100
**Status**: {summary.get('status', 'unknown').title()}
**Checks Passed**: {summary.get('passed_checks', 0)}/{summary.get('total_checks', 0)}
**Recommendations**: {summary.get('recommendations', 0)}

"""
        
        # Repository structure
        structure = self.config_status.get('checks', {}).get('repository_structure', {})
        if structure:
            report += f"""## Repository Structure

**Status**: {structure.get('status', 'unknown').title()}
**Required Files**: {structure.get('required_files', 0)}
**Missing Files**: {len(structure.get('missing_files', []))}
**Required Directories**: {structure.get('required_directories', 0)}
**Missing Directories**: {len(structure.get('missing_directories', []))}

"""
            
            if structure.get('missing_files'):
                report += "**Missing Files**:\n"
                for file in structure['missing_files']:
                    report += f"- {file}\n"
                report += "\n"
            
            if structure.get('missing_directories'):
                report += "**Missing Directories**:\n"
                for dir in structure['missing_directories']:
                    report += f"- {dir}\n"
                report += "\n"
        
        # Integration status
        integrations = self.config_status.get('validations', {}).get('integrations', {})
        if integrations:
            report += "## Integration Status\n\n"
            
            for integration, status in integrations.items():
                if status.get('configured'):
                    report += f"✅ **{integration.title()}**: Configured\n"
                elif status.get('error'):
                    report += f"❌ **{integration.title()}**: Error - {status['error']}\n"
                else:
                    report += f"⚠️  **{integration.title()}**: Not configured\n"
            
            report += "\n"
        
        # Quality checks
        quality = self.config_status.get('validations', {}).get('quality', {})
        if quality:
            report += "## Quality Checks\n\n"
            
            for check, result in quality.items():
                check_name = check.replace('_', ' ').title()
                if result.get('passed'):
                    report += f"✅ **{check_name}**: Passed\n"
                elif result.get('error'):
                    report += f"❌ **{check_name}**: Error - {result['error']}\n"
                else:
                    issues = result.get('issues', 0)
                    report += f"⚠️  **{check_name}**: {issues} issues found\n"
            
            report += "\n"
        
        # Recommendations
        recommendations = self.config_status.get('recommendations', [])
        if recommendations:
            report += "## Recommendations\n\n"
            
            for rec in recommendations:
                priority_emoji = {'high': '🔴', 'medium': '🟡', 'low': '🟢'}.get(rec['priority'], '⚪')
                report += f"{priority_emoji} **{rec['title']}** ({rec['priority']} priority)\n"
                report += f"{rec['description']}\n"
                report += f"*Action*: {rec['action']}\n\n"
        
        return report


def main():
    """Main entry point for repository configurator."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Configure and validate repository setup')
    parser.add_argument('--repo-root', default='.',
                       help='Path to repository root directory')
    parser.add_argument('--output', default='configuration-report.json',
                       help='Output file for configuration report')
    parser.add_argument('--report', action='store_true',
                       help='Generate human-readable report')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run configurator
    configurator = RepositoryConfigurator(args.repo_root)
    
    try:
        results = configurator.configure_repository()
        configurator.save_configuration_report(args.output)
        
        if args.report:
            report = configurator.generate_summary_report()
            print(report)
            
            # Save report to file
            report_file = args.output.replace('.json', '-summary.md')
            with open(report_file, 'w') as f:
                f.write(report)
            print(f"\n📄 Summary report saved to: {report_file}")
        
        # Exit with appropriate code based on results
        summary = results.get('summary', {})
        overall_score = summary.get('overall_score', 0)
        
        if overall_score >= 90:
            print("\n✅ Repository configuration excellent")
            sys.exit(0)
        elif overall_score >= 75:
            print(f"\n⚠️  Repository configuration good ({overall_score:.1f}/100)")
            sys.exit(0)
        else:
            print(f"\n❌ Repository configuration needs improvement ({overall_score:.1f}/100)")
            sys.exit(1)
    
    except Exception as e:
        print(f"❌ Error during repository configuration: {e}")
        sys.exit(2)


if __name__ == '__main__':
    main()