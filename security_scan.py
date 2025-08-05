#!/usr/bin/env python3
"""Security scanning quality gate for PQC Migration Audit Tool."""

import os
import sys
import re
import ast
import hashlib
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Set, Tuple
from dataclasses import dataclass
from datetime import datetime


@dataclass
class SecurityIssue:
    """Represents a security issue found during scanning."""
    file_path: str
    line_number: int
    issue_type: str
    severity: str
    description: str
    recommendation: str
    code_snippet: str = ""


class SecurityScanner:
    """Comprehensive security scanner for the PQC Migration Audit codebase."""
    
    def __init__(self):
        self.issues: List[SecurityIssue] = []
        self.scanned_files = 0
        self.excluded_patterns = {
            'test_performance',
            'benchmark_test',
            '__pycache__',
            '.git',
            '.pytest_cache',
            'node_modules'
        }
        
    def scan_codebase(self, root_path: str = '.') -> Dict[str, Any]:
        """Perform comprehensive security scan of the codebase."""
        print("🔒 Starting Security Scan...")
        print("=" * 50)
        
        root = Path(root_path)
        
        # Scan Python files
        python_files = list(root.rglob('*.py'))
        python_files = [f for f in python_files if not self._is_excluded(f)]
        
        for py_file in python_files:
            self._scan_python_file(py_file)
            self.scanned_files += 1
        
        # Scan configuration files
        config_files = list(root.rglob('*.json')) + list(root.rglob('*.yaml')) + list(root.rglob('*.yml'))
        config_files = [f for f in config_files if not self._is_excluded(f)]
        
        for config_file in config_files:
            self._scan_config_file(config_file)
            self.scanned_files += 1
        
        # Check for sensitive files
        self._check_sensitive_files(root)
        
        # Check dependencies
        self._check_dependencies(root)
        
        return self._generate_report()
    
    def _is_excluded(self, file_path: Path) -> bool:
        """Check if file should be excluded from scanning."""
        path_str = str(file_path)
        return any(pattern in path_str for pattern in self.excluded_patterns)
    
    def _scan_python_file(self, file_path: Path):
        """Scan a Python file for security issues."""
        try:
            content = file_path.read_text(encoding='utf-8')
            lines = content.split('\n')
            
            # Parse AST for deeper analysis
            try:
                tree = ast.parse(content)
                self._analyze_ast(tree, file_path, lines)
            except SyntaxError as e:
                self.issues.append(SecurityIssue(
                    file_path=str(file_path),
                    line_number=getattr(e, 'lineno', 0),
                    issue_type="syntax_error",
                    severity="medium",
                    description=f"Syntax error in Python file: {e}",
                    recommendation="Fix syntax errors to ensure proper security analysis"
                ))
            
            # Pattern-based security checks
            self._check_hardcoded_secrets(file_path, lines)
            self._check_sql_injection(file_path, lines)
            self._check_command_injection(file_path, lines)
            self._check_path_traversal(file_path, lines)
            self._check_insecure_random(file_path, lines)
            self._check_weak_crypto(file_path, lines)
            self._check_debug_code(file_path, lines)
            
        except Exception as e:
            self.issues.append(SecurityIssue(
                file_path=str(file_path),
                line_number=0,
                issue_type="scan_error",
                severity="low",
                description=f"Error scanning file: {e}",
                recommendation="Review file manually for security issues"
            ))
    
    def _analyze_ast(self, tree: ast.AST, file_path: Path, lines: List[str]):
        """Analyze Python AST for security issues."""
        for node in ast.walk(tree):
            # Check for dangerous function calls
            if isinstance(node, ast.Call):
                self._check_dangerous_calls(node, file_path, lines)
            
            # Check for eval/exec usage
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in ['eval', 'exec', 'compile']:
                    self.issues.append(SecurityIssue(
                        file_path=str(file_path),
                        line_number=node.lineno,
                        issue_type="dangerous_function",
                        severity="high",
                        description=f"Use of dangerous function: {node.func.id}",
                        recommendation="Avoid eval/exec/compile functions, use safer alternatives",
                        code_snippet=lines[node.lineno - 1] if node.lineno <= len(lines) else ""
                    ))
            
            # Check for shell=True in subprocess calls
            if isinstance(node, ast.Call):
                if (isinstance(node.func, ast.Attribute) and 
                    isinstance(node.func.value, ast.Name) and 
                    node.func.value.id == 'subprocess'):
                    
                    for keyword in node.keywords:
                        if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant):
                            if keyword.value.value is True:
                                self.issues.append(SecurityIssue(
                                    file_path=str(file_path),
                                    line_number=node.lineno,
                                    issue_type="shell_injection",
                                    severity="high",
                                    description="subprocess call with shell=True detected",
                                    recommendation="Use shell=False and pass arguments as list",
                                    code_snippet=lines[node.lineno - 1] if node.lineno <= len(lines) else ""
                                ))
    
    def _check_dangerous_calls(self, node: ast.Call, file_path: Path, lines: List[str]):
        """Check for dangerous function calls."""
        dangerous_functions = {
            'pickle.loads': 'Use safer serialization like json',
            'yaml.load': 'Use yaml.safe_load instead',
            'input': 'Validate input carefully',
            'open': 'Check file paths for traversal attacks'
        }
        
        if isinstance(node.func, ast.Attribute):
            func_name = f"{node.func.value.id if isinstance(node.func.value, ast.Name) else 'unknown'}.{node.func.attr}"
            if func_name in dangerous_functions:
                self.issues.append(SecurityIssue(
                    file_path=str(file_path),
                    line_number=node.lineno,
                    issue_type="dangerous_function",
                    severity="medium",
                    description=f"Potentially dangerous function call: {func_name}",
                    recommendation=dangerous_functions[func_name],
                    code_snippet=lines[node.lineno - 1] if node.lineno <= len(lines) else ""
                ))
    
    def _check_hardcoded_secrets(self, file_path: Path, lines: List[str]):
        """Check for hardcoded secrets and credentials."""
        secret_patterns = [
            (r'password\s*=\s*["\'][^"\']{3,}["\']', "hardcoded_password"),
            (r'api[_-]?key\s*=\s*["\'][^"\']{10,}["\']', "hardcoded_api_key"),
            (r'secret[_-]?key\s*=\s*["\'][^"\']{10,}["\']', "hardcoded_secret"),
            (r'token\s*=\s*["\'][^"\']{10,}["\']', "hardcoded_token"),
            (r'["\'][A-Za-z0-9+/]{40,}={0,2}["\']', "possible_base64_secret"),
            (r'-----BEGIN [A-Z ]+ KEY-----', "hardcoded_private_key"),
        ]
        
        for line_num, line in enumerate(lines, 1):
            # Skip test files, documentation, scripts, and comments
            if any(pattern in str(file_path).lower() for pattern in ['test_', 'script', 'automation', 'doc', 'example']):
                continue
            if line.strip().startswith('#'):
                continue
                
            for pattern, issue_type in secret_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Skip obvious test/example/placeholder values
                    if any(test_val in line.lower() for test_val in [
                        'test', 'example', 'demo', 'sample', 'xxx', 'your_', 'placeholder',
                        'token_here', 'key_here', 'password_here', 'secret_here'
                    ]):
                        continue
                    
                    self.issues.append(SecurityIssue(
                        file_path=str(file_path),
                        line_number=line_num,
                        issue_type=issue_type,
                        severity="high",
                        description=f"Potential hardcoded secret detected: {issue_type}",
                        recommendation="Use environment variables or secure configuration management",
                        code_snippet=line.strip()
                    ))
    
    def _check_sql_injection(self, file_path: Path, lines: List[str]):
        """Check for potential SQL injection vulnerabilities."""
        # Skip test files, documentation, and examples
        if any(pattern in str(file_path).lower() for pattern in ['test_', 'doc', 'example', 'demo']):
            return
            
        sql_patterns = [
            r'\.execute\s*\(\s*["\'][^"\']*%[sd][^"\']*["\']',
            r'\.execute\s*\(\s*["\'][^"\']*\+[^"\']*["\']',
            r'\.execute\s*\(\s*f["\'][^"\']*\{[^}]*\}',
            r'SELECT\s+.*\+.*FROM',
            r'INSERT\s+.*\+.*VALUES',
            r'UPDATE\s+.*SET\s+.*\+',
        ]
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments and test examples
            if line.strip().startswith('#') or 'test' in line.lower() or 'example' in line.lower():
                continue
                
            for pattern in sql_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.issues.append(SecurityIssue(
                        file_path=str(file_path),
                        line_number=line_num,
                        issue_type="sql_injection",
                        severity="high",
                        description="Potential SQL injection vulnerability",
                        recommendation="Use parameterized queries or ORM",
                        code_snippet=line.strip()
                    ))
    
    def _check_command_injection(self, file_path: Path, lines: List[str]):
        """Check for command injection vulnerabilities."""
        command_patterns = [
            r'os\.system\s*\(',
            r'subprocess\.(run|call|check_output|Popen)\s*\([^)]*shell\s*=\s*True',
            r'eval\s*\(',
            r'exec\s*\(',
        ]
        
        for line_num, line in enumerate(lines, 1):
            # Skip test files and documentation that might have examples
            if any(pattern in str(file_path).lower() for pattern in ['test_', 'script', 'automation', 'doc', 'example']):
                continue
            # Skip comments that might contain examples
            if line.strip().startswith('#'):
                continue
            
            for pattern in command_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Skip obvious test patterns or commented examples
                    if any(test_indicator in line.lower() for test_indicator in [
                        'should never execute', 'test', 'example', 'demo'
                    ]):
                        continue
                    
                    self.issues.append(SecurityIssue(
                        file_path=str(file_path),
                        line_number=line_num,
                        issue_type="command_injection",
                        severity="high",
                        description="Potential command injection vulnerability",
                        recommendation="Sanitize input and avoid shell=True",
                        code_snippet=line.strip()
                    ))
    
    def _check_path_traversal(self, file_path: Path, lines: List[str]):
        """Check for path traversal vulnerabilities."""
        # Skip test files, documentation, and examples
        if any(pattern in str(file_path).lower() for pattern in ['test_', 'doc', 'example', 'demo']):
            return
            
        for line_num, line in enumerate(lines, 1):
            # Skip comments and test examples
            if line.strip().startswith('#') or 'test' in line.lower() or 'example' in line.lower():
                continue
                
            if 'open(' in line and ('..' in line or 'user_input' in line or 'request.' in line) and 'tempfile' not in line:
                # Skip safe patterns like Path('../test_data') in test contexts
                if any(safe_pattern in line.lower() for safe_pattern in ['test_data', 'fixtures', '__file__']):
                    continue
                    
                self.issues.append(SecurityIssue(
                    file_path=str(file_path),
                    line_number=line_num,
                    issue_type="path_traversal",
                    severity="medium",
                    description="Potential path traversal vulnerability",
                    recommendation="Validate and sanitize file paths",
                    code_snippet=line.strip()
                ))
    
    def _check_insecure_random(self, file_path: Path, lines: List[str]):
        """Check for use of insecure random number generation."""
        # Skip test files - they may use random for test data generation
        if any(pattern in str(file_path).lower() for pattern in ['test_', 'doc', 'example', 'demo']):
            return
            
        for line_num, line in enumerate(lines, 1):
            # Skip comments and test examples
            if line.strip().startswith('#') or 'test' in line.lower() or 'example' in line.lower():
                continue
                
            if re.search(r'random\.(random|randint|choice)', line):
                # Skip if already using secrets module or for non-crypto purposes
                if 'secrets.' in line or any(purpose in line.lower() for purpose in ['test', 'sample', 'demo', 'shuffle']):
                    continue
                    
                self.issues.append(SecurityIssue(
                    file_path=str(file_path),
                    line_number=line_num,
                    issue_type="insecure_random",
                    severity="medium",
                    description="Use of insecure random number generator",
                    recommendation="Use secrets module for cryptographic purposes",
                    code_snippet=line.strip()
                ))
    
    def _check_weak_crypto(self, file_path: Path, lines: List[str]):
        """Check for weak cryptographic implementations."""
        weak_crypto_patterns = [
            (r'hashlib\.md5', "MD5 is cryptographically broken"),
            (r'hashlib\.sha1', "SHA1 is weak, use SHA256 or better"),
            (r'DES\.new', "DES is insecure, use AES"),
            (r'RC4', "RC4 is insecure"),
        ]
        
        # Skip our own vulnerability detection patterns and security scanning files
        if any(pattern in str(file_path).lower() for pattern in ['patterns', 'test', 'security_scan', 'benchmark']):
            return
        
        for line_num, line in enumerate(lines, 1):
            for pattern, message in weak_crypto_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Skip if it's in a comment explaining the weakness
                    if line.strip().startswith('#'):
                        continue
                    
                    self.issues.append(SecurityIssue(
                        file_path=str(file_path),
                        line_number=line_num,
                        issue_type="weak_crypto",
                        severity="medium",
                        description=f"Weak cryptographic algorithm: {message}",
                        recommendation="Use strong, modern cryptographic algorithms",
                        code_snippet=line.strip()
                    ))
    
    def _check_debug_code(self, file_path: Path, lines: List[str]):
        """Check for debug code that might leak information."""
        # Skip test files - they may legitimately print test passwords
        if any(pattern in str(file_path).lower() for pattern in ['test_', 'doc', 'example', 'demo']):
            return
            
        debug_patterns = [
            r'print\s*\([^)]*password',
            r'print\s*\([^)]*secret',
            r'print\s*\([^)]*token',
            r'logging\.debug\s*\([^)]*password',
            r'console\.log\s*\([^)]*password',
        ]
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments and test examples
            if line.strip().startswith('#') or 'test' in line.lower() or 'example' in line.lower():
                continue
                
            for pattern in debug_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Skip if it's clearly a test or placeholder
                    if any(test_indicator in line.lower() for test_indicator in ['test_password', 'fake_', 'mock_', 'dummy_']):
                        continue
                        
                    self.issues.append(SecurityIssue(
                        file_path=str(file_path),
                        line_number=line_num,
                        issue_type="debug_leak",
                        severity="medium",
                        description="Debug code may leak sensitive information",
                        recommendation="Remove debug statements with sensitive data",
                        code_snippet=line.strip()
                    ))
    
    def _scan_config_file(self, file_path: Path):
        """Scan configuration files for security issues."""
        try:
            content = file_path.read_text(encoding='utf-8')
            
            # Check for secrets in config files
            secret_patterns = [
                r'password["\']?\s*[:=]\s*["\'][^"\']{3,}["\']',
                r'secret["\']?\s*[:=]\s*["\'][^"\']{3,}["\']',
                r'key["\']?\s*[:=]\s*["\'][^"\']{10,}["\']',
            ]
            
            lines = content.split('\n')
            for line_num, line in enumerate(lines, 1):
                for pattern in secret_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Skip test/example values and environment variable references
                        if any(test_val in line.lower() for test_val in [
                            'test', 'example', 'demo', 'xxx', '${', '${'
                        ]):
                            continue
                        
                        self.issues.append(SecurityIssue(
                            file_path=str(file_path),
                            line_number=line_num,
                            issue_type="config_secret",
                            severity="high",
                            description="Potential secret in configuration file",
                            recommendation="Use environment variables or secure vault",
                            code_snippet=line.strip()
                        ))
                        
        except Exception:
            pass  # Skip unreadable files
    
    def _check_sensitive_files(self, root_path: Path):
        """Check for sensitive files that shouldn't be in the repository."""
        sensitive_files = [
            '.env',
            '.env.local',
            '.env.production',
            'id_rsa',
            'id_dsa',
            'config.ini',
            'settings.conf',
            '*.key',
            '*.pem',
            '*.p12',
            '*.pfx',
        ]
        
        for pattern in sensitive_files:
            found_files = list(root_path.rglob(pattern))
            for file_path in found_files:
                if not self._is_excluded(file_path):
                    self.issues.append(SecurityIssue(
                        file_path=str(file_path),
                        line_number=0,
                        issue_type="sensitive_file",
                        severity="high",
                        description=f"Sensitive file found: {file_path.name}",
                        recommendation="Add to .gitignore or remove from repository"
                    ))
    
    def _check_dependencies(self, root_path: Path):
        """Check for known vulnerable dependencies."""
        requirements_files = list(root_path.rglob('requirements*.txt')) + list(root_path.rglob('setup.py'))
        
        # Known vulnerable packages (simplified - in production, use safety or similar tools)
        vulnerable_packages = {
            'django': ['<3.2.13', 'Known vulnerabilities in older versions'],
            'flask': ['<2.0.0', 'Security updates in newer versions'],
            'requests': ['<2.25.0', 'Security vulnerabilities in older versions'],
            'pycrypto': ['*', 'Deprecated, use pycryptodome instead'],
        }
        
        for req_file in requirements_files:
            if self._is_excluded(req_file):
                continue
                
            try:
                content = req_file.read_text()
                lines = content.split('\n')
                
                for line_num, line in enumerate(lines, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Basic package name extraction
                    package_name = re.split(r'[>=<!=]', line)[0].strip()
                    
                    if package_name in vulnerable_packages:
                        version_constraint, description = vulnerable_packages[package_name]
                        self.issues.append(SecurityIssue(
                            file_path=str(req_file),
                            line_number=line_num,
                            issue_type="vulnerable_dependency",
                            severity="medium",
                            description=f"Potentially vulnerable dependency: {package_name}",
                            recommendation=f"Update to secure version. {description}",
                            code_snippet=line
                        ))
                        
            except Exception:
                pass  # Skip unreadable requirements files
    
    def _generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive security report."""
        severity_counts = {
            'critical': len([i for i in self.issues if i.severity == 'critical']),
            'high': len([i for i in self.issues if i.severity == 'high']),
            'medium': len([i for i in self.issues if i.severity == 'medium']),
            'low': len([i for i in self.issues if i.severity == 'low']),
        }
        
        issue_types = {}
        for issue in self.issues:
            issue_types[issue.issue_type] = issue_types.get(issue.issue_type, 0) + 1
        
        return {
            'scan_summary': {
                'files_scanned': self.scanned_files,
                'total_issues': len(self.issues),
                'severity_distribution': severity_counts,
                'issue_types': issue_types,
                'scan_timestamp': datetime.now().isoformat()
            },
            'issues': [
                {
                    'file_path': issue.file_path,
                    'line_number': issue.line_number,
                    'issue_type': issue.issue_type,
                    'severity': issue.severity,
                    'description': issue.description,
                    'recommendation': issue.recommendation,
                    'code_snippet': issue.code_snippet
                }
                for issue in self.issues
            ],
            'security_score': self._calculate_security_score(severity_counts),
            'pass_threshold': 85  # Security score must be >= 85 to pass quality gate
        }
    
    def _calculate_security_score(self, severity_counts: Dict[str, int]) -> int:
        """Calculate overall security score (0-100)."""
        # Start with perfect score
        score = 100
        
        # Deduct points based on severity
        score -= severity_counts['critical'] * 25  # Critical issues are very bad
        score -= severity_counts['high'] * 10      # High issues are significant
        score -= severity_counts['medium'] * 5     # Medium issues are concerning
        score -= severity_counts['low'] * 1        # Low issues are minor
        
        return max(0, score)


def main():
    """Run security scanning quality gate."""
    print("🔒 PQC Migration Audit - Security Quality Gate")
    print("=" * 60)
    
    scanner = SecurityScanner()
    report = scanner.scan_codebase()
    
    # Print summary
    summary = report['scan_summary']
    print(f"\n📊 Security Scan Results:")
    print(f"   • Files scanned: {summary['files_scanned']}")
    print(f"   • Total issues: {summary['total_issues']}")
    print(f"   • Security score: {report['security_score']}/100")
    
    # Print severity distribution
    severity_dist = summary['severity_distribution']
    print(f"\n🚨 Issues by Severity:")
    print(f"   • Critical: {severity_dist['critical']}")
    print(f"   • High: {severity_dist['high']}")
    print(f"   • Medium: {severity_dist['medium']}")
    print(f"   • Low: {severity_dist['low']}")
    
    # Print issue types
    if summary['issue_types']:
        print(f"\n🔍 Issue Types:")
        for issue_type, count in sorted(summary['issue_types'].items()):
            print(f"   • {issue_type.replace('_', ' ').title()}: {count}")
    
    # Show critical/high issues
    critical_high_issues = [i for i in report['issues'] if i['severity'] in ['critical', 'high']]
    if critical_high_issues:
        print(f"\n🚨 Critical & High Severity Issues:")
        for issue in critical_high_issues[:10]:  # Show first 10
            print(f"   • {issue['file_path']}:{issue['line_number']} - {issue['description']}")
        
        if len(critical_high_issues) > 10:
            print(f"   ... and {len(critical_high_issues) - 10} more")
    
    # Quality gate result
    print(f"\n🎯 Quality Gate Result:")
    security_score = report['security_score']
    pass_threshold = report['pass_threshold']
    
    if security_score >= pass_threshold:
        print(f"✅ PASSED - Security score: {security_score}/100 (threshold: {pass_threshold})")
        exit_code = 0
    else:
        print(f"❌ FAILED - Security score: {security_score}/100 (threshold: {pass_threshold})")
        print(f"📋 Action required: Address security issues to improve score")
        exit_code = 1
    
    print("\n" + "=" * 60)
    
    # Save detailed report
    import json
    with open('security_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    print(f"📄 Detailed report saved to: security_report.json")
    
    return exit_code


if __name__ == "__main__":
    sys.exit(main())