#!/usr/bin/env python3
"""
Advanced Dependency Scanner for PQC Migration Audit project.

This script provides comprehensive dependency analysis including:
- Security vulnerability scanning
- License compliance checking
- Outdated package detection
- Dependency tree analysis
- Risk assessment
"""

import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import tempfile
import urllib.request
import urllib.parse


class DependencyScanner:
    """Comprehensive dependency scanner and analyzer."""
    
    def __init__(self, project_root: str = "."):
        """Initialize dependency scanner."""
        self.project_root = Path(project_root).resolve()
        self.logger = logging.getLogger(__name__)
        
        # Security databases
        self.pyup_db_url = "https://pyup.io/api/v1/vulnerabilities/"
        self.osv_api_url = "https://api.osv.dev/v1/query"
        
        # Results storage
        self.scan_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'project_root': str(self.project_root),
            'dependencies': {},
            'vulnerabilities': [],
            'licenses': {},
            'outdated': [],
            'metrics': {},
            'recommendations': []
        }
    
    def scan_all_dependencies(self) -> Dict:
        """Perform comprehensive dependency scan."""
        self.logger.info("Starting comprehensive dependency scan")
        
        try:
            # Discover dependency files
            dep_files = self._discover_dependency_files()
            self.logger.info(f"Found {len(dep_files)} dependency files")
            
            # Parse dependencies from all sources
            dependencies = self._parse_all_dependencies(dep_files)
            self.scan_results['dependencies'] = dependencies
            
            # Security vulnerability scan
            vulnerabilities = self._scan_vulnerabilities(dependencies)
            self.scan_results['vulnerabilities'] = vulnerabilities
            
            # License compliance scan
            licenses = self._scan_licenses(dependencies)
            self.scan_results['licenses'] = licenses
            
            # Outdated packages check
            outdated = self._check_outdated_packages(dependencies)
            self.scan_results['outdated'] = outdated
            
            # Dependency tree analysis
            tree_analysis = self._analyze_dependency_tree(dependencies)
            self.scan_results['tree_analysis'] = tree_analysis
            
            # Calculate metrics and risk scores
            metrics = self._calculate_metrics()
            self.scan_results['metrics'] = metrics
            
            # Generate recommendations
            recommendations = self._generate_recommendations()
            self.scan_results['recommendations'] = recommendations
            
            self.logger.info("Dependency scan completed successfully")
            return self.scan_results
            
        except Exception as e:
            self.logger.error(f"Error during dependency scan: {e}")
            raise
    
    def _discover_dependency_files(self) -> List[Path]:
        """Discover all dependency files in the project."""
        dependency_patterns = [
            'requirements.txt',
            'requirements-*.txt',
            'setup.py',
            'setup.cfg',
            'pyproject.toml',
            'Pipfile',
            'Pipfile.lock',
            'poetry.lock',
            'conda.yml',
            'environment.yml',
            'package.json',
            'package-lock.json',
            'yarn.lock',
            'Gemfile',
            'Gemfile.lock',
            'go.mod',
            'go.sum',
            'Cargo.toml',
            'Cargo.lock',
            'composer.json',
            'composer.lock'
        ]
        
        found_files = []
        
        for pattern in dependency_patterns:
            if '*' in pattern:
                # Handle wildcard patterns
                files = list(self.project_root.glob(pattern))
                found_files.extend(files)
            else:
                file_path = self.project_root / pattern
                if file_path.exists():
                    found_files.append(file_path)
        
        # Also search in subdirectories for some files
        for subdir in ['src', 'lib', 'app', 'server', 'client']:
            subdir_path = self.project_root / subdir
            if subdir_path.exists():
                for pattern in ['requirements.txt', 'package.json', 'setup.py']:
                    file_path = subdir_path / pattern
                    if file_path.exists():
                        found_files.append(file_path)
        
        return list(set(found_files))  # Remove duplicates
    
    def _parse_all_dependencies(self, dep_files: List[Path]) -> Dict:
        """Parse dependencies from all discovered files."""
        all_dependencies = {}
        
        for dep_file in dep_files:
            self.logger.info(f"Parsing dependencies from {dep_file}")
            
            try:
                if dep_file.name == 'requirements.txt' or dep_file.name.startswith('requirements-'):
                    deps = self._parse_requirements_txt(dep_file)
                elif dep_file.name == 'setup.py':
                    deps = self._parse_setup_py(dep_file)
                elif dep_file.name == 'pyproject.toml':
                    deps = self._parse_pyproject_toml(dep_file)
                elif dep_file.name == 'package.json':
                    deps = self._parse_package_json(dep_file)
                elif dep_file.name in ['Pipfile', 'Pipfile.lock']:
                    deps = self._parse_pipfile(dep_file)
                else:
                    self.logger.warning(f"Unsupported dependency file type: {dep_file}")
                    continue
                
                # Merge dependencies
                for name, info in deps.items():
                    if name not in all_dependencies:
                        all_dependencies[name] = info
                    else:
                        # Merge version constraints
                        existing = all_dependencies[name]
                        if 'version_constraints' in existing and 'version_constraints' in info:
                            existing['version_constraints'].extend(info['version_constraints'])
                            existing['version_constraints'] = list(set(existing['version_constraints']))
                        
                        # Add source file information
                        if 'source_files' not in existing:
                            existing['source_files'] = []
                        existing['source_files'].append(str(dep_file))
                
            except Exception as e:
                self.logger.error(f"Error parsing {dep_file}: {e}")
        
        return all_dependencies
    
    def _parse_requirements_txt(self, file_path: Path) -> Dict:
        """Parse requirements.txt file."""
        dependencies = {}
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Skip comments and empty lines
                    if not line or line.startswith('#') or line.startswith('-'):
                        continue
                    
                    # Parse package specification
                    package_info = self._parse_package_spec(line)
                    if package_info:
                        name, version_spec = package_info
                        dependencies[name] = {
                            'name': name,
                            'version_constraints': [version_spec] if version_spec else [],
                            'source_file': str(file_path),
                            'line_number': line_num,
                            'ecosystem': 'pypi'
                        }
        
        except Exception as e:
            self.logger.error(f"Error reading {file_path}: {e}")
        
        return dependencies
    
    def _parse_package_spec(self, spec: str) -> Optional[Tuple[str, str]]:
        """Parse a package specification like 'package>=1.0.0'."""
        import re
        
        # Remove comments
        spec = spec.split('#')[0].strip()
        
        # Pattern to match package specifications
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?)([<>=!~]+[0-9][^;]*)?'
        match = re.match(pattern, spec)
        
        if match:
            package_name = match.group(1)
            version_spec = match.group(3) if match.group(3) else None
            return package_name.lower(), version_spec
        
        return None
    
    def _parse_setup_py(self, file_path: Path) -> Dict:
        """Extract dependencies from setup.py file."""
        dependencies = {}
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Simple regex-based extraction (not perfect but works for most cases)
            import re
            
            # Look for install_requires
            install_requires_pattern = r'install_requires\s*=\s*\[(.*?)\]'
            match = re.search(install_requires_pattern, content, re.DOTALL)
            
            if match:
                requirements_str = match.group(1)
                # Extract quoted strings
                req_pattern = r'["\']([^"\']+)["\']'
                requirements = re.findall(req_pattern, requirements_str)
                
                for req in requirements:
                    package_info = self._parse_package_spec(req)
                    if package_info:
                        name, version_spec = package_info
                        dependencies[name] = {
                            'name': name,
                            'version_constraints': [version_spec] if version_spec else [],
                            'source_file': str(file_path),
                            'ecosystem': 'pypi'
                        }
        
        except Exception as e:
            self.logger.error(f"Error parsing setup.py {file_path}: {e}")
        
        return dependencies
    
    def _parse_pyproject_toml(self, file_path: Path) -> Dict:
        """Parse pyproject.toml file."""
        dependencies = {}
        
        try:
            import tomllib
            
            with open(file_path, 'rb') as f:
                data = tomllib.load(f)
            
            # Check different sections for dependencies
            sections = [
                ['project', 'dependencies'],
                ['tool', 'poetry', 'dependencies'],
                ['build-system', 'requires']
            ]
            
            for section_path in sections:
                current = data
                for key in section_path:
                    if isinstance(current, dict) and key in current:
                        current = current[key]
                    else:
                        current = None
                        break
                
                if current and isinstance(current, list):
                    for dep in current:
                        if isinstance(dep, str):
                            package_info = self._parse_package_spec(dep)
                            if package_info:
                                name, version_spec = package_info
                                dependencies[name] = {
                                    'name': name,
                                    'version_constraints': [version_spec] if version_spec else [],
                                    'source_file': str(file_path),
                                    'ecosystem': 'pypi'
                                }
        
        except ImportError:
            self.logger.warning("tomllib not available, skipping pyproject.toml parsing")
        except Exception as e:
            self.logger.error(f"Error parsing pyproject.toml {file_path}: {e}")
        
        return dependencies
    
    def _parse_package_json(self, file_path: Path) -> Dict:
        """Parse package.json file."""
        dependencies = {}
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Parse dependencies and devDependencies
            for dep_type in ['dependencies', 'devDependencies', 'peerDependencies']:
                if dep_type in data:
                    for name, version in data[dep_type].items():
                        dependencies[name] = {
                            'name': name,
                            'version_constraints': [version],
                            'source_file': str(file_path),
                            'ecosystem': 'npm',
                            'dependency_type': dep_type
                        }
        
        except Exception as e:
            self.logger.error(f"Error parsing package.json {file_path}: {e}")
        
        return dependencies
    
    def _parse_pipfile(self, file_path: Path) -> Dict:
        """Parse Pipfile or Pipfile.lock."""
        dependencies = {}
        
        try:
            if file_path.name == 'Pipfile.lock':
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                for section in ['default', 'develop']:
                    if section in data:
                        for name, info in data[section].items():
                            version = info.get('version', '')
                            dependencies[name] = {
                                'name': name,
                                'version_constraints': [version] if version else [],
                                'source_file': str(file_path),
                                'ecosystem': 'pypi',
                                'section': section
                            }
            else:
                # Parse Pipfile (TOML format)
                try:
                    import tomllib
                    with open(file_path, 'rb') as f:
                        data = tomllib.load(f)
                    
                    for section in ['packages', 'dev-packages']:
                        if section in data:
                            for name, version_spec in data[section].items():
                                if isinstance(version_spec, str):
                                    version = version_spec
                                elif isinstance(version_spec, dict):
                                    version = version_spec.get('version', '')
                                else:
                                    version = ''
                                
                                dependencies[name] = {
                                    'name': name,
                                    'version_constraints': [version] if version else [],
                                    'source_file': str(file_path),
                                    'ecosystem': 'pypi',
                                    'section': section
                                }
                
                except ImportError:
                    self.logger.warning("tomllib not available, skipping Pipfile parsing")
        
        except Exception as e:
            self.logger.error(f"Error parsing {file_path}: {e}")
        
        return dependencies
    
    def _scan_vulnerabilities(self, dependencies: Dict) -> List[Dict]:
        """Scan dependencies for known security vulnerabilities."""
        self.logger.info("Scanning for security vulnerabilities")
        
        vulnerabilities = []
        
        # Use multiple sources for vulnerability data
        vulnerabilities.extend(self._scan_with_safety(dependencies))
        vulnerabilities.extend(self._scan_with_osv(dependencies))
        vulnerabilities.extend(self._scan_with_audit(dependencies))
        
        # Deduplicate vulnerabilities
        seen = set()
        unique_vulns = []
        for vuln in vulnerabilities:
            vuln_id = f"{vuln['package']}-{vuln.get('id', vuln.get('title', ''))}"
            if vuln_id not in seen:
                seen.add(vuln_id)
                unique_vulns.append(vuln)
        
        self.logger.info(f"Found {len(unique_vulns)} unique vulnerabilities")
        return unique_vulns
    
    def _scan_with_safety(self, dependencies: Dict) -> List[Dict]:
        """Scan using Safety tool."""
        vulnerabilities = []
        
        try:
            # Run safety check
            result = subprocess.run(
                ['safety', 'check', '--json'],
                capture_output=True, text=True, timeout=300
            )
            
            if result.stdout:
                try:
                    safety_data = json.loads(result.stdout)
                    for vuln in safety_data:
                        vulnerabilities.append({
                            'package': vuln.get('package', ''),
                            'version': vuln.get('installed_version', ''),
                            'id': vuln.get('id', ''),
                            'title': vuln.get('title', ''),
                            'description': vuln.get('description', ''),
                            'severity': vuln.get('severity', 'unknown'),
                            'cve': vuln.get('cve', ''),
                            'source': 'safety',
                            'vulnerable_versions': vuln.get('specs', [])
                        })
                except json.JSONDecodeError:
                    self.logger.warning("Could not parse safety output")
        
        except subprocess.TimeoutExpired:
            self.logger.warning("Safety scan timed out")
        except FileNotFoundError:
            self.logger.info("Safety tool not found, skipping safety scan")
        except Exception as e:
            self.logger.error(f"Error running safety scan: {e}")
        
        return vulnerabilities
    
    def _scan_with_osv(self, dependencies: Dict) -> List[Dict]:
        """Scan using OSV (Open Source Vulnerabilities) API."""
        vulnerabilities = []
        
        try:
            for package_name, package_info in dependencies.items():
                if package_info.get('ecosystem') == 'pypi':
                    vulns = self._query_osv_api(package_name, package_info.get('version', ''))
                    vulnerabilities.extend(vulns)
        
        except Exception as e:
            self.logger.error(f"Error scanning with OSV: {e}")
        
        return vulnerabilities
    
    def _query_osv_api(self, package: str, version: str) -> List[Dict]:
        """Query OSV API for vulnerabilities."""
        vulnerabilities = []
        
        try:
            query_data = {
                "package": {
                    "name": package,
                    "ecosystem": "PyPI"
                }
            }
            
            if version:
                query_data["version"] = version
            
            query_json = json.dumps(query_data).encode('utf-8')
            
            req = urllib.request.Request(
                self.osv_api_url,
                data=query_json,
                headers={'Content-Type': 'application/json'}
            )
            
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode('utf-8'))
            
            for vuln in data.get('vulns', []):
                vulnerabilities.append({
                    'package': package,
                    'version': version,
                    'id': vuln.get('id', ''),
                    'title': vuln.get('summary', ''),
                    'description': vuln.get('details', ''),
                    'severity': self._extract_severity_from_osv(vuln),
                    'source': 'osv',
                    'published': vuln.get('published', ''),
                    'modified': vuln.get('modified', ''),
                    'references': [ref.get('url', '') for ref in vuln.get('references', [])]
                })
        
        except Exception as e:
            self.logger.debug(f"Error querying OSV for {package}: {e}")
        
        return vulnerabilities
    
    def _extract_severity_from_osv(self, vuln_data: Dict) -> str:
        """Extract severity from OSV vulnerability data."""
        severity = vuln_data.get('database_specific', {}).get('severity', 'unknown')
        
        # Try to get CVSS score
        for ref in vuln_data.get('references', []):
            if ref.get('type') == 'ADVISORY':
                # Would need to parse CVSS from advisory
                pass
        
        return severity
    
    def _scan_with_audit(self, dependencies: Dict) -> List[Dict]:
        """Scan using pip-audit tool."""
        vulnerabilities = []
        
        try:
            result = subprocess.run(
                ['pip-audit', '--format=json'],
                capture_output=True, text=True, timeout=300
            )
            
            if result.stdout:
                try:
                    audit_data = json.loads(result.stdout)
                    for vuln in audit_data.get('vulnerabilities', []):
                        vulnerabilities.append({
                            'package': vuln.get('package', ''),
                            'version': vuln.get('installed_version', ''),
                            'id': vuln.get('id', ''),
                            'title': vuln.get('description', ''),
                            'description': vuln.get('description', ''),
                            'severity': 'unknown',  # pip-audit doesn't provide severity
                            'source': 'pip-audit',
                            'fix_versions': vuln.get('fix_versions', [])
                        })
                except json.JSONDecodeError:
                    self.logger.warning("Could not parse pip-audit output")
        
        except subprocess.TimeoutExpired:
            self.logger.warning("pip-audit scan timed out")
        except FileNotFoundError:
            self.logger.info("pip-audit tool not found, skipping audit scan")
        except Exception as e:
            self.logger.error(f"Error running pip-audit: {e}")
        
        return vulnerabilities
    
    def _scan_licenses(self, dependencies: Dict) -> Dict:
        """Scan dependencies for license information."""
        self.logger.info("Scanning license information")
        
        licenses = {}
        license_summary = {
            'by_license': {},
            'unknown': [],
            'risky': [],
            'approved': []
        }
        
        # Approved licenses (modify based on your organization's policy)
        approved_licenses = {
            'MIT', 'Apache Software License', 'Apache-2.0', 'BSD', 'BSD-2-Clause',
            'BSD-3-Clause', 'ISC', 'Mozilla Public License 2.0 (MPL 2.0)'
        }
        
        # Risky licenses that require review
        risky_licenses = {
            'GNU General Public License (GPL)', 'GPL-2.0', 'GPL-3.0',
            'GNU Affero General Public License v3 (AGPLv3)', 'AGPL-3.0'
        }
        
        try:
            # Get license information using pip-licenses
            result = subprocess.run(
                ['pip-licenses', '--format=json'],
                capture_output=True, text=True, timeout=120
            )
            
            if result.stdout:
                license_data = json.loads(result.stdout)
                
                for pkg in license_data:
                    name = pkg.get('Name', '').lower()
                    license_name = pkg.get('License', 'Unknown')
                    
                    licenses[name] = {
                        'name': license_name,
                        'version': pkg.get('Version', ''),
                        'status': self._classify_license(license_name, approved_licenses, risky_licenses)
                    }
                    
                    # Update summary
                    if license_name not in license_summary['by_license']:
                        license_summary['by_license'][license_name] = []
                    license_summary['by_license'][license_name].append(name)
                    
                    if license_name == 'Unknown':
                        license_summary['unknown'].append(name)
                    elif license_name in risky_licenses:
                        license_summary['risky'].append(name)
                    elif license_name in approved_licenses:
                        license_summary['approved'].append(name)
        
        except subprocess.TimeoutExpired:
            self.logger.warning("License scan timed out")
        except FileNotFoundError:
            self.logger.info("pip-licenses tool not found, skipping license scan")
        except Exception as e:
            self.logger.error(f"Error scanning licenses: {e}")
        
        return {
            'packages': licenses,
            'summary': license_summary
        }
    
    def _classify_license(self, license_name: str, approved: Set[str], risky: Set[str]) -> str:
        """Classify license as approved, risky, or unknown."""
        if license_name in approved:
            return 'approved'
        elif license_name in risky:
            return 'risky'
        elif license_name == 'Unknown':
            return 'unknown'
        else:
            return 'review_required'
    
    def _check_outdated_packages(self, dependencies: Dict) -> List[Dict]:
        """Check for outdated packages."""
        self.logger.info("Checking for outdated packages")
        
        outdated_packages = []
        
        try:
            result = subprocess.run(
                ['pip', 'list', '--outdated', '--format=json'],
                capture_output=True, text=True, timeout=120
            )
            
            if result.stdout:
                outdated_data = json.loads(result.stdout)
                
                for pkg in outdated_data:
                    package_name = pkg.get('name', '').lower()
                    
                    # Calculate how outdated the package is
                    current_version = pkg.get('version', '')
                    latest_version = pkg.get('latest_version', '')
                    
                    outdated_packages.append({
                        'name': package_name,
                        'current_version': current_version,
                        'latest_version': latest_version,
                        'package_type': pkg.get('latest_filetype', ''),
                        'urgency': self._calculate_update_urgency(current_version, latest_version)
                    })
        
        except subprocess.TimeoutExpired:
            self.logger.warning("Outdated packages check timed out")
        except Exception as e:
            self.logger.error(f"Error checking outdated packages: {e}")
        
        return outdated_packages
    
    def _calculate_update_urgency(self, current: str, latest: str) -> str:
        """Calculate update urgency based on version difference."""
        try:
            from packaging import version
            
            current_v = version.parse(current)
            latest_v = version.parse(latest)
            
            if latest_v.major > current_v.major:
                return 'major'
            elif latest_v.minor > current_v.minor:
                return 'minor'
            elif latest_v.micro > current_v.micro:
                return 'patch'
            else:
                return 'none'
        
        except Exception:
            return 'unknown'
    
    def _analyze_dependency_tree(self, dependencies: Dict) -> Dict:
        """Analyze dependency tree structure."""
        self.logger.info("Analyzing dependency tree")
        
        tree_analysis = {
            'total_dependencies': len(dependencies),
            'direct_dependencies': 0,
            'transitive_dependencies': 0,
            'depth_analysis': {},
            'circular_dependencies': [],
            'large_packages': []
        }
        
        try:
            # Get dependency tree using pipdeptree
            result = subprocess.run(
                ['pipdeptree', '--json'],
                capture_output=True, text=True, timeout=120
            )
            
            if result.stdout:
                tree_data = json.loads(result.stdout)
                
                # Analyze tree structure
                for package in tree_data:
                    pkg_name = package.get('package_name', '').lower()
                    dependencies_list = package.get('dependencies', [])
                    
                    if pkg_name in dependencies:
                        tree_analysis['direct_dependencies'] += 1
                        
                        # Analyze depth
                        depth = self._calculate_dependency_depth(package, tree_data)
                        if depth not in tree_analysis['depth_analysis']:
                            tree_analysis['depth_analysis'][depth] = 0
                        tree_analysis['depth_analysis'][depth] += 1
                
                # Calculate transitive dependencies
                tree_analysis['transitive_dependencies'] = (
                    tree_analysis['total_dependencies'] - tree_analysis['direct_dependencies']
                )
        
        except subprocess.TimeoutExpired:
            self.logger.warning("Dependency tree analysis timed out")
        except FileNotFoundError:
            self.logger.info("pipdeptree tool not found, skipping tree analysis")
        except Exception as e:
            self.logger.error(f"Error analyzing dependency tree: {e}")
        
        return tree_analysis
    
    def _calculate_dependency_depth(self, package: Dict, tree_data: List[Dict]) -> int:
        """Calculate the dependency depth for a package."""
        # Simple implementation - could be enhanced
        dependencies = package.get('dependencies', [])
        if not dependencies:
            return 0
        
        max_depth = 0
        for dep in dependencies:
            dep_name = dep.get('package_name', '').lower()
            # Find dependency in tree
            for pkg in tree_data:
                if pkg.get('package_name', '').lower() == dep_name:
                    depth = 1 + self._calculate_dependency_depth(pkg, tree_data)
                    max_depth = max(max_depth, depth)
                    break
        
        return max_depth
    
    def _calculate_metrics(self) -> Dict:
        """Calculate various metrics from scan results."""
        metrics = {
            'security': {
                'vulnerability_count': len(self.scan_results['vulnerabilities']),
                'critical_vulnerabilities': len([
                    v for v in self.scan_results['vulnerabilities']
                    if v.get('severity', '').lower() in ['critical', 'high']
                ]),
                'security_score': 0
            },
            'compliance': {
                'license_compliance_score': 0,
                'risky_licenses': len(self.scan_results['licenses'].get('summary', {}).get('risky', [])),
                'unknown_licenses': len(self.scan_results['licenses'].get('summary', {}).get('unknown', []))
            },
            'maintenance': {
                'outdated_count': len(self.scan_results['outdated']),
                'major_updates_available': len([
                    pkg for pkg in self.scan_results['outdated']
                    if pkg.get('urgency') == 'major'
                ]),
                'maintenance_score': 0
            },
            'overall': {
                'risk_score': 0,
                'health_score': 0
            }
        }
        
        # Calculate security score (0-100, higher is better)
        total_deps = len(self.scan_results['dependencies'])
        if total_deps > 0:
            vuln_ratio = metrics['security']['vulnerability_count'] / total_deps
            metrics['security']['security_score'] = max(0, 100 - (vuln_ratio * 100))
        else:
            metrics['security']['security_score'] = 100
        
        # Calculate license compliance score
        total_licenses = len(self.scan_results['licenses'].get('packages', {}))
        if total_licenses > 0:
            risky_ratio = metrics['compliance']['risky_licenses'] / total_licenses
            unknown_ratio = metrics['compliance']['unknown_licenses'] / total_licenses
            metrics['compliance']['license_compliance_score'] = max(
                0, 100 - ((risky_ratio + unknown_ratio) * 100)
            )
        else:
            metrics['compliance']['license_compliance_score'] = 100
        
        # Calculate maintenance score
        if total_deps > 0:
            outdated_ratio = metrics['maintenance']['outdated_count'] / total_deps
            metrics['maintenance']['maintenance_score'] = max(0, 100 - (outdated_ratio * 50))
        else:
            metrics['maintenance']['maintenance_score'] = 100
        
        # Calculate overall scores
        metrics['overall']['risk_score'] = (
            (100 - metrics['security']['security_score']) * 0.5 +
            (100 - metrics['compliance']['license_compliance_score']) * 0.3 +
            (100 - metrics['maintenance']['maintenance_score']) * 0.2
        )
        
        metrics['overall']['health_score'] = 100 - metrics['overall']['risk_score']
        
        return metrics
    
    def _generate_recommendations(self) -> List[Dict]:
        """Generate actionable recommendations based on scan results."""
        recommendations = []
        
        # Security recommendations
        critical_vulns = [
            v for v in self.scan_results['vulnerabilities']
            if v.get('severity', '').lower() in ['critical', 'high']
        ]
        
        if critical_vulns:
            recommendations.append({
                'type': 'security',
                'priority': 'high',
                'title': 'Address Critical Security Vulnerabilities',
                'description': f'Found {len(critical_vulns)} critical/high severity vulnerabilities',
                'action': 'Update vulnerable packages immediately',
                'packages': [v['package'] for v in critical_vulns]
            })
        
        # License recommendations
        risky_licenses = self.scan_results['licenses'].get('summary', {}).get('risky', [])
        if risky_licenses:
            recommendations.append({
                'type': 'compliance',
                'priority': 'medium',
                'title': 'Review Risky License Dependencies',
                'description': f'Found {len(risky_licenses)} packages with risky licenses',
                'action': 'Review and potentially replace packages with risky licenses',
                'packages': risky_licenses
            })
        
        # Maintenance recommendations
        major_updates = [
            pkg for pkg in self.scan_results['outdated']
            if pkg.get('urgency') == 'major'
        ]
        
        if major_updates:
            recommendations.append({
                'type': 'maintenance',
                'priority': 'low',
                'title': 'Consider Major Version Updates',
                'description': f'Found {len(major_updates)} packages with major updates available',
                'action': 'Plan and test major version updates',
                'packages': [pkg['name'] for pkg in major_updates]
            })
        
        # Dependency management recommendations
        total_deps = len(self.scan_results['dependencies'])
        if total_deps > 100:
            recommendations.append({
                'type': 'architecture',
                'priority': 'low',
                'title': 'Consider Dependency Reduction',
                'description': f'Project has {total_deps} dependencies',
                'action': 'Review and potentially reduce dependency count',
                'packages': []
            })
        
        return recommendations
    
    def save_results(self, output_file: str):
        """Save scan results to file."""
        with open(output_file, 'w') as f:
            json.dump(self.scan_results, f, indent=2, default=str)
        
        self.logger.info(f"Scan results saved to {output_file}")
    
    def generate_report(self) -> str:
        """Generate human-readable report."""
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        
        report = f"""# Dependency Security and Compliance Report

Generated: {timestamp}
Project: {self.scan_results['project_root']}

## Summary

- **Total Dependencies**: {len(self.scan_results['dependencies'])}
- **Security Vulnerabilities**: {len(self.scan_results['vulnerabilities'])}
- **Outdated Packages**: {len(self.scan_results['outdated'])}
- **License Issues**: {len(self.scan_results['licenses'].get('summary', {}).get('risky', []))}

## Security Analysis

"""
        
        vulnerabilities = self.scan_results['vulnerabilities']
        if vulnerabilities:
            report += "### 🚨 Security Vulnerabilities\n\n"
            
            # Group by severity
            by_severity = {}
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'unknown').lower()
                if severity not in by_severity:
                    by_severity[severity] = []
                by_severity[severity].append(vuln)
            
            for severity in ['critical', 'high', 'medium', 'low', 'unknown']:
                if severity in by_severity:
                    report += f"**{severity.title()}**: {len(by_severity[severity])}\n"
                    for vuln in by_severity[severity][:5]:  # Show first 5
                        report += f"- {vuln['package']}: {vuln.get('title', vuln.get('id', 'Unknown'))}\n"
                    if len(by_severity[severity]) > 5:
                        report += f"- ... and {len(by_severity[severity]) - 5} more\n"
                    report += "\n"
        else:
            report += "✅ No security vulnerabilities found.\n\n"
        
        # License compliance
        license_summary = self.scan_results['licenses'].get('summary', {})
        report += "## License Compliance\n\n"
        
        if license_summary.get('risky'):
            report += f"⚠️  **Risky Licenses**: {len(license_summary['risky'])}\n"
            for pkg in license_summary['risky'][:10]:
                license_info = self.scan_results['licenses']['packages'].get(pkg, {})
                report += f"- {pkg}: {license_info.get('name', 'Unknown')}\n"
            report += "\n"
        
        if license_summary.get('unknown'):
            report += f"❓ **Unknown Licenses**: {len(license_summary['unknown'])}\n"
            for pkg in license_summary['unknown'][:10]:
                report += f"- {pkg}\n"
            report += "\n"
        
        # Outdated packages
        outdated = self.scan_results['outdated']
        if outdated:
            report += "## Maintenance\n\n"
            report += f"📦 **Outdated Packages**: {len(outdated)}\n\n"
            
            # Group by urgency
            by_urgency = {}
            for pkg in outdated:
                urgency = pkg.get('urgency', 'unknown')
                if urgency not in by_urgency:
                    by_urgency[urgency] = []
                by_urgency[urgency].append(pkg)
            
            for urgency in ['major', 'minor', 'patch']:
                if urgency in by_urgency:
                    report += f"**{urgency.title()} Updates**: {len(by_urgency[urgency])}\n"
                    for pkg in by_urgency[urgency][:5]:
                        report += f"- {pkg['name']}: {pkg['current_version']} → {pkg['latest_version']}\n"
                    if len(by_urgency[urgency]) > 5:
                        report += f"- ... and {len(by_urgency[urgency]) - 5} more\n"
                    report += "\n"
        
        # Recommendations
        recommendations = self.scan_results['recommendations']
        if recommendations:
            report += "## Recommendations\n\n"
            
            for rec in recommendations:
                priority_emoji = {'high': '🔴', 'medium': '🟡', 'low': '🟢'}.get(rec['priority'], '⚪')
                report += f"{priority_emoji} **{rec['title']}** ({rec['priority']} priority)\n"
                report += f"{rec['description']}\n"
                report += f"*Action*: {rec['action']}\n\n"
        
        # Metrics
        metrics = self.scan_results.get('metrics', {})
        if metrics:
            report += "## Scores\n\n"
            report += f"- **Security Score**: {metrics.get('security', {}).get('security_score', 0):.1f}/100\n"
            report += f"- **License Compliance**: {metrics.get('compliance', {}).get('license_compliance_score', 0):.1f}/100\n"
            report += f"- **Maintenance Score**: {metrics.get('maintenance', {}).get('maintenance_score', 0):.1f}/100\n"
            report += f"- **Overall Health**: {metrics.get('overall', {}).get('health_score', 0):.1f}/100\n"
        
        return report


def main():
    """Main entry point for dependency scanner."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Comprehensive dependency security scanner')
    parser.add_argument('--project-root', default='.',
                       help='Path to project root directory')
    parser.add_argument('--output', default='dependency-scan-results.json',
                       help='Output file for scan results')
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
    
    # Run scanner
    scanner = DependencyScanner(args.project_root)
    
    try:
        results = scanner.scan_all_dependencies()
        scanner.save_results(args.output)
        
        if args.report:
            report = scanner.generate_report()
            print(report)
            
            # Save report to file
            report_file = args.output.replace('.json', '-report.md')
            with open(report_file, 'w') as f:
                f.write(report)
            print(f"\n📄 Report saved to: {report_file}")
        
        # Exit with appropriate code based on findings
        vulnerabilities = len(results['vulnerabilities'])
        critical_vulns = len([
            v for v in results['vulnerabilities']
            if v.get('severity', '').lower() in ['critical', 'high']
        ])
        
        if critical_vulns > 0:
            print(f"\n❌ {critical_vulns} critical/high severity vulnerabilities found")
            sys.exit(2)
        elif vulnerabilities > 0:
            print(f"\n⚠️  {vulnerabilities} vulnerabilities found")
            sys.exit(1)
        else:
            print("\n✅ No security vulnerabilities found")
            sys.exit(0)
    
    except Exception as e:
        print(f"❌ Error during dependency scan: {e}")
        sys.exit(3)


if __name__ == '__main__':
    main()