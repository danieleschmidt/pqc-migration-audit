"""Cryptographic inventory and SBOM management service."""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
import yaml

from ..core import ScanResults
from ..models import CryptoInventoryItem, SBOMCryptoComponent


class CryptoInventoryService:
    """Service for managing cryptographic inventory and SBOM generation."""
    
    def __init__(self):
        """Initialize inventory service."""
        self.inventory_items: List[CryptoInventoryItem] = []
        self.sbom_components: List[SBOMCryptoComponent] = []
    
    def generate_crypto_inventory(self, results: ScanResults) -> Dict[str, Any]:
        """Generate comprehensive cryptographic inventory.
        
        Args:
            results: Scan results containing vulnerabilities
            
        Returns:
            Cryptographic inventory report
        """
        # Create inventory items from scan results
        inventory_items = self._create_inventory_from_scan(results)
        
        # Analyze dependencies
        dependencies = self._analyze_crypto_dependencies(results.scan_path)
        
        # Generate summary statistics
        summary = self._generate_inventory_summary(inventory_items, dependencies)
        
        inventory = {
            "metadata": {
                "generated_date": datetime.now().isoformat(),
                "scan_path": results.scan_path,
                "total_files_scanned": results.scanned_files,
                "languages_detected": results.languages_detected
            },
            "summary": summary,
            "cryptographic_implementations": [
                self._inventory_item_to_dict(item) for item in inventory_items
            ],
            "dependencies": dependencies,
            "risk_assessment": self._assess_inventory_risk(inventory_items),
            "recommendations": self._generate_inventory_recommendations(inventory_items)
        }
        
        return inventory
    
    def generate_sbom(self, results: ScanResults, format: str = "cyclonedx") -> Dict[str, Any]:
        """Generate Software Bill of Materials with crypto focus.
        
        Args:
            results: Scan results
            format: SBOM format (cyclonedx, spdx)
            
        Returns:
            SBOM data structure
        """
        if format.lower() == "cyclonedx":
            return self._generate_cyclonedx_sbom(results)
        elif format.lower() == "spdx":
            return self._generate_spdx_sbom(results)
        else:
            raise ValueError(f"Unsupported SBOM format: {format}")
    
    def _create_inventory_from_scan(self, results: ScanResults) -> List[CryptoInventoryItem]:
        """Create inventory items from scan results."""
        inventory_items = []
        
        # Group vulnerabilities by file
        files_with_crypto = {}
        for vuln in results.vulnerabilities:
            if vuln.file_path not in files_with_crypto:
                files_with_crypto[vuln.file_path] = []
            files_with_crypto[vuln.file_path].append(vuln)
        
        # Create inventory items
        for file_path, vulns in files_with_crypto.items():
            algorithms = list(set(v.algorithm.value for v in vulns))
            key_sizes = [v.key_size for v in vulns if v.key_size is not None]
            
            # Determine usage context
            usage_context = self._determine_usage_context(file_path, vulns)
            
            # Determine migration priority
            max_severity = max(v.severity for v in vulns)
            priority_map = {
                "critical": "critical",
                "high": "high", 
                "medium": "medium",
                "low": "low"
            }
            migration_priority = priority_map.get(max_severity.value, "medium")
            
            item = CryptoInventoryItem(
                name=Path(file_path).name,
                version="unknown",  # Could be enhanced to detect version
                location=file_path,
                algorithms=algorithms,
                key_sizes=key_sizes,
                usage_context=usage_context,
                pqc_ready=False,  # All items from scan are vulnerable
                migration_priority=migration_priority,
                last_updated=datetime.now().isoformat()
            )
            
            inventory_items.append(item)
        
        return inventory_items
    
    def _determine_usage_context(self, file_path: str, vulnerabilities) -> str:
        """Determine the usage context of cryptographic implementation."""
        path_lower = file_path.lower()
        
        if any(keyword in path_lower for keyword in ['auth', 'login', 'security']):
            return "authentication"
        elif any(keyword in path_lower for keyword in ['tls', 'ssl', 'https']):
            return "transport_security"
        elif any(keyword in path_lower for keyword in ['cert', 'certificate', 'x509']):
            return "certificate_management"
        elif any(keyword in path_lower for keyword in ['sign', 'signature']):
            return "digital_signatures"
        elif any(keyword in path_lower for keyword in ['encrypt', 'decrypt', 'cipher']):
            return "data_encryption"
        elif any(keyword in path_lower for keyword in ['key', 'keygen']):
            return "key_management"
        elif any(keyword in path_lower for keyword in ['api', 'service', 'server']):
            return "api_security"
        elif any(keyword in path_lower for keyword in ['database', 'db', 'storage']):
            return "data_at_rest"
        else:
            return "general_cryptography"
    
    def _analyze_crypto_dependencies(self, scan_path: str) -> Dict[str, Any]:
        """Analyze cryptographic dependencies in the project."""
        dependencies = {
            "package_managers": {},
            "crypto_libraries": [],
            "vulnerable_versions": []
        }
        
        try:
            # Python dependencies
            requirements_file = Path(scan_path) / "requirements.txt"
            if requirements_file.exists():
                python_deps = self._parse_python_requirements(requirements_file)
                dependencies["package_managers"]["python"] = python_deps
                dependencies["crypto_libraries"].extend(
                    self._identify_crypto_libraries(python_deps, "python")
                )
            
            # Node.js dependencies
            package_json = Path(scan_path) / "package.json"
            if package_json.exists():
                npm_deps = self._parse_package_json(package_json)
                dependencies["package_managers"]["npm"] = npm_deps
                dependencies["crypto_libraries"].extend(
                    self._identify_crypto_libraries(npm_deps, "javascript")
                )
            
            # Go dependencies
            go_mod = Path(scan_path) / "go.mod"
            if go_mod.exists():
                go_deps = self._parse_go_mod(go_mod)
                dependencies["package_managers"]["go"] = go_deps
                dependencies["crypto_libraries"].extend(
                    self._identify_crypto_libraries(go_deps, "go")
                )
                
        except Exception as e:
            # Continue even if dependency analysis fails
            pass
        
        return dependencies
    
    def _parse_python_requirements(self, requirements_file: Path) -> List[Dict[str, str]]:
        """Parse Python requirements.txt file."""
        dependencies = []
        
        try:
            with open(requirements_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Simple parsing - could be enhanced
                        if '==' in line:
                            name, version = line.split('==', 1)
                            dependencies.append({"name": name.strip(), "version": version.strip()})
                        elif '>=' in line:
                            name, version = line.split('>=', 1)
                            dependencies.append({"name": name.strip(), "version": f">={version.strip()}"})
                        else:
                            dependencies.append({"name": line, "version": "latest"})
        except Exception:
            pass
            
        return dependencies
    
    def _parse_package_json(self, package_json: Path) -> List[Dict[str, str]]:
        """Parse Node.js package.json file."""
        dependencies = []
        
        try:
            with open(package_json, 'r') as f:
                data = json.load(f)
                
            for dep_type in ['dependencies', 'devDependencies']:
                if dep_type in data:
                    for name, version in data[dep_type].items():
                        dependencies.append({"name": name, "version": version})
        except Exception:
            pass
            
        return dependencies
    
    def _parse_go_mod(self, go_mod: Path) -> List[Dict[str, str]]:
        """Parse Go go.mod file."""
        dependencies = []
        
        try:
            with open(go_mod, 'r') as f:
                content = f.read()
                
            # Simple parsing for require section
            in_require = False
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith('require ('):
                    in_require = True
                    continue
                elif line == ')' and in_require:
                    in_require = False
                    continue
                elif in_require and line:
                    parts = line.split()
                    if len(parts) >= 2:
                        name = parts[0]
                        version = parts[1]
                        dependencies.append({"name": name, "version": version})
        except Exception:
            pass
            
        return dependencies
    
    def _identify_crypto_libraries(self, dependencies: List[Dict[str, str]], 
                                  language: str) -> List[Dict[str, Any]]:
        """Identify cryptographic libraries from dependencies."""
        crypto_libs = []
        
        # Known cryptographic libraries by language
        crypto_library_patterns = {
            "python": [
                "cryptography", "pycrypto", "pycryptodome", "pyopenssl",
                "hashlib", "ssl", "hmac", "secrets"
            ],
            "javascript": [
                "crypto", "node-forge", "crypto-js", "bcrypt", "jsonwebtoken",
                "elliptic", "jsrsasign"
            ],
            "go": [
                "crypto/", "golang.org/x/crypto", "github.com/cloudflare/circl"
            ]
        }
        
        patterns = crypto_library_patterns.get(language, [])
        
        for dep in dependencies:
            dep_name = dep["name"].lower()
            if any(pattern in dep_name for pattern in patterns):
                crypto_libs.append({
                    "name": dep["name"],
                    "version": dep["version"],
                    "language": language,
                    "quantum_vulnerable": self._is_library_quantum_vulnerable(dep["name"]),
                    "pqc_alternatives": self._get_pqc_alternatives(dep["name"])
                })
        
        return crypto_libs
    
    def _is_library_quantum_vulnerable(self, library_name: str) -> bool:
        """Check if a library contains quantum-vulnerable algorithms."""
        # Most traditional crypto libraries are quantum-vulnerable
        vulnerable_libs = [
            "cryptography", "pycrypto", "pycryptodome", "pyopenssl",
            "crypto-js", "node-forge", "elliptic", "jsrsasign"
        ]
        
        return any(lib in library_name.lower() for lib in vulnerable_libs)
    
    def _get_pqc_alternatives(self, library_name: str) -> List[str]:
        """Get PQC alternatives for a library."""
        alternatives_map = {
            "cryptography": ["pqcrypto", "liboqs-python"],
            "pycrypto": ["pqcrypto"],
            "pycryptodome": ["pqcrypto"],
            "crypto-js": ["post-quantum-crypto"],
            "node-forge": ["pqc-js"],
            "elliptic": ["kyber-js", "dilithium-js"]
        }
        
        for lib, alternatives in alternatives_map.items():
            if lib in library_name.lower():
                return alternatives
        
        return ["liboqs"]  # Default PQC library
    
    def _generate_inventory_summary(self, inventory_items: List[CryptoInventoryItem],
                                  dependencies: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary statistics for inventory."""
        
        # Algorithm distribution
        all_algorithms = []
        for item in inventory_items:
            all_algorithms.extend(item.algorithms)
        
        algorithm_counts = {}
        for algo in all_algorithms:
            algorithm_counts[algo] = algorithm_counts.get(algo, 0) + 1
        
        # Priority distribution
        priority_counts = {}
        for item in inventory_items:
            priority_counts[item.migration_priority] = priority_counts.get(item.migration_priority, 0) + 1
        
        # Context distribution
        context_counts = {}
        for item in inventory_items:
            context_counts[item.usage_context] = context_counts.get(item.usage_context, 0) + 1
        
        return {
            "total_crypto_implementations": len(inventory_items),
            "algorithm_distribution": algorithm_counts,
            "priority_distribution": priority_counts,
            "context_distribution": context_counts,
            "crypto_libraries_found": len(dependencies.get("crypto_libraries", [])),
            "pqc_ready_percentage": 0.0  # All scanned items are vulnerable
        }
    
    def _assess_inventory_risk(self, inventory_items: List[CryptoInventoryItem]) -> Dict[str, Any]:
        """Assess risk level of cryptographic inventory."""
        
        risk_factors = []
        
        # High-risk contexts
        high_risk_contexts = ["authentication", "transport_security", "api_security"]
        high_risk_items = [
            item for item in inventory_items 
            if item.usage_context in high_risk_contexts
        ]
        
        if high_risk_items:
            risk_factors.append(f"{len(high_risk_items)} implementations in high-risk contexts")
        
        # Critical priority items
        critical_items = [
            item for item in inventory_items 
            if item.migration_priority == "critical"
        ]
        
        if critical_items:
            risk_factors.append(f"{len(critical_items)} critical priority items")
        
        # Calculate overall risk level
        if len(critical_items) > 0 or len(high_risk_items) > len(inventory_items) * 0.5:
            risk_level = "HIGH"
        elif len(high_risk_items) > 0:
            risk_level = "MEDIUM" 
        else:
            risk_level = "LOW"
        
        return {
            "overall_risk_level": risk_level,
            "risk_factors": risk_factors,
            "high_risk_implementations": len(high_risk_items),
            "critical_priority_items": len(critical_items)
        }
    
    def _generate_inventory_recommendations(self, inventory_items: List[CryptoInventoryItem]) -> List[str]:
        """Generate recommendations based on inventory analysis."""
        recommendations = []
        
        # Priority-based recommendations
        critical_items = [item for item in inventory_items if item.migration_priority == "critical"]
        if critical_items:
            recommendations.append(f"Immediately address {len(critical_items)} critical priority implementations")
        
        # Context-based recommendations
        auth_items = [item for item in inventory_items if item.usage_context == "authentication"]
        if auth_items:
            recommendations.append(f"Prioritize {len(auth_items)} authentication-related implementations")
        
        tls_items = [item for item in inventory_items if item.usage_context == "transport_security"]
        if tls_items:
            recommendations.append(f"Plan TLS/transport security migration for {len(tls_items)} implementations")
        
        # General recommendations
        recommendations.extend([
            "Establish crypto-agility framework for future algorithm transitions",
            "Implement regular cryptographic inventory scanning",
            "Train development teams on post-quantum cryptography",
            "Create migration timeline with quarterly milestones"
        ])
        
        return recommendations
    
    def _generate_cyclonedx_sbom(self, results: ScanResults) -> Dict[str, Any]:
        """Generate CycloneDX format SBOM."""
        
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "tools": [
                    {
                        "vendor": "Terragon Labs",
                        "name": "pqc-migration-audit",
                        "version": "0.1.0"
                    }
                ],
                "component": {
                    "type": "application",
                    "bom-ref": "main-component",
                    "name": Path(results.scan_path).name,
                    "version": "1.0.0"
                }
            },
            "components": []
        }
        
        # Add cryptographic components
        crypto_components = self._extract_crypto_components(results)
        
        for comp in crypto_components:
            component = {
                "type": "library",
                "bom-ref": f"crypto-{comp.component_name}",
                "name": comp.component_name,
                "version": comp.version,
                "supplier": {
                    "name": comp.supplier
                },
                "properties": [
                    {
                        "name": "quantum_vulnerable",
                        "value": str(comp.quantum_vulnerable).lower()
                    },
                    {
                        "name": "algorithms_used",
                        "value": ", ".join(comp.algorithms_used)
                    }
                ]
            }
            
            if comp.pqc_alternatives:
                component["properties"].append({
                    "name": "pqc_alternatives",
                    "value": ", ".join(comp.pqc_alternatives)
                })
            
            sbom["components"].append(component)
        
        return sbom
    
    def _generate_spdx_sbom(self, results: ScanResults) -> Dict[str, Any]:
        """Generate SPDX format SBOM."""
        
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"PQC-Audit-{Path(results.scan_path).name}",
            "documentNamespace": f"https://pqc-audit.example.com/{uuid.uuid4()}",
            "creators": [
                "Tool: pqc-migration-audit-0.1.0"
            ],
            "created": datetime.now().isoformat(),
            "packages": []
        }
        
        # Add cryptographic packages
        crypto_components = self._extract_crypto_components(results)
        
        for comp in crypto_components:
            package = {
                "SPDXID": f"SPDXRef-{comp.component_name}",
                "name": comp.component_name,
                "versionInfo": comp.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "supplier": f"Organization: {comp.supplier}",
                "annotations": [
                    {
                        "annotationType": "REVIEW",
                        "annotator": "Tool: pqc-migration-audit",
                        "annotationDate": datetime.now().isoformat(),
                        "annotationComment": f"Quantum vulnerable: {comp.quantum_vulnerable}. Algorithms: {', '.join(comp.algorithms_used)}"
                    }
                ]
            }
            
            sbom["packages"].append(package)
        
        return sbom
    
    def _extract_crypto_components(self, results: ScanResults) -> List[SBOMCryptoComponent]:
        """Extract cryptographic components for SBOM."""
        components = []
        
        # Group by algorithms and create components
        algorithm_files = {}
        for vuln in results.vulnerabilities:
            algo = vuln.algorithm.value
            if algo not in algorithm_files:
                algorithm_files[algo] = []
            algorithm_files[algo].append(vuln.file_path)
        
        for algo, files in algorithm_files.items():
            comp = SBOMCryptoComponent(
                component_name=f"crypto-{algo.lower()}",
                version="unknown",
                supplier="Internal Implementation",
                algorithms_used=[algo],
                quantum_vulnerable=True,
                pqc_alternatives=self._get_pqc_alternatives_for_algorithm(algo),
                license="NOASSERTION"
            )
            components.append(comp)
        
        return components
    
    def _get_pqc_alternatives_for_algorithm(self, algorithm: str) -> List[str]:
        """Get PQC alternatives for a specific algorithm."""
        alternatives_map = {
            "RSA": ["ML-KEM-768", "ML-DSA-65"],
            "ECC": ["ML-DSA-65"],
            "ECDSA": ["ML-DSA-65"],
            "DSA": ["ML-DSA-44"],
            "DH": ["ML-KEM-768"],
            "ECDH": ["ML-KEM-768"]
        }
        
        return alternatives_map.get(algorithm, ["ML-KEM-768"])
    
    def _inventory_item_to_dict(self, item: CryptoInventoryItem) -> Dict[str, Any]:
        """Convert inventory item to dictionary."""
        return {
            "name": item.name,
            "version": item.version,
            "location": item.location,
            "algorithms": item.algorithms,
            "key_sizes": item.key_sizes,
            "usage_context": item.usage_context,
            "pqc_ready": item.pqc_ready,
            "migration_priority": item.migration_priority,
            "last_updated": item.last_updated
        }
    
    def export_inventory(self, inventory: Dict[str, Any], output_path: Path, 
                        format: str = "json") -> None:
        """Export inventory to file.
        
        Args:
            inventory: Inventory data
            output_path: Output file path
            format: Export format (json, yaml, csv)
        """
        if format.lower() == "json":
            with open(output_path, 'w') as f:
                json.dump(inventory, f, indent=2)
        elif format.lower() == "yaml":
            with open(output_path, 'w') as f:
                yaml.dump(inventory, f, default_flow_style=False)
        elif format.lower() == "csv":
            self._export_inventory_csv(inventory, output_path)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def _export_inventory_csv(self, inventory: Dict[str, Any], output_path: Path) -> None:
        """Export inventory to CSV format."""
        import csv
        
        implementations = inventory.get("cryptographic_implementations", [])
        
        with open(output_path, 'w', newline='') as csvfile:
            fieldnames = [
                'name', 'location', 'algorithms', 'usage_context', 
                'migration_priority', 'pqc_ready'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for impl in implementations:
                row = {
                    'name': impl['name'],
                    'location': impl['location'],
                    'algorithms': '; '.join(impl['algorithms']),
                    'usage_context': impl['usage_context'],
                    'migration_priority': impl['migration_priority'],
                    'pqc_ready': impl['pqc_ready']
                }
                writer.writerow(row)