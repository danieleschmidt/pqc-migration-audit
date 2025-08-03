"""Migration planning and strategy service."""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json

from ..core import ScanResults, Vulnerability, Severity, CryptoAlgorithm
from ..models import (
    MigrationStrategy, PQCAlgorithm, MigrationRecommendation,
    PerformanceMetrics
)


class MigrationService:
    """Service for planning and managing PQC migrations."""
    
    def __init__(self):
        """Initialize migration service."""
        self.algorithm_mappings = self._init_algorithm_mappings()
        self.performance_profiles = self._init_performance_profiles()
    
    def create_migration_roadmap(self, results: ScanResults, 
                                target_date: Optional[str] = None,
                                strategy: MigrationStrategy = MigrationStrategy.HYBRID) -> Dict[str, Any]:
        """Create comprehensive migration roadmap.
        
        Args:
            results: Scan results containing vulnerabilities
            target_date: Target completion date (ISO format)
            strategy: Migration strategy to use
            
        Returns:
            Detailed migration roadmap
        """
        if not target_date:
            # Default to 18 months from now
            target_date = (datetime.now() + timedelta(days=547)).isoformat()[:10]
        
        # Analyze vulnerabilities and create recommendations
        recommendations = self._create_migration_recommendations(results.vulnerabilities, strategy)
        
        # Create timeline
        timeline = self._create_migration_timeline(recommendations, target_date)
        
        # Calculate resource requirements
        resources = self._calculate_resource_requirements(recommendations)
        
        # Identify dependencies and risks
        dependencies = self._analyze_dependencies(recommendations)
        risks = self._assess_migration_risks(results.vulnerabilities, strategy)
        
        roadmap = {
            "metadata": {
                "created_date": datetime.now().isoformat(),
                "target_completion": target_date,
                "strategy": strategy.value,
                "total_vulnerabilities": len(results.vulnerabilities)
            },
            "executive_summary": {
                "total_effort_hours": sum(r.estimated_effort_hours for r in recommendations),
                "high_priority_items": len([r for r in recommendations if r.priority >= 8]),
                "estimated_cost_range": self._estimate_migration_cost(recommendations),
                "key_milestones": timeline.get("milestones", [])
            },
            "recommendations": [self._recommendation_to_dict(r) for r in recommendations],
            "timeline": timeline,
            "resource_requirements": resources,
            "dependencies": dependencies,
            "risk_assessment": risks,
            "success_metrics": self._define_success_metrics()
        }
        
        return roadmap
    
    def _create_migration_recommendations(self, vulnerabilities: List[Vulnerability],
                                        strategy: MigrationStrategy) -> List[MigrationRecommendation]:
        """Create specific migration recommendations for each vulnerability."""
        recommendations = []
        
        for i, vuln in enumerate(vulnerabilities):
            # Determine recommended PQC algorithm
            pqc_algo = self._recommend_pqc_algorithm(vuln.algorithm, vuln.key_size)
            
            # Calculate priority based on severity and context
            priority = self._calculate_priority(vuln, strategy)
            
            # Estimate effort
            effort_hours = self._estimate_effort(vuln, strategy)
            
            # Generate code example
            code_example = self._generate_code_example(vuln, pqc_algo)
            
            recommendation = MigrationRecommendation(
                vulnerability_id=f"vuln_{i+1}",
                current_algorithm=vuln.algorithm.value,
                recommended_algorithm=pqc_algo,
                strategy=strategy,
                priority=priority,
                estimated_effort_hours=effort_hours,
                dependencies=self._identify_dependencies(vuln),
                notes=self._generate_migration_notes(vuln, pqc_algo),
                code_example=code_example
            )
            
            recommendations.append(recommendation)
        
        # Sort by priority (highest first)
        return sorted(recommendations, key=lambda r: r.priority, reverse=True)
    
    def _recommend_pqc_algorithm(self, current_algo: CryptoAlgorithm, 
                                key_size: Optional[int]) -> PQCAlgorithm:
        """Recommend appropriate PQC algorithm based on current usage."""
        
        # Key exchange / encryption algorithms
        if current_algo in [CryptoAlgorithm.RSA, CryptoAlgorithm.DH, CryptoAlgorithm.ECDH]:
            if key_size and key_size < 2048:
                return PQCAlgorithm.ML_KEM_512  # Lower security level
            elif key_size and key_size >= 4096:
                return PQCAlgorithm.ML_KEM_1024  # Higher security level
            else:
                return PQCAlgorithm.ML_KEM_768  # Standard level
        
        # Digital signature algorithms
        elif current_algo in [CryptoAlgorithm.DSA, CryptoAlgorithm.ECDSA, CryptoAlgorithm.ECC]:
            if key_size and key_size < 2048:
                return PQCAlgorithm.ML_DSA_44   # Lower security level
            elif key_size and key_size >= 4096:
                return PQCAlgorithm.ML_DSA_87   # Higher security level
            else:
                return PQCAlgorithm.ML_DSA_65   # Standard level
        
        # Default to standard level ML-KEM for unknown cases
        return PQCAlgorithm.ML_KEM_768
    
    def _calculate_priority(self, vuln: Vulnerability, strategy: MigrationStrategy) -> int:
        """Calculate migration priority (1-10, 10 being highest)."""
        base_priority = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 8,
            Severity.MEDIUM: 5,
            Severity.LOW: 3
        }.get(vuln.severity, 5)
        
        # Adjust based on algorithm risk
        algorithm_risk = {
            CryptoAlgorithm.ECC: 2,      # Higher risk (easier to break)
            CryptoAlgorithm.ECDSA: 2,
            CryptoAlgorithm.ECDH: 2,
            CryptoAlgorithm.RSA: 1,      # Standard risk
            CryptoAlgorithm.DSA: 1,
            CryptoAlgorithm.DH: 1
        }.get(vuln.algorithm, 0)
        
        # Adjust based on key size
        key_size_penalty = 0
        if vuln.key_size:
            if vuln.key_size < 1024:
                key_size_penalty = 3
            elif vuln.key_size < 2048:
                key_size_penalty = 2
            elif vuln.key_size < 4096:
                key_size_penalty = 1
        
        # Strategy adjustments
        strategy_multiplier = {
            MigrationStrategy.IMMEDIATE: 1.2,
            MigrationStrategy.HYBRID: 1.0,
            MigrationStrategy.GRADUAL: 0.8,
            MigrationStrategy.CUSTOM: 1.0
        }.get(strategy, 1.0)
        
        final_priority = min(10, int((base_priority + algorithm_risk + key_size_penalty) * strategy_multiplier))
        return max(1, final_priority)
    
    def _estimate_effort(self, vuln: Vulnerability, strategy: MigrationStrategy) -> int:
        """Estimate effort in hours for migrating a vulnerability."""
        
        # Base effort by algorithm complexity
        base_hours = {
            CryptoAlgorithm.RSA: 8,      # 1 day
            CryptoAlgorithm.ECC: 12,     # 1.5 days (more complex)
            CryptoAlgorithm.ECDSA: 10,   # 1.25 days
            CryptoAlgorithm.ECDH: 10,
            CryptoAlgorithm.DSA: 6,      # 0.75 days
            CryptoAlgorithm.DH: 8
        }.get(vuln.algorithm, 8)
        
        # Complexity multipliers
        if strategy == MigrationStrategy.HYBRID:
            base_hours = int(base_hours * 1.5)  # Hybrid implementation is more complex
        elif strategy == MigrationStrategy.IMMEDIATE:
            base_hours = int(base_hours * 1.2)  # Rush job penalty
        
        # Add testing and integration time (25%)
        total_hours = int(base_hours * 1.25)
        
        return total_hours
    
    def _identify_dependencies(self, vuln: Vulnerability) -> List[str]:
        """Identify dependencies for migrating a vulnerability."""
        dependencies = []
        
        # Library dependencies
        if vuln.algorithm in [CryptoAlgorithm.RSA, CryptoAlgorithm.ECC]:
            dependencies.append("liboqs integration")
            dependencies.append("PQC library installation")
        
        # Testing dependencies
        dependencies.append("Unit tests update")
        dependencies.append("Integration tests")
        
        # Infrastructure dependencies
        if "server" in vuln.file_path.lower() or "service" in vuln.file_path.lower():
            dependencies.append("Infrastructure compatibility check")
            dependencies.append("Performance testing")
        
        return dependencies
    
    def _generate_migration_notes(self, vuln: Vulnerability, pqc_algo: PQCAlgorithm) -> str:
        """Generate migration notes and considerations."""
        notes = []
        
        # Algorithm-specific notes
        if vuln.algorithm == CryptoAlgorithm.RSA:
            notes.append("RSA replacement requires careful consideration of key exchange vs. signature usage")
        elif vuln.algorithm in [CryptoAlgorithm.ECC, CryptoAlgorithm.ECDSA]:
            notes.append("ECC replacement has high priority due to quantum vulnerability")
        
        # PQC algorithm notes
        if pqc_algo in [PQCAlgorithm.ML_KEM_512, PQCAlgorithm.ML_KEM_768, PQCAlgorithm.ML_KEM_1024]:
            notes.append("ML-KEM (Kyber) is NIST standardized for key exchange")
        elif pqc_algo in [PQCAlgorithm.ML_DSA_44, PQCAlgorithm.ML_DSA_65, PQCAlgorithm.ML_DSA_87]:
            notes.append("ML-DSA (Dilithium) is NIST standardized for digital signatures")
        
        # Performance considerations
        notes.append("Consider performance impact and key size increases")
        notes.append("Plan gradual rollout with fallback mechanisms")
        
        return "; ".join(notes)
    
    def _generate_code_example(self, vuln: Vulnerability, pqc_algo: PQCAlgorithm) -> str:
        """Generate code example for migration."""
        
        if "python" in vuln.file_path.lower() or vuln.file_path.endswith('.py'):
            return self._generate_python_example(vuln, pqc_algo)
        elif "java" in vuln.file_path.lower() or vuln.file_path.endswith('.java'):
            return self._generate_java_example(vuln, pqc_algo)
        elif "go" in vuln.file_path.lower() or vuln.file_path.endswith('.go'):
            return self._generate_go_example(vuln, pqc_algo)
        else:
            return f"# Replace {vuln.algorithm.value} with {pqc_algo.value}"
    
    def _generate_python_example(self, vuln: Vulnerability, pqc_algo: PQCAlgorithm) -> str:
        """Generate Python migration example."""
        if pqc_algo in [PQCAlgorithm.ML_KEM_512, PQCAlgorithm.ML_KEM_768, PQCAlgorithm.ML_KEM_1024]:
            return f"""
# Before (quantum-vulnerable):
# {vuln.code_snippet}

# After (post-quantum secure):
from pqcrypto.kem.{pqc_algo.value.lower().replace('-', '_')} import generate_keypair, encapsulate, decapsulate

# Generate key pair
public_key, private_key = generate_keypair()

# Encapsulation (sender side)
ciphertext, shared_secret = encapsulate(public_key)

# Decapsulation (receiver side)
shared_secret = decapsulate(private_key, ciphertext)
"""
        else:  # ML-DSA algorithms
            return f"""
# Before (quantum-vulnerable):
# {vuln.code_snippet}

# After (post-quantum secure):
from pqcrypto.sign.{pqc_algo.value.lower().replace('-', '_')} import generate_keypair, sign, verify

# Generate key pair
public_key, private_key = generate_keypair()

# Signing
signature = sign(private_key, message)

# Verification
is_valid = verify(public_key, message, signature)
"""
    
    def _generate_java_example(self, vuln: Vulnerability, pqc_algo: PQCAlgorithm) -> str:
        """Generate Java migration example."""
        return f"""
// Before (quantum-vulnerable):
// {vuln.code_snippet}

// After (post-quantum secure):
import org.bouncycastle.pqc.crypto.*;

// Initialize {pqc_algo.value} key pair generator
KeyPairGenerator keyGen = KeyPairGenerator.getInstance("{pqc_algo.value}");
KeyPair keyPair = keyGen.generateKeyPair();

// Use generated keys for cryptographic operations
PublicKey publicKey = keyPair.getPublic();
PrivateKey privateKey = keyPair.getPrivate();
"""
    
    def _generate_go_example(self, vuln: Vulnerability, pqc_algo: PQCAlgorithm) -> str:
        """Generate Go migration example."""
        return f"""
// Before (quantum-vulnerable):
// {vuln.code_snippet}

// After (post-quantum secure):
import "github.com/cloudflare/circl/kem/{pqc_algo.value.lower()}"

// Generate key pair
publicKey, privateKey, err := {pqc_algo.value.lower()}.GenerateKeyPair()
if err != nil {{
    return err
}}

// Encapsulation/Decapsulation operations
ciphertext, sharedSecret, err := {pqc_algo.value.lower()}.Encapsulate(publicKey)
"""
    
    def _create_migration_timeline(self, recommendations: List[MigrationRecommendation],
                                 target_date: str) -> Dict[str, Any]:
        """Create migration timeline with phases and milestones."""
        
        # Calculate total effort
        total_hours = sum(r.estimated_effort_hours for r in recommendations)
        
        # Assuming 6 hours of migration work per day (part-time)
        total_days = total_hours // 6
        
        # Create phases based on priority
        high_priority = [r for r in recommendations if r.priority >= 8]
        medium_priority = [r for r in recommendations if 5 <= r.priority < 8]
        low_priority = [r for r in recommendations if r.priority < 5]
        
        phases = []
        
        if high_priority:
            phase1_hours = sum(r.estimated_effort_hours for r in high_priority)
            phases.append({
                "phase": 1,
                "name": "Critical Vulnerabilities",
                "description": "Address highest priority quantum-vulnerable implementations",
                "items": len(high_priority),
                "estimated_hours": phase1_hours,
                "estimated_days": phase1_hours // 6,
                "deliverables": [
                    "Critical crypto implementations migrated",
                    "Security testing completed",
                    "Documentation updated"
                ]
            })
        
        if medium_priority:
            phase2_hours = sum(r.estimated_effort_hours for r in medium_priority)
            phases.append({
                "phase": 2,
                "name": "Standard Migrations", 
                "description": "Migrate remaining high-impact implementations",
                "items": len(medium_priority),
                "estimated_hours": phase2_hours,
                "estimated_days": phase2_hours // 6,
                "deliverables": [
                    "Core systems migrated",
                    "Performance validation",
                    "Staff training completed"
                ]
            })
        
        if low_priority:
            phase3_hours = sum(r.estimated_effort_hours for r in low_priority)
            phases.append({
                "phase": 3,
                "name": "Cleanup and Optimization",
                "description": "Complete remaining migrations and optimize",
                "items": len(low_priority),
                "estimated_hours": phase3_hours,
                "estimated_days": phase3_hours // 6,
                "deliverables": [
                    "All migrations completed",
                    "Performance optimized",
                    "Monitoring established"
                ]
            })
        
        # Create milestones
        milestones = [
            {
                "name": "Project Kickoff",
                "description": "Project initiation and team setup",
                "target_date": datetime.now().isoformat()[:10]
            },
            {
                "name": "Phase 1 Complete",
                "description": "Critical vulnerabilities addressed",
                "target_date": (datetime.now() + timedelta(days=phases[0]["estimated_days"] if phases else 30)).isoformat()[:10]
            },
            {
                "name": "Migration Complete",
                "description": "All PQC migrations completed",
                "target_date": target_date
            }
        ]
        
        return {
            "phases": phases,
            "milestones": milestones,
            "total_estimated_hours": total_hours,
            "total_estimated_days": total_days,
            "target_completion": target_date
        }
    
    def _calculate_resource_requirements(self, recommendations: List[MigrationRecommendation]) -> Dict[str, Any]:
        """Calculate resource requirements for migration."""
        
        total_hours = sum(r.estimated_effort_hours for r in recommendations)
        
        # Assume different skill levels and hourly rates
        skill_requirements = {
            "senior_crypto_engineer": {
                "hours": int(total_hours * 0.4),  # 40% senior work
                "hourly_rate": 150,
                "description": "Cryptography expert for complex migrations"
            },
            "software_engineer": {
                "hours": int(total_hours * 0.5),  # 50% standard work
                "hourly_rate": 100,
                "description": "General software development and testing"
            },
            "security_tester": {
                "hours": int(total_hours * 0.1),  # 10% testing
                "hourly_rate": 120,
                "description": "Security testing and validation"
            }
        }
        
        # Calculate costs
        total_cost = sum(
            role["hours"] * role["hourly_rate"] 
            for role in skill_requirements.values()
        )
        
        # Additional costs
        additional_costs = {
            "training": 10000,  # PQC training for team
            "tools_and_licenses": 5000,  # Development tools
            "infrastructure": 15000,  # Testing infrastructure
            "consulting": 20000  # External expert consultation
        }
        
        total_additional = sum(additional_costs.values())
        
        return {
            "personnel": skill_requirements,
            "personnel_total_cost": total_cost,
            "additional_costs": additional_costs,
            "additional_total_cost": total_additional,
            "grand_total_cost": total_cost + total_additional,
            "cost_range": {
                "low": int((total_cost + total_additional) * 0.8),
                "high": int((total_cost + total_additional) * 1.3)
            }
        }
    
    def _analyze_dependencies(self, recommendations: List[MigrationRecommendation]) -> Dict[str, Any]:
        """Analyze dependencies between migration tasks."""
        
        # Collect all dependencies
        all_dependencies = []
        for rec in recommendations:
            all_dependencies.extend(rec.dependencies)
        
        # Count frequency
        dependency_counts = {}
        for dep in all_dependencies:
            dependency_counts[dep] = dependency_counts.get(dep, 0) + 1
        
        # Critical dependencies (affects many items)
        critical_deps = {
            dep: count for dep, count in dependency_counts.items() 
            if count >= len(recommendations) * 0.3  # Affects 30%+ of items
        }
        
        return {
            "critical_dependencies": critical_deps,
            "all_dependencies": dependency_counts,
            "dependency_graph": self._build_dependency_graph(recommendations)
        }
    
    def _build_dependency_graph(self, recommendations: List[MigrationRecommendation]) -> Dict[str, List[str]]:
        """Build dependency graph for migration tasks."""
        graph = {}
        
        for rec in recommendations:
            graph[rec.vulnerability_id] = rec.dependencies
        
        return graph
    
    def _assess_migration_risks(self, vulnerabilities: List[Vulnerability],
                              strategy: MigrationStrategy) -> Dict[str, Any]:
        """Assess risks associated with migration."""
        
        risks = []
        
        # Technical risks
        if len(vulnerabilities) > 50:
            risks.append({
                "type": "technical",
                "risk": "Large migration scope",
                "probability": "medium",
                "impact": "high",
                "mitigation": "Phase migration and use automation tools"
            })
        
        # Performance risks
        if any(v.algorithm in [CryptoAlgorithm.ECC, CryptoAlgorithm.ECDSA] for v in vulnerabilities):
            risks.append({
                "type": "performance",
                "risk": "PQC performance overhead",
                "probability": "high",
                "impact": "medium",
                "mitigation": "Performance testing and optimization"
            })
        
        # Timeline risks
        if strategy == MigrationStrategy.IMMEDIATE:
            risks.append({
                "type": "timeline",
                "risk": "Aggressive timeline may compromise quality",
                "probability": "medium",
                "impact": "high",
                "mitigation": "Increase testing and quality assurance"
            })
        
        # Compatibility risks
        risks.append({
            "type": "compatibility",
            "risk": "Legacy system compatibility issues",
            "probability": "medium",
            "impact": "medium",
            "mitigation": "Hybrid approach and gradual rollout"
        })
        
        return {
            "identified_risks": risks,
            "overall_risk_level": self._calculate_overall_risk_level(risks),
            "mitigation_strategy": "Implement comprehensive testing and phased rollout"
        }
    
    def _calculate_overall_risk_level(self, risks: List[Dict[str, str]]) -> str:
        """Calculate overall risk level."""
        if any(r["impact"] == "high" and r["probability"] in ["high", "medium"] for r in risks):
            return "HIGH"
        elif any(r["impact"] == "medium" and r["probability"] == "high" for r in risks):
            return "MEDIUM"
        else:
            return "LOW"
    
    def _define_success_metrics(self) -> Dict[str, Any]:
        """Define success metrics for migration."""
        return {
            "primary_metrics": [
                "100% of critical vulnerabilities migrated",
                "No quantum-vulnerable algorithms in production",
                "Performance impact < 20% for key operations",
                "Zero security incidents during migration"
            ],
            "secondary_metrics": [
                "Team training completion rate > 90%",
                "Automated testing coverage > 95%",
                "Documentation completeness > 90%",
                "Stakeholder satisfaction > 85%"
            ],
            "measurement_methods": {
                "security": "Automated scanning and manual review",
                "performance": "Benchmark testing and monitoring",
                "quality": "Code review and testing metrics",
                "stakeholder_satisfaction": "Surveys and feedback sessions"
            }
        }
    
    def _estimate_migration_cost(self, recommendations: List[MigrationRecommendation]) -> Dict[str, int]:
        """Estimate total migration cost range."""
        total_hours = sum(r.estimated_effort_hours for r in recommendations)
        
        # Conservative estimate
        low_cost = total_hours * 100  # $100/hour average
        
        # Aggressive estimate 
        high_cost = total_hours * 200  # $200/hour average
        
        # Add overhead costs (training, tools, etc.)
        overhead = 50000
        
        return {
            "low": low_cost + overhead,
            "high": high_cost + overhead
        }
    
    def _recommendation_to_dict(self, rec: MigrationRecommendation) -> Dict[str, Any]:
        """Convert recommendation to dictionary."""
        return {
            "vulnerability_id": rec.vulnerability_id,
            "current_algorithm": rec.current_algorithm,
            "recommended_algorithm": rec.recommended_algorithm.value,
            "strategy": rec.strategy.value,
            "priority": rec.priority,
            "estimated_effort_hours": rec.estimated_effort_hours,
            "dependencies": rec.dependencies,
            "notes": rec.notes,
            "code_example": rec.code_example
        }
    
    def _init_algorithm_mappings(self) -> Dict[str, str]:
        """Initialize algorithm mapping recommendations."""
        return {
            "RSA": "ML-KEM-768",
            "ECC": "ML-DSA-65", 
            "ECDSA": "ML-DSA-65",
            "DSA": "ML-DSA-44",
            "DH": "ML-KEM-768",
            "ECDH": "ML-KEM-768"
        }
    
    def _init_performance_profiles(self) -> Dict[str, PerformanceMetrics]:
        """Initialize performance profiles for PQC algorithms."""
        return {
            "ML-KEM-768": PerformanceMetrics(
                algorithm="ML-KEM-768",
                key_generation_time_ms=0.5,
                encryption_time_ms=0.1,
                decryption_time_ms=0.2,
                public_key_size_bytes=1184,
                private_key_size_bytes=2400,
                ciphertext_overhead_factor=1.1
            ),
            "ML-DSA-65": PerformanceMetrics(
                algorithm="ML-DSA-65",
                key_generation_time_ms=1.2,
                encryption_time_ms=0.0,  # Not applicable
                decryption_time_ms=0.0,  # Not applicable
                signature_time_ms=2.8,
                verification_time_ms=1.1,
                public_key_size_bytes=1952,
                private_key_size_bytes=4000,
                signature_size_bytes=3293
            )
        }