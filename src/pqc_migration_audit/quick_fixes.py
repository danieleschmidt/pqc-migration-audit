"""
Quick Fixes for Generation 1: Make It Work
Simple patch suggestions and migration helpers.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
from pathlib import Path


@dataclass
class QuickFix:
    """Simple fix suggestion."""
    vulnerability_type: str
    original_code: str
    suggested_fix: str
    explanation: str
    confidence: str  # 'high', 'medium', 'low'


class QuickFixGenerator:
    """Generate simple fix suggestions for common vulnerabilities."""
    
    def __init__(self):
        """Initialize quick fix generator."""
        self.fix_templates = {
            'python': {
                'rsa_key_generation': [
                    QuickFix(
                        vulnerability_type='RSA Key Generation',
                        original_code='rsa.generate_private_key(public_exponent=65537, key_size=2048)',
                        suggested_fix='''# TODO: Replace with post-quantum cryptography
# from pqc_migration.crypto import ML_KEM_768  # Kyber
# private_key, public_key = ML_KEM_768.generate_keypair()

# TEMPORARY: Document quantum vulnerability
# This RSA key generation is quantum-vulnerable
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)''',
                        explanation='RSA is vulnerable to quantum attacks. Consider ML-KEM (Kyber) for key exchange.',
                        confidence='high'
                    )
                ],
                'ecc_key_generation': [
                    QuickFix(
                        vulnerability_type='ECC Key Generation',
                        original_code='ec.generate_private_key(ec.SECP256R1())',
                        suggested_fix='''# TODO: Replace with post-quantum cryptography
# from pqc_migration.crypto import ML_DSA_65  # Dilithium
# signing_key, verification_key = ML_DSA_65.generate_keypair()

# TEMPORARY: Document quantum vulnerability
# This ECC key generation is quantum-vulnerable
private_key = ec.generate_private_key(ec.SECP256R1())''',
                        explanation='ECC is vulnerable to quantum attacks. Consider ML-DSA (Dilithium) for signatures.',
                        confidence='high'
                    )
                ],
                'crypto_imports': [
                    QuickFix(
                        vulnerability_type='Quantum-Vulnerable Imports',
                        original_code='from cryptography.hazmat.primitives.asymmetric import rsa',
                        suggested_fix='''# TODO: Plan migration to post-quantum cryptography
# Consider: from pqc_migration.crypto import ML_KEM_768, ML_DSA_65

# TEMPORARY: Document quantum vulnerability
from cryptography.hazmat.primitives.asymmetric import rsa  # QUANTUM-VULNERABLE''',
                        explanation='This import provides quantum-vulnerable cryptography.',
                        confidence='medium'
                    )
                ]
            },
            'java': {
                'rsa_key_generation': [
                    QuickFix(
                        vulnerability_type='RSA KeyPairGenerator',
                        original_code='KeyPairGenerator.getInstance("RSA")',
                        suggested_fix='''// TODO: Replace with post-quantum cryptography
// Consider NIST-approved PQC algorithms like ML-KEM or ML-DSA
// For now, document the quantum vulnerability
KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA"); // QUANTUM-VULNERABLE''',
                        explanation='RSA key generation is vulnerable to quantum attacks.',
                        confidence='high'
                    )
                ]
            },
            'go': {
                'rsa_key_generation': [
                    QuickFix(
                        vulnerability_type='RSA Key Generation',
                        original_code='rsa.GenerateKey(rand.Reader, 2048)',
                        suggested_fix='''// TODO: Replace with post-quantum cryptography
// Consider using liboqs Go bindings for PQC algorithms
// For now, document the quantum vulnerability
privateKey, err := rsa.GenerateKey(rand.Reader, 2048) // QUANTUM-VULNERABLE''',
                        explanation='RSA key generation is vulnerable to quantum attacks.',
                        confidence='high'
                    )
                ]
            }
        }
    
    def get_quick_fixes(self, language: str, vulnerability_type: str) -> List[QuickFix]:
        """Get quick fix suggestions for a vulnerability."""
        lang_fixes = self.fix_templates.get(language, {})
        return lang_fixes.get(vulnerability_type, [])
    
    def generate_migration_plan(self, vulnerabilities_by_type: Dict[str, int]) -> Dict[str, any]:
        """Generate a simple migration plan."""
        total_vulns = sum(vulnerabilities_by_type.values())
        
        if total_vulns == 0:
            return {
                'status': 'clean',
                'message': 'No quantum-vulnerable cryptography found!',
                'next_steps': ['Continue using secure cryptographic practices']
            }
        
        # Estimate effort
        effort_hours = total_vulns * 4  # 4 hours per vulnerability on average
        
        plan = {
            'status': 'migration_needed',
            'total_vulnerabilities': total_vulns,
            'estimated_effort_hours': effort_hours,
            'estimated_effort_days': max(1, effort_hours // 8),
            'priority_order': [
                'RSA key generation (highest priority)',
                'ECC key generation (high priority)', 
                'Legacy crypto imports (medium priority)',
                'Other vulnerabilities (low priority)'
            ],
            'immediate_actions': [
                '1. Document all quantum-vulnerable code with TODO comments',
                '2. Research post-quantum alternatives (ML-KEM, ML-DSA)',
                '3. Set up testing environment for PQC libraries',
                '4. Create timeline for gradual migration'
            ],
            'recommended_pqc_algorithms': {
                'Key Exchange': 'ML-KEM (Kyber) - NIST standardized',
                'Digital Signatures': 'ML-DSA (Dilithium) - NIST standardized',
                'Hash Functions': 'SHA-3 (already quantum-resistant)'
            }
        }
        
        return plan
    
    def create_simple_patch_file(self, fixes: List[QuickFix], output_path: str) -> None:
        """Create a simple patch file with fix suggestions."""
        with open(output_path, 'w') as f:
            f.write("# PQC Migration Quick Fixes\n")
            f.write("# Generated by pqc-migration-audit\n\n")
            
            for i, fix in enumerate(fixes, 1):
                f.write(f"## Fix {i}: {fix.vulnerability_type}\n")
                f.write(f"**Confidence:** {fix.confidence}\n\n")
                f.write(f"**Original Code:**\n```\n{fix.original_code}\n```\n\n")
                f.write(f"**Suggested Fix:**\n```\n{fix.suggested_fix}\n```\n\n")
                f.write(f"**Explanation:** {fix.explanation}\n\n")
                f.write("---\n\n")
        
        print(f"Patch file created: {output_path}")


def create_migration_checklist() -> str:
    """Create a simple migration checklist."""
    checklist = """
# Post-Quantum Cryptography Migration Checklist

## Phase 1: Assessment (Week 1)
- [ ] Complete vulnerability scan with pqc-migration-audit
- [ ] Document all quantum-vulnerable code locations
- [ ] Assess business impact and prioritize components
- [ ] Research suitable PQC alternatives

## Phase 2: Planning (Week 2)
- [ ] Choose post-quantum algorithms (ML-KEM, ML-DSA, etc.)
- [ ] Plan hybrid approach during transition
- [ ] Set up development/testing environment
- [ ] Create migration timeline

## Phase 3: Implementation (Weeks 3-N)
- [ ] Implement highest priority fixes first
- [ ] Test new implementations thoroughly
- [ ] Maintain backward compatibility where needed
- [ ] Update documentation and security policies

## Phase 4: Deployment (Final weeks)
- [ ] Deploy to staging environment
- [ ] Conduct security testing
- [ ] Roll out to production gradually
- [ ] Monitor for issues and performance impact

## Quick Reference: NIST PQC Standards
- **ML-KEM (Kyber)**: Key encapsulation mechanism
- **ML-DSA (Dilithium)**: Digital signature algorithm
- **SLH-DSA (SPHINCS+)**: Hash-based signature scheme

## Need Help?
- NIST PQC: https://csrc.nist.gov/projects/post-quantum-cryptography
- Open Quantum Safe: https://openquantumsafe.org/
- Migration guides: Check your crypto library documentation
"""
    return checklist


def main():
    """Simple CLI for quick fixes."""
    import sys
    
    print("🔧 PQC Quick Fix Generator")
    print("Generate simple migration suggestions and checklists")
    
    # Create migration checklist
    checklist_path = "/tmp/pqc_migration_checklist.md"
    with open(checklist_path, 'w') as f:
        f.write(create_migration_checklist())
    print(f"✅ Migration checklist created: {checklist_path}")
    
    # Example fixes
    generator = QuickFixGenerator()
    example_fixes = []
    
    # Add some example fixes
    for lang in ['python', 'java', 'go']:
        for vuln_type in generator.fix_templates.get(lang, {}):
            fixes = generator.get_quick_fixes(lang, vuln_type)
            example_fixes.extend(fixes)
    
    if example_fixes:
        patch_path = "/tmp/pqc_quick_fixes.md"
        generator.create_simple_patch_file(example_fixes, patch_path)
    
    # Example migration plan
    example_vulns = {'rsa_key_generation': 3, 'ecc_key_generation': 2, 'crypto_imports': 5}
    plan = generator.generate_migration_plan(example_vulns)
    
    print(f"\n📋 Example Migration Plan:")
    print(f"Status: {plan['status']}")
    print(f"Total vulnerabilities: {plan.get('total_vulnerabilities', 0)}")
    print(f"Estimated effort: {plan.get('estimated_effort_days', 0)} days")


if __name__ == "__main__":
    main()