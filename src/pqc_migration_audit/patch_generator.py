"""Post-quantum cryptography patch generation module."""

import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

from .types import Vulnerability, CryptoAlgorithm, Severity


class PatchType(Enum):
    """Types of patches that can be generated."""
    REPLACE_RSA = "replace_rsa"
    REPLACE_ECC = "replace_ecc"
    REPLACE_DSA = "replace_dsa"
    UPGRADE_TLS = "upgrade_tls"
    HYBRID_MODE = "hybrid_mode"


@dataclass
class PatchTemplate:
    """Template for generating cryptographic patches."""
    
    language: str
    vulnerability_type: str
    old_pattern: str
    new_code: str
    description: str
    imports_needed: List[str] = None
    dependencies: List[str] = None
    
    def __post_init__(self):
        if self.imports_needed is None:
            self.imports_needed = []
        if self.dependencies is None:
            self.dependencies = []


class PQCPatchGenerator:
    """Generate migration patches for post-quantum cryptography."""
    
    def __init__(self):
        """Initialize the patch generator with templates."""
        self.templates = self._load_patch_templates()
    
    def generate_patch(self, vulnerability: Vulnerability, 
                      patch_type: PatchType = None,
                      target_language: str = None) -> Optional[str]:
        """Generate a patch for a specific vulnerability.
        
        Args:
            vulnerability: The vulnerability to patch
            patch_type: Type of patch to generate
            target_language: Target language for the patch
            
        Returns:
            Generated patch string or None if cannot generate
        """
        # Auto-detect language from file extension if not provided
        if not target_language:
            target_language = self._detect_language(vulnerability.file_path)
        
        # Auto-detect patch type if not provided
        if not patch_type:
            patch_type = self._detect_patch_type(vulnerability)
        
        # Find appropriate template
        template = self._find_template(target_language, vulnerability.algorithm, patch_type)
        if not template:
            return None
        
        # Generate patch
        patch_content = self._generate_patch_content(vulnerability, template)
        
        return patch_content
    
    def generate_migration_guide(self, vulnerabilities: List[Vulnerability]) -> str:
        """Generate comprehensive migration guide for all vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerabilities to address
            
        Returns:
            Comprehensive migration guide
        """
        guide_sections = []
        
        # Executive summary
        guide_sections.append(self._generate_executive_summary(vulnerabilities))
        
        # Algorithm-specific sections
        algorithms = set(vuln.algorithm for vuln in vulnerabilities)
        for algorithm in algorithms:
            algo_vulns = [v for v in vulnerabilities if v.algorithm == algorithm]
            guide_sections.append(self._generate_algorithm_section(algorithm, algo_vulns))
        
        # Implementation recommendations
        guide_sections.append(self._generate_implementation_recommendations())
        
        # Testing guidelines
        guide_sections.append(self._generate_testing_guidelines())
        
        return "\n\n".join(guide_sections)
    
    def _load_patch_templates(self) -> Dict[str, List[PatchTemplate]]:
        """Load patch templates for different languages and vulnerabilities."""
        return {
            "python": [
                PatchTemplate(
                    language="python",
                    vulnerability_type="rsa_key_generation",
                    old_pattern=r"rsa\.generate_private_key\s*\(",
                    new_code="""# Post-quantum replacement for RSA key generation
from pqc_lib import ML_KEM_768  # Kyber for key exchange
from pqc_lib import ML_DSA_65   # Dilithium for signatures

# For key exchange:
kem_private_key, kem_public_key = ML_KEM_768.generate_keypair()

# For digital signatures:
sig_private_key, sig_public_key = ML_DSA_65.generate_keypair()""",
                    description="Replace RSA key generation with ML-KEM (Kyber) for key exchange and ML-DSA (Dilithium) for signatures",
                    imports_needed=["from pqc_lib import ML_KEM_768, ML_DSA_65"],
                    dependencies=["pqc-lib>=1.0.0"]
                ),
                PatchTemplate(
                    language="python",
                    vulnerability_type="ecc_key_generation",
                    old_pattern=r"ec\.generate_private_key\s*\(",
                    new_code="""# Post-quantum replacement for ECC
from pqc_lib import ML_DSA_65  # Dilithium for signatures

# Generate post-quantum signature keys
private_key, public_key = ML_DSA_65.generate_keypair()""",
                    description="Replace ECC with ML-DSA (Dilithium) for digital signatures",
                    imports_needed=["from pqc_lib import ML_DSA_65"],
                    dependencies=["pqc-lib>=1.0.0"]
                ),
                PatchTemplate(
                    language="python",
                    vulnerability_type="hybrid_mode",
                    old_pattern=r"rsa\.generate_private_key\s*\(",
                    new_code="""# Hybrid classical + post-quantum approach
from cryptography.hazmat.primitives.asymmetric import rsa
from pqc_lib import ML_KEM_768

# Classical component (for backward compatibility)
classical_private = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
classical_public = classical_private.public_key()

# Post-quantum component
pqc_private, pqc_public = ML_KEM_768.generate_keypair()

# Hybrid key structure
hybrid_keys = {
    'classical': {'private': classical_private, 'public': classical_public},
    'pqc': {'private': pqc_private, 'public': pqc_public}
}""",
                    description="Implement hybrid classical + post-quantum cryptography for transition period",
                    imports_needed=["from pqc_lib import ML_KEM_768"],
                    dependencies=["pqc-lib>=1.0.0"]
                )
            ],
            "java": [
                PatchTemplate(
                    language="java",
                    vulnerability_type="rsa_key_generation",
                    old_pattern=r"KeyPairGenerator\.getInstance\s*\(\s*[\"']RSA[\"']\s*\)",
                    new_code="""// Post-quantum replacement for RSA
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.MLDSAParameterSpec;

// Add PQC provider
Security.addProvider(new BouncyCastlePQCProvider());

// For key exchange (ML-KEM/Kyber)
KeyPairGenerator kemGen = KeyPairGenerator.getInstance("ML-KEM", "BCPQC");
kemGen.initialize(MLKEMParameterSpec.ml_kem_768);
KeyPair kemKeyPair = kemGen.generateKeyPair();

// For digital signatures (ML-DSA/Dilithium)
KeyPairGenerator dsaGen = KeyPairGenerator.getInstance("ML-DSA", "BCPQC");
dsaGen.initialize(MLDSAParameterSpec.ml_dsa_65);
KeyPair dsaKeyPair = dsaGen.generateKeyPair();""",
                    description="Replace RSA with Bouncy Castle PQC implementation",
                    imports_needed=[
                        "import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;",
                        "import org.bouncycastle.pqc.jcajce.spec.MLKEMParameterSpec;",
                        "import org.bouncycastle.pqc.jcajce.spec.MLDSAParameterSpec;"
                    ],
                    dependencies=["org.bouncycastle:bcpqc-jdk15on:1.70"]
                )
            ],
            "go": [
                PatchTemplate(
                    language="go",
                    vulnerability_type="rsa_key_generation",
                    old_pattern=r"rsa\.GenerateKey\s*\(",
                    new_code="""// Post-quantum replacement for RSA using liboqs-go
import (
    "github.com/open-quantum-safe/liboqs-go/oqs"
)

// For key exchange (Kyber)
kemClient := oqs.KeyEncapsulation{}
defer kemClient.Clean()

err := kemClient.Init("Kyber768", nil)
if err != nil {
    return err
}

publicKey, err := kemClient.GenerateKeypair()  
if err != nil {
    return err
}

// For digital signatures (Dilithium)
sigClient := oqs.Signature{}
defer sigClient.Clean()

err = sigClient.Init("Dilithium3", nil)
if err != nil {
    return err
}

sigPublicKey, err := sigClient.GenerateKeypair()
if err != nil {
    return err
}""",
                    description="Replace RSA with liboqs-go post-quantum implementation",
                    imports_needed=["\"github.com/open-quantum-safe/liboqs-go/oqs\""],
                    dependencies=["github.com/open-quantum-safe/liboqs-go"]
                )
            ],
            "javascript": [
                PatchTemplate(
                    language="javascript",
                    vulnerability_type="rsa_key_generation",
                    old_pattern=r"crypto\.generateKeyPair\s*\(\s*[\"']rsa[\"']",
                    new_code="""// Post-quantum replacement for RSA
// Note: Full PQC support in Web Crypto API is still developing
// Consider using WebAssembly wrapper for liboqs

import { Kyber768, Dilithium3 } from 'pqc-wasm';

// For key exchange (Kyber)
const kyberKeyPair = Kyber768.generateKeyPair();
const kyberPublicKey = kyberKeyPair.publicKey;
const kyberPrivateKey = kyberKeyPair.privateKey;

// For digital signatures (Dilithium)  
const dilithiumKeyPair = Dilithium3.generateKeyPair();
const dilithiumPublicKey = dilithiumKeyPair.publicKey;
const dilithiumPrivateKey = dilithiumKeyPair.privateKey;

// Usage example:
// Encapsulation
const { ciphertext, sharedSecret } = Kyber768.encapsulate(kyberPublicKey);

// Decapsulation
const recoveredSecret = Kyber768.decapsulate(kyberPrivateKey, ciphertext);

// Signing
const signature = Dilithium3.sign(dilithiumPrivateKey, message);

// Verification
const isValid = Dilithium3.verify(dilithiumPublicKey, message, signature);""",
                    description="Replace RSA with WebAssembly PQC implementation",
                    imports_needed=["import { Kyber768, Dilithium3 } from 'pqc-wasm';"],
                    dependencies=["pqc-wasm"]
                )
            ],
            "c": [
                PatchTemplate(
                    language="c",
                    vulnerability_type="openssl_rsa",
                    old_pattern=r"RSA_generate_key(_ex)?\s*\(",
                    new_code="""// Post-quantum replacement using liboqs
#include <oqs/oqs.h>

// For key exchange (Kyber)
OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
if (kem == NULL) {
    return -1;
}

uint8_t *public_key = malloc(kem->length_public_key);
uint8_t *secret_key = malloc(kem->length_secret_key);

OQS_STATUS rc = OQS_KEM_keypair(kem, public_key, secret_key);
if (rc != OQS_SUCCESS) {
    cleanup_and_return_error();
}

// For digital signatures (Dilithium)
OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
if (sig == NULL) {
    return -1;
}

uint8_t *sig_public_key = malloc(sig->length_public_key);
uint8_t *sig_secret_key = malloc(sig->length_secret_key);

rc = OQS_SIG_keypair(sig, sig_public_key, sig_secret_key);
if (rc != OQS_SUCCESS) {
    cleanup_and_return_error();
}

// Remember to clean up
OQS_KEM_free(kem);
OQS_SIG_free(sig);""",
                    description="Replace OpenSSL RSA with liboqs post-quantum implementation",
                    imports_needed=["#include <oqs/oqs.h>"],
                    dependencies=["liboqs"]
                )
            ]
        }
    
    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension."""
        ext = Path(file_path).suffix.lower()
        ext_map = {
            '.py': 'python',
            '.java': 'java',
            '.go': 'go',
            '.js': 'javascript',
            '.ts': 'javascript',
            '.c': 'c',
            '.cpp': 'c',
            '.h': 'c',
            '.hpp': 'c'
        }
        return ext_map.get(ext, 'unknown')
    
    def _detect_patch_type(self, vulnerability: Vulnerability) -> PatchType:
        """Detect appropriate patch type for vulnerability."""
        if vulnerability.algorithm == CryptoAlgorithm.RSA:
            return PatchType.REPLACE_RSA
        elif vulnerability.algorithm == CryptoAlgorithm.ECC:
            return PatchType.REPLACE_ECC
        elif vulnerability.algorithm == CryptoAlgorithm.DSA:
            return PatchType.REPLACE_DSA
        else:
            return PatchType.REPLACE_RSA  # Default
    
    def _find_template(self, language: str, algorithm: CryptoAlgorithm, 
                      patch_type: PatchType) -> Optional[PatchTemplate]:
        """Find appropriate template for the given parameters."""
        if language not in self.templates:
            return None
        
        # Map algorithm and patch type to vulnerability type
        vuln_type_map = {
            (CryptoAlgorithm.RSA, PatchType.REPLACE_RSA): "rsa_key_generation",
            (CryptoAlgorithm.ECC, PatchType.REPLACE_ECC): "ecc_key_generation",
            (CryptoAlgorithm.RSA, PatchType.HYBRID_MODE): "hybrid_mode",
        }
        
        vuln_type = vuln_type_map.get((algorithm, patch_type))
        if not vuln_type:
            vuln_type = "rsa_key_generation"  # Default
        
        # Find matching template
        for template in self.templates[language]:
            if template.vulnerability_type == vuln_type:
                return template
        
        return None
    
    def _generate_patch_content(self, vulnerability: Vulnerability, 
                               template: PatchTemplate) -> str:
        """Generate patch content from template."""
        patch_header = f"""# Post-Quantum Cryptography Migration Patch
# File: {vulnerability.file_path}
# Line: {vulnerability.line_number}
# Algorithm: {vulnerability.algorithm.value}
# Severity: {vulnerability.severity.value}
# 
# Description: {template.description}
#
# Generated by PQC Migration Audit Tool
"""
        
        dependencies_section = ""
        if template.dependencies:
            deps = "\n".join(f"# - {dep}" for dep in template.dependencies)
            dependencies_section = f"""
# Dependencies to add:
{deps}
"""
        
        imports_section = ""
        if template.imports_needed:
            imports = "\n".join(template.imports_needed)
            imports_section = f"""
# Required imports:
{imports}
"""
        
        original_code_section = f"""
# Original vulnerable code:
# {vulnerability.code_snippet}
"""
        
        new_code_section = f"""
# Post-quantum replacement:
{template.new_code}
"""
        
        implementation_notes = f"""
# Implementation Notes:
# 1. Test thoroughly in development environment
# 2. Consider hybrid approach for transition period
# 3. Update documentation and key management procedures
# 4. Ensure compliance with organizational security policies
# 5. Plan for gradual rollout and monitoring

# Security Consideration:
# {vulnerability.recommendation}
"""
        
        return (patch_header + dependencies_section + imports_section + 
                original_code_section + new_code_section + implementation_notes)
    
    def _generate_executive_summary(self, vulnerabilities: List[Vulnerability]) -> str:
        """Generate executive summary for migration guide."""
        total_vulns = len(vulnerabilities)
        critical_count = len([v for v in vulnerabilities if v.severity == Severity.CRITICAL])
        high_count = len([v for v in vulnerabilities if v.severity == Severity.HIGH])
        
        return f"""# Post-Quantum Cryptography Migration Guide

## Executive Summary

This migration guide addresses **{total_vulns}** quantum-vulnerable cryptographic implementations identified in your codebase:

- **Critical Priority**: {critical_count} vulnerabilities requiring immediate attention
- **High Priority**: {high_count} vulnerabilities requiring near-term migration
- **Medium/Low Priority**: {total_vulns - critical_count - high_count} vulnerabilities for planned migration

### Quantum Threat Timeline
- **2025-2027**: Inventory and prepare for migration
- **2027-2030**: Complete migration of critical systems
- **2030+**: Full post-quantum cryptography deployment

### Recommended Approach
1. **Phase 1**: Address critical and high-severity vulnerabilities
2. **Phase 2**: Implement hybrid classical + PQC solutions
3. **Phase 3**: Complete migration to pure PQC implementations"""
    
    def _generate_algorithm_section(self, algorithm: CryptoAlgorithm, 
                                   vulnerabilities: List[Vulnerability]) -> str:
        """Generate algorithm-specific migration section."""
        algo_name = algorithm.value
        vuln_count = len(vulnerabilities)
        
        # Algorithm-specific recommendations
        recommendations = {
            CryptoAlgorithm.RSA: {
                "replacement": "ML-KEM (Kyber) for key exchange, ML-DSA (Dilithium) for signatures",
                "rationale": "RSA is vulnerable to Shor's algorithm on quantum computers"
            },
            CryptoAlgorithm.ECC: {
                "replacement": "ML-DSA (Dilithium) for signatures, ML-KEM (Kyber) for key exchange",
                "rationale": "ECC is vulnerable to Shor's algorithm and easier to break than RSA"
            },
            CryptoAlgorithm.DSA: {
                "replacement": "ML-DSA (Dilithium) for digital signatures",
                "rationale": "DSA is vulnerable to Shor's algorithm"
            }
        }
        
        rec = recommendations.get(algorithm, {
            "replacement": "Post-quantum alternatives",
            "rationale": "Vulnerable to quantum attacks"
        })
        
        return f"""## {algo_name} Migration ({vuln_count} instances found)

### Vulnerability Assessment
- **Algorithm**: {algo_name}
- **Quantum Vulnerability**: {rec['rationale']}
- **Instances Found**: {vuln_count}

### Recommended Migration Path
- **Target Algorithm**: {rec['replacement']}
- **Migration Strategy**: Hybrid approach during transition
- **Timeline**: Complete within 18-24 months

### Implementation Priority
Files requiring immediate attention:
{self._format_file_list(vulnerabilities[:5])}"""
    
    def _format_file_list(self, vulnerabilities: List[Vulnerability]) -> str:
        """Format vulnerability file list for display."""
        if not vulnerabilities:
            return "- None"
        
        file_list = []
        for vuln in vulnerabilities:
            file_list.append(f"- {vuln.file_path}:{vuln.line_number} ({vuln.severity.value})")
        
        return "\n".join(file_list)
    
    def _generate_implementation_recommendations(self) -> str:
        """Generate implementation recommendations section."""
        return """## Implementation Recommendations

### 1. Crypto-Agility Framework
Implement a crypto-agility framework to enable easy algorithm swapping:
```python
class CryptoProvider:
    def __init__(self, algorithm_type="hybrid"):
        self.algorithm_type = algorithm_type
    
    def generate_keypair(self):
        if self.algorithm_type == "classical":
            return self._generate_rsa_keypair()
        elif self.algorithm_type == "pqc":
            return self._generate_pqc_keypair()
        else:  # hybrid
            return self._generate_hybrid_keypair()
```

### 2. Hybrid Implementation Strategy
During the transition period (2025-2027), implement hybrid solutions:
- Maintain classical cryptography for backward compatibility
- Add PQC layer for future-proofing
- Negotiate algorithm support dynamically

### 3. Key Management Updates
- Update key storage formats to support PQC key sizes
- Implement secure key rotation procedures
- Plan for certificate authority updates

### 4. Performance Considerations
- PQC algorithms have different performance characteristics
- Kyber: Fast key generation and encapsulation
- Dilithium: Larger signature sizes but good performance
- Plan capacity for increased computational and storage requirements"""
    
    def _generate_testing_guidelines(self) -> str:
        """Generate testing guidelines section."""
        return """## Testing and Validation Guidelines

### 1. Development Environment Setup
- Install PQC libraries (liboqs, Bouncy Castle PQC, etc.)
- Set up test environments with PQC implementations
- Create test vectors for validation

### 2. Compatibility Testing
- Test interoperability between classical and PQC systems
- Validate hybrid mode operations
- Test fallback mechanisms

### 3. Performance Testing
- Benchmark key generation performance
- Measure signature/verification times
- Test memory usage with larger key sizes
- Validate network throughput with larger signatures

### 4. Security Validation
- Conduct security reviews of PQC implementations
- Validate proper random number generation
- Test against known attack vectors
- Ensure side-channel attack resistance

### 5. Integration Testing
- Test with existing authentication systems
- Validate certificate chain operations
- Test with load balancers and proxies
- Ensure monitoring and logging capture PQC operations

### 6. Rollback Planning
- Implement ability to rollback to classical crypto if needed
- Test rollback procedures
- Plan for emergency algorithm switching
- Document rollback decision criteria"""