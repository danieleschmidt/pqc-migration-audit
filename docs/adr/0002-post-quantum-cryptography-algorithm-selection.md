# ADR-0002: Post-Quantum Cryptography Algorithm Selection

## Status
Accepted

## Context
With NIST standardizing post-quantum cryptographic algorithms in 2024, we need to establish which PQC algorithms to prioritize in our migration recommendations. The tool must provide practical, secure alternatives to quantum-vulnerable classical cryptography.

Key considerations:
- NIST standardization status and maturity
- Performance characteristics and implementation availability
- Industry adoption and ecosystem support
- Quantum security levels and future-proofing
- Interoperability with existing systems

## Decision
We will prioritize the following NIST-standardized PQC algorithms:

**Key Encapsulation Mechanisms (KEMs):**
- ML-KEM-512 (Kyber-512) for Level 1 security
- ML-KEM-768 (Kyber-768) for Level 3 security (recommended default)
- ML-KEM-1024 (Kyber-1024) for Level 5 security

**Digital Signatures:**
- ML-DSA-44 (Dilithium2) for Level 2 security
- ML-DSA-65 (Dilithium3) for Level 3 security (recommended default)
- ML-DSA-87 (Dilithium5) for Level 5 security

**Secondary Support:**
- SLH-DSA (SPHINCS+) for signature applications requiring hash-based security
- Classic McEliece for conservative KEM applications
- Falcon for size-constrained signature applications

## Consequences
**Positive:**
- Focus on NIST-standardized, mature algorithms
- Clear migration path with security level mapping
- Industry alignment and ecosystem compatibility
- Future-proof recommendations based on quantum threat models

**Negative:**
- Limited algorithm diversity may not suit all use cases
- Dependence on relatively new implementations
- Larger key/signature sizes in some cases

**Neutral:**
- Algorithm preferences can be updated as standards evolve
- Tool architecture supports pluggable algorithm recommendations