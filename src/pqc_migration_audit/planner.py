"""
MigrationPlanner: generates PQC migration paths for each finding.

NIST PQC finalists used:
  - ML-KEM   (FIPS 203 / Kyber)      — key encapsulation
  - ML-DSA   (FIPS 204 / Dilithium)  — digital signatures
  - SLH-DSA  (FIPS 205 / SPHINCS+)   — hash-based signatures (stateless)

Reference: NIST IR 8547 (2024) and FIPS 203/204/205.
"""

from dataclasses import dataclass

from .scanner import CryptoFinding
from .risk import RiskAssessment, RiskLevel


@dataclass
class MigrationStep:
    order: int
    action: str


@dataclass
class MigrationPlan:
    finding: CryptoFinding
    risk_assessment: RiskAssessment
    pqc_algorithm: str          # ML-KEM | ML-DSA | SLH-DSA | ML-KEM + ML-DSA
    migration_description: str
    steps: list[MigrationStep]
    estimated_effort_days: int
    timeline_recommendation: str
    reference_url: str


# ──────────────────────────────────────────────────────────────────────────────
# Migration knowledge base
# ──────────────────────────────────────────────────────────────────────────────

_NIST_URLS = {
    "ML-KEM":  "https://csrc.nist.gov/pubs/fips/203/final",
    "ML-DSA":  "https://csrc.nist.gov/pubs/fips/204/final",
    "SLH-DSA": "https://csrc.nist.gov/pubs/fips/205/final",
}

# (algorithm, usage_context) → (pqc_algo, description, steps, effort_days)
_MIGRATION_KB: dict[tuple[str, str], tuple[str, str, list[str], int]] = {
    # ── RSA ──────────────────────────────────────────────────────────────────
    ("RSA", "keygen"): (
        "ML-KEM",
        "Replace RSA key-pair generation with ML-KEM key encapsulation mechanism.",
        [
            "Identify all RSA key generation call sites and their consumers.",
            "Select ML-KEM parameter set: ML-KEM-512 (128-bit), ML-KEM-768 (192-bit), or ML-KEM-1024 (256-bit).",
            "Replace `RSA.generate_private_key` / `RSA.generate()` with ML-KEM KEM API from your PQC library (e.g., liboqs, CIRCL, Bouncy Castle 1.80+).",
            "Update key serialization/deserialization (DER/PEM formats for PQC are defined in IETF drafts).",
            "Run regression + integration tests.",
            "Update certificate/key management workflows if applicable.",
        ],
        5,
    ),
    ("RSA", "encrypt"): (
        "ML-KEM",
        "Replace RSA-OAEP/PKCS#1 encryption with ML-KEM KEM + symmetric AEAD.",
        [
            "Map all RSA encrypt/decrypt call sites.",
            "Replace with ML-KEM KEM: encapsulate shared secret, then encrypt data with AES-256-GCM or ChaCha20-Poly1305.",
            "Update wire protocol / storage format to include ML-KEM ciphertext alongside AEAD ciphertext.",
            "Consider hybrid mode (ML-KEM + X25519) for transition period per NIST guidance.",
            "Test with both sender and receiver code paths.",
        ],
        7,
    ),
    ("RSA", "sign"): (
        "ML-DSA",
        "Replace RSA signatures (PKCS#1 v1.5 / PSS) with ML-DSA (Dilithium).",
        [
            "Enumerate all signing and verification call sites.",
            "Choose ML-DSA parameter set: ML-DSA-44, ML-DSA-65, or ML-DSA-87.",
            "Replace sign/verify calls using your PQC library's ML-DSA API.",
            "If stateless hash-based signatures are preferred, use SLH-DSA instead.",
            "Update certificate chains, JWT libraries, or code-signing pipelines as needed.",
            "Validate signature format compatibility with consumers.",
        ],
        8,
    ),
    ("RSA", "import"): (
        "ML-KEM",
        "RSA import detected — audit usage and plan migration to ML-KEM or ML-DSA.",
        [
            "Trace the import to actual usage (keygen / sign / encrypt).",
            "Apply keygen, sign, or encrypt migration plan based on usage.",
            "Remove RSA import once all usages are migrated.",
        ],
        2,
    ),
    ("RSA", "keysize"): (
        "ML-KEM",
        "Weak RSA key size detected — upgrade key size immediately and plan PQC migration.",
        [
            "If key size < 2048: upgrade to 4096-bit RSA as short-term fix.",
            "Begin ML-KEM migration for long-term PQC readiness.",
            "Document key rotation plan and timeline.",
        ],
        3,
    ),
    # ── ECC ──────────────────────────────────────────────────────────────────
    ("ECC", "keygen"): (
        "ML-KEM",
        "Replace ECDH/ECDSA key generation with ML-KEM (for KEM) or ML-DSA (for signing).",
        [
            "Determine if ECC key is used for key exchange (ECDH) or signature (ECDSA).",
            "For ECDH: migrate to ML-KEM KEM.",
            "For ECDSA: migrate to ML-DSA.",
            "Remove elliptic curve parameter specifications.",
        ],
        6,
    ),
    ("ECC", "sign"): (
        "ML-DSA",
        "Replace ECDSA with ML-DSA (Dilithium) digital signatures.",
        [
            "Identify ECDSA sign/verify call sites.",
            "Replace with ML-DSA-44/65/87 via your PQC library.",
            "Update public key distribution mechanism (certificates, DNSSEC, etc.).",
            "Consider SLH-DSA for scenarios needing conservative security assumptions.",
        ],
        7,
    ),
    ("ECC", "handshake"): (
        "ML-KEM",
        "Replace ECDH key exchange with ML-KEM — highest HNDL risk.",
        [
            "CRITICAL: ECDH-protected data transmitted today is at harvest-now-decrypt-later risk.",
            "Deploy ML-KEM-768 or ML-KEM-1024 for key exchange immediately.",
            "Use hybrid KEM (ML-KEM + X25519/P-256) for backward compatibility during transition.",
            "Update TLS configuration if this is a TLS handshake (requires TLS 1.3 + ML-KEM extension).",
            "Re-key any long-term secrets protected by ECDH.",
        ],
        10,
    ),
    ("ECC", "import"): (
        "ML-KEM",
        "ECC import detected — audit and migrate to ML-KEM or ML-DSA.",
        [
            "Trace import to actual usage.",
            "Apply handshake, sign, or keygen migration plan.",
        ],
        2,
    ),
    # ── DH ───────────────────────────────────────────────────────────────────
    ("DH", "keygen"): (
        "ML-KEM",
        "Replace finite-field DH with ML-KEM key encapsulation.",
        [
            "DH parameter generation is expensive and often weak; replace entirely.",
            "Migrate to ML-KEM-768 for equivalent or better security.",
            "Remove DH parameter generation code.",
            "Update any protocols that negotiate DH groups.",
        ],
        6,
    ),
    ("DH", "handshake"): (
        "ML-KEM",
        "Replace DH key exchange with ML-KEM — harvest-now-decrypt-later risk.",
        [
            "Immediate priority: DH key exchange exposes past and future traffic.",
            "Replace with ML-KEM hybrid KEM in protocol implementation.",
            "Update TLS/SSH configuration to disable DHE cipher suites.",
        ],
        8,
    ),
    ("DH", "import"): (
        "ML-KEM",
        "DH import — migrate key exchange to ML-KEM.",
        [
            "Trace to usage and apply keygen/handshake plan.",
            "Remove DH import once migrated.",
        ],
        2,
    ),
    # ── DSA ──────────────────────────────────────────────────────────────────
    ("DSA", "keygen"): (
        "ML-DSA",
        "Replace DSA (deprecated by NIST 2023) with ML-DSA.",
        [
            "DSA is deprecated per NIST SP 800-131Ar2 (2023).",
            "Migrate to ML-DSA-44/65/87.",
            "Update key generation, signing, and verification paths.",
            "Revoke and reissue any DSA certificates or keys.",
        ],
        5,
    ),
    ("DSA", "sign"): (
        "ML-DSA",
        "Replace DSA signatures with ML-DSA. DSA is deprecated.",
        [
            "Replace DSA sign/verify with ML-DSA API.",
            "Use SLH-DSA as an alternative if conservative, stateless hash-based approach is preferred.",
            "Update protocol to distribute new public keys.",
        ],
        6,
    ),
    ("DSA", "import"): (
        "ML-DSA",
        "DSA import — deprecated algorithm, migrate immediately.",
        [
            "Trace and replace with ML-DSA per sign/keygen plan.",
        ],
        2,
    ),
}

# Default fallback
_DEFAULT_MIGRATION = (
    "ML-DSA",
    "Quantum-vulnerable algorithm detected. Replace with appropriate NIST PQC finalist.",
    [
        "Identify exact usage context (encrypt/sign/handshake).",
        "Select ML-KEM (key exchange), ML-DSA (signatures), or SLH-DSA (hash-based signatures).",
        "Apply relevant migration steps from NIST migration guide.",
    ],
    4,
)

_TIMELINE_BY_RISK: dict[RiskLevel, str] = {
    RiskLevel.CRITICAL: "Immediate (within 30 days) — active HNDL threat or deprecated algorithm in production.",
    RiskLevel.HIGH:     "Short-term (90 days) — high-value target or auth path; migrate before 2025 NIST deadlines.",
    RiskLevel.MEDIUM:   "Medium-term (6 months) — plan migration in next major release cycle.",
    RiskLevel.LOW:      "Long-term (12–18 months) — include in cryptographic agility roadmap.",
}


class MigrationPlanner:
    def plan(self, assessment: RiskAssessment) -> MigrationPlan:
        f = assessment.finding
        key = (f.algorithm, f.usage_context)
        pqc_algo, desc, raw_steps, effort = _MIGRATION_KB.get(key, _DEFAULT_MIGRATION)

        steps = [MigrationStep(order=i + 1, action=s) for i, s in enumerate(raw_steps)]
        timeline = _TIMELINE_BY_RISK[assessment.risk_level]
        ref_url = _NIST_URLS.get(pqc_algo.split(" + ")[0], "https://csrc.nist.gov/projects/post-quantum-cryptography")

        return MigrationPlan(
            finding=f,
            risk_assessment=assessment,
            pqc_algorithm=pqc_algo,
            migration_description=desc,
            steps=steps,
            estimated_effort_days=effort,
            timeline_recommendation=timeline,
            reference_url=ref_url,
        )

    def plan_all(self, assessments: list[RiskAssessment]) -> list[MigrationPlan]:
        """Return migration plans sorted by risk (highest first)."""
        return [self.plan(a) for a in assessments]
