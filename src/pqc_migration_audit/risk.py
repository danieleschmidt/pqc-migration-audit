"""
RiskScorer: assigns CRITICAL/HIGH/MEDIUM/LOW risk to each CryptoFinding.

Risk factors:
  - Algorithm family: DSA/DH are higher risk than RSA; ECC key-exchange is worst
  - Key size: smaller keys = easier to break today
  - Usage context: auth (sign) > key-exchange (handshake) > encryption > import
  - Harvest-now-decrypt-later (HNDL): long-lived secrets in storage/transit
"""

from dataclasses import dataclass
from enum import Enum

from .scanner import CryptoFinding


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


# Numeric scores (higher = worse)
_ALGO_BASE: dict[str, int] = {
    "DH":  90,   # pure key-exchange, no PQC alternative widely deployed
    "DSA": 85,   # deprecated by NIST
    "ECC": 80,   # ECDH especially vulnerable to HNDL
    "RSA": 75,
}

_CONTEXT_BONUS: dict[str, int] = {
    "handshake": 20,   # key exchange – HNDL threat
    "sign":      10,   # authentication
    "encrypt":   8,    # data confidentiality
    "keygen":    5,
    "keysize":   3,
    "import":    0,
}

# Weak key sizes add extra risk
def _key_size_bonus(algo: str, size: int | None) -> int:
    if size is None:
        return 0
    thresholds: dict[str, list[tuple[int, int]]] = {
        # (threshold, bonus) — if size <= threshold, apply bonus
        "RSA": [(1024, 20), (2048, 10), (3072, 5)],
        "DH":  [(1024, 20), (2048, 10)],
        "DSA": [(1024, 20), (2048, 10)],
        "ECC": [(192, 20), (256, 5)],
    }
    for threshold, bonus in thresholds.get(algo, []):
        if size <= threshold:
            return bonus
    return 0


def _score_to_level(score: int) -> RiskLevel:
    if score >= 100:
        return RiskLevel.CRITICAL
    if score >= 85:
        return RiskLevel.HIGH
    if score >= 70:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


@dataclass
class RiskAssessment:
    finding: CryptoFinding
    risk_level: RiskLevel
    score: int
    rationale: str


class RiskScorer:
    def score(self, finding: CryptoFinding) -> RiskAssessment:
        base  = _ALGO_BASE.get(finding.algorithm, 70)
        ctx   = _CONTEXT_BONUS.get(finding.usage_context, 0)
        size  = _key_size_bonus(finding.algorithm, finding.key_size)
        total = base + ctx + size

        parts: list[str] = [
            f"{finding.algorithm} ({finding.usage_context})",
            f"base={base}",
        ]
        if ctx:
            parts.append(f"context+{ctx}")
        if size:
            parts.append(f"weak-key+{size}")
        rationale = ", ".join(parts) + f" → score {total}"

        return RiskAssessment(
            finding=finding,
            risk_level=_score_to_level(total),
            score=total,
            rationale=rationale,
        )

    def score_all(self, findings: list[CryptoFinding]) -> list[RiskAssessment]:
        return sorted(
            [self.score(f) for f in findings],
            key=lambda a: a.score,
            reverse=True,
        )
