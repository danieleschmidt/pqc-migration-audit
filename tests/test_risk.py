"""Tests for RiskScorer."""

from pqc_migration_audit.scanner import CryptoFinding
from pqc_migration_audit.risk import RiskScorer, RiskLevel


def make_finding(algorithm, usage_context, key_size=None):
    return CryptoFinding(
        file_path="test.py",
        line_number=1,
        line_text="...",
        algorithm=algorithm,
        usage_context=usage_context,
        key_size=key_size,
    )


def test_ecdh_handshake_is_critical():
    f = make_finding("ECC", "handshake")
    a = RiskScorer().score(f)
    assert a.risk_level == RiskLevel.CRITICAL


def test_dsa_sign_is_high_or_critical():
    f = make_finding("DSA", "sign")
    a = RiskScorer().score(f)
    assert a.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)


def test_rsa_import_is_lower_risk():
    f = make_finding("RSA", "import")
    a = RiskScorer().score(f)
    # import alone should be MEDIUM or LOW
    assert a.risk_level in (RiskLevel.MEDIUM, RiskLevel.LOW)


def test_weak_rsa_key_raises_risk():
    weak = make_finding("RSA", "keygen", key_size=1024)
    strong = make_finding("RSA", "keygen", key_size=4096)
    scorer = RiskScorer()
    assert scorer.score(weak).score > scorer.score(strong).score


def test_score_all_sorted():
    findings = [
        make_finding("RSA", "import"),
        make_finding("ECC", "handshake"),
        make_finding("DSA", "keygen"),
    ]
    assessments = RiskScorer().score_all(findings)
    scores = [a.score for a in assessments]
    assert scores == sorted(scores, reverse=True)


def test_rationale_contains_algorithm():
    f = make_finding("RSA", "sign")
    a = RiskScorer().score(f)
    assert "RSA" in a.rationale
