"""Tests for MigrationPlanner."""

from pqc_migration_audit.scanner import CryptoFinding
from pqc_migration_audit.risk import RiskScorer, RiskLevel
from pqc_migration_audit.planner import MigrationPlanner


def make_assessment(algorithm, usage_context, key_size=None):
    f = CryptoFinding(
        file_path="app.py",
        line_number=10,
        line_text="rsa.generate_private_key(...)",
        algorithm=algorithm,
        usage_context=usage_context,
        key_size=key_size,
    )
    return RiskScorer().score(f)


def test_rsa_keygen_uses_ml_kem():
    a = make_assessment("RSA", "keygen")
    plan = MigrationPlanner().plan(a)
    assert "ML-KEM" in plan.pqc_algorithm


def test_rsa_sign_uses_ml_dsa():
    a = make_assessment("RSA", "sign")
    plan = MigrationPlanner().plan(a)
    assert "ML-DSA" in plan.pqc_algorithm


def test_ecc_sign_uses_ml_dsa():
    a = make_assessment("ECC", "sign")
    plan = MigrationPlanner().plan(a)
    assert "ML-DSA" in plan.pqc_algorithm


def test_ecc_handshake_uses_ml_kem():
    a = make_assessment("ECC", "handshake")
    plan = MigrationPlanner().plan(a)
    assert "ML-KEM" in plan.pqc_algorithm


def test_dsa_sign_uses_ml_dsa():
    a = make_assessment("DSA", "sign")
    plan = MigrationPlanner().plan(a)
    assert "ML-DSA" in plan.pqc_algorithm


def test_plan_has_steps():
    a = make_assessment("RSA", "encrypt")
    plan = MigrationPlanner().plan(a)
    assert len(plan.steps) >= 3
    assert plan.steps[0].order == 1


def test_plan_has_effort_estimate():
    a = make_assessment("RSA", "keygen")
    plan = MigrationPlanner().plan(a)
    assert plan.estimated_effort_days > 0


def test_plan_all_preserves_order():
    assessments = [
        make_assessment("RSA", "import"),
        make_assessment("ECC", "handshake"),
        make_assessment("DSA", "keygen"),
    ]
    # Sort by risk first (planner expects sorted input)
    assessments.sort(key=lambda a: a.score, reverse=True)
    plans = MigrationPlanner().plan_all(assessments)
    assert len(plans) == 3


def test_reference_url_is_nist():
    a = make_assessment("RSA", "sign")
    plan = MigrationPlanner().plan(a)
    assert "csrc.nist.gov" in plan.reference_url
