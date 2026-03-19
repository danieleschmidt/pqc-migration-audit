"""Tests for AuditReport."""

import json

from pqc_migration_audit.scanner import CryptoFinding, CryptoScanner
from pqc_migration_audit.risk import RiskScorer
from pqc_migration_audit.planner import MigrationPlanner
from pqc_migration_audit.report import AuditReport


def _make_report():
    findings = [
        CryptoFinding("app.py", 5, "rsa.generate_private_key(...)", "RSA", "keygen"),
        CryptoFinding("auth.py", 12, "ECDSA(hashes.SHA256())", "ECC", "sign"),
        CryptoFinding("client.py", 3, "ECDH()", "ECC", "handshake"),
    ]
    scorer = RiskScorer()
    assessments = scorer.score_all(findings)
    plans = MigrationPlanner().plan_all(assessments)
    return AuditReport(plans, scan_root="/tmp/project")


def test_summary_counts():
    report = _make_report()
    s = report.summary()
    assert s.total_findings == 3
    assert s.unique_files == 3
    assert "RSA" in s.by_algorithm
    assert "ECC" in s.by_algorithm


def test_summary_effort_positive():
    report = _make_report()
    assert report.summary().total_effort_days > 0


def test_to_dict_structure():
    report = _make_report()
    d = report.to_dict()
    assert "summary" in d
    assert "roadmap" in d
    assert len(d["roadmap"]) == 3
    first = d["roadmap"][0]
    assert "risk_level" in first
    assert "pqc_replacement" in first
    assert "steps" in first


def test_json_roundtrip():
    report = _make_report()
    d = report.to_dict()
    dumped = json.dumps(d)
    loaded = json.loads(dumped)
    assert loaded["summary"]["total_findings"] == 3


def test_text_output_contains_key_info():
    report = _make_report()
    text = report.to_text()
    assert "CRITICAL" in text or "HIGH" in text
    assert "ML-KEM" in text or "ML-DSA" in text
    assert "RSA" in text
    assert "ECC" in text


def test_save_json(tmp_path):
    report = _make_report()
    out = tmp_path / "report.json"
    report.save_json(out)
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["summary"]["total_findings"] == 3
