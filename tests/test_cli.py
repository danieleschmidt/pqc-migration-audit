"""Tests for the CLI entry point."""

import json
import textwrap
from pathlib import Path

import pytest

from pqc_migration_audit.cli import main


def make_codebase(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(textwrap.dedent("""\
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    """))
    (tmp_path / "auth.go").write_text(textwrap.dedent("""\
        package main
        import "crypto/ecdsa"
        import "crypto/elliptic"
        func main() {
            k, _ := ecdsa.GenerateKey(elliptic.P256(), nil)
            _ = k
        }
    """))
    return tmp_path


def test_cli_text_output(tmp_path, capsys):
    codebase = make_codebase(tmp_path)
    ret = main([str(codebase)])
    captured = capsys.readouterr()
    assert "RSA" in captured.out or "ECC" in captured.out


def test_cli_json_output(tmp_path, capsys):
    codebase = make_codebase(tmp_path)
    ret = main([str(codebase), "--format", "json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "summary" in data
    assert data["summary"]["total_findings"] >= 1


def test_cli_save_to_file(tmp_path):
    codebase = make_codebase(tmp_path)
    out_file = tmp_path / "report.json"
    main([str(codebase), "--output", str(out_file), "--format", "json"])
    assert out_file.exists()
    data = json.loads(out_file.read_text())
    assert data["summary"]["total_findings"] >= 1


def test_cli_invalid_path(tmp_path, capsys):
    ret = main([str(tmp_path / "nonexistent")])
    assert ret == 1


def test_cli_min_risk_filter(tmp_path, capsys):
    codebase = make_codebase(tmp_path)
    ret = main([str(codebase), "--format", "json", "--min-risk", "CRITICAL"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    for item in data["roadmap"]:
        assert item["risk_level"] == "CRITICAL"


def test_cli_empty_dir_no_crash(tmp_path, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()
    ret = main([str(empty)])
    assert ret == 0
