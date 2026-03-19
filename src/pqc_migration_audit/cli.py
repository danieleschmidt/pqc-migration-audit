"""
CLI: pqc-audit /path/to/codebase [--output report.json] [--format text|json]

Uses stdlib only (argparse, pathlib, json).
"""

import argparse
import json
import sys
from pathlib import Path

from .scanner import CryptoScanner
from .risk import RiskScorer
from .planner import MigrationPlanner
from .report import AuditReport


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pqc-audit",
        description=(
            "Post-Quantum Cryptography Migration Auditor — "
            "scans a codebase for quantum-vulnerable cryptography and "
            "generates a prioritised migration roadmap."
        ),
    )
    parser.add_argument(
        "codebase",
        metavar="PATH",
        help="Path to the codebase directory to scan.",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Write JSON report to FILE (default: stdout).",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["json", "text"],
        default="text",
        help="Output format: 'json' or 'text' (default: text).",
    )
    parser.add_argument(
        "--exclude",
        metavar="DIR",
        action="append",
        default=[],
        help="Directory names to exclude (repeatable).",
    )
    parser.add_argument(
        "--min-risk",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default="LOW",
        help="Only include findings at or above this risk level.",
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version="pqc-audit 1.0.0",
    )

    args = parser.parse_args(argv)

    root = Path(args.codebase).expanduser().resolve()
    if not root.is_dir():
        print(f"error: '{root}' is not a directory.", file=sys.stderr)
        return 1

    # ── Scan ─────────────────────────────────────────────────────────────────
    exclude = set(args.exclude) if args.exclude else None
    print(f"[pqc-audit] Scanning {root} …", file=sys.stderr)

    scanner = CryptoScanner()
    findings = list(scanner.scan_directory(root, exclude_dirs=exclude))
    print(f"[pqc-audit] {len(findings)} raw findings.", file=sys.stderr)

    # ── Score ─────────────────────────────────────────────────────────────────
    scorer = RiskScorer()
    assessments = scorer.score_all(findings)

    # Apply risk filter
    _RISK_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    min_score = _RISK_ORDER[args.min_risk]
    assessments = [a for a in assessments
                   if _RISK_ORDER[a.risk_level.value] >= min_score]

    # ── Plan ──────────────────────────────────────────────────────────────────
    planner = MigrationPlanner()
    plans = planner.plan_all(assessments)

    # ── Report ────────────────────────────────────────────────────────────────
    report = AuditReport(plans, scan_root=str(root))

    if args.format == "json":
        output = json.dumps(report.to_dict(), indent=2)
    else:
        output = report.to_text()

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"[pqc-audit] Report written to {args.output}", file=sys.stderr)
    else:
        print(output)

    # Exit code: 1 if any CRITICAL findings, 0 otherwise
    has_critical = any(
        p.risk_assessment.risk_level.value == "CRITICAL" for p in plans
    )
    return 1 if has_critical else 0


if __name__ == "__main__":
    sys.exit(main())
