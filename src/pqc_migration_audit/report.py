"""
AuditReport: builds and serializes the final PQC migration audit report.

Output formats: JSON (machine-readable), text summary (human-readable).
"""

import json
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .planner import MigrationPlan
from .risk import RiskLevel


@dataclass
class ReportSummary:
    total_findings: int
    unique_files: int
    by_risk: dict[str, int]
    by_algorithm: dict[str, int]
    total_effort_days: int
    scan_root: str
    generated_at: str


class AuditReport:
    def __init__(self, plans: list[MigrationPlan], scan_root: str):
        self.plans = plans
        self.scan_root = scan_root
        self.generated_at = datetime.now(tz=timezone.utc).isoformat()

    # ── Summary ──────────────────────────────────────────────────────────────

    def summary(self) -> ReportSummary:
        risk_counts: Counter = Counter(
            p.risk_assessment.risk_level.value for p in self.plans
        )
        algo_counts: Counter = Counter(
            p.finding.algorithm for p in self.plans
        )
        files = {p.finding.file_path for p in self.plans}
        total_effort = sum(p.estimated_effort_days for p in self.plans)

        return ReportSummary(
            total_findings=len(self.plans),
            unique_files=len(files),
            by_risk=dict(risk_counts),
            by_algorithm=dict(algo_counts),
            total_effort_days=total_effort,
            scan_root=self.scan_root,
            generated_at=self.generated_at,
        )

    # ── JSON output ───────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": asdict(self.summary()),
            "roadmap": [self._plan_to_dict(p) for p in self.plans],
        }

    def _plan_to_dict(self, p: MigrationPlan) -> dict[str, Any]:
        return {
            "risk_level": p.risk_assessment.risk_level.value,
            "risk_score": p.risk_assessment.score,
            "algorithm": p.finding.algorithm,
            "pqc_replacement": p.pqc_algorithm,
            "file": p.finding.file_path,
            "line": p.finding.line_number,
            "line_text": p.finding.line_text,
            "usage_context": p.finding.usage_context,
            "key_size": p.finding.key_size,
            "migration_description": p.migration_description,
            "steps": [{"order": s.order, "action": s.action} for s in p.steps],
            "estimated_effort_days": p.estimated_effort_days,
            "timeline_recommendation": p.timeline_recommendation,
            "reference_url": p.reference_url,
            "risk_rationale": p.risk_assessment.rationale,
        }

    def save_json(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    # ── Text summary ─────────────────────────────────────────────────────────

    def to_text(self) -> str:
        s = self.summary()
        lines: list[str] = [
            "═" * 70,
            "  PQC Migration Audit Report",
            f"  Generated: {s.generated_at}",
            f"  Scan root: {s.scan_root}",
            "═" * 70,
            "",
            "SUMMARY",
            "-------",
            f"  Total findings  : {s.total_findings}",
            f"  Unique files    : {s.unique_files}",
            f"  Est. total effort: {s.total_effort_days} developer-days",
            "",
            "  Risk breakdown:",
        ]
        for lvl in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW):
            count = s.by_risk.get(lvl.value, 0)
            lines.append(f"    {lvl.value:<10} {count}")
        lines += [
            "",
            "  Algorithms found:",
        ]
        for algo, cnt in sorted(s.by_algorithm.items(), key=lambda x: -x[1]):
            lines.append(f"    {algo:<6} {cnt}")

        lines += ["", "MIGRATION ROADMAP (sorted by risk)", "-" * 70]

        for i, p in enumerate(self.plans, start=1):
            rl = p.risk_assessment.risk_level.value
            lines += [
                "",
                f"  [{i}] {rl} — {p.finding.algorithm} ({p.finding.usage_context})",
                f"       File  : {p.finding.file_path}:{p.finding.line_number}",
                f"       Code  : {p.finding.line_text[:72]}",
                f"       → Replace with: {p.pqc_algorithm}",
                f"       {p.migration_description}",
                f"       Effort : ~{p.estimated_effort_days} dev-days",
                f"       Timeline: {p.timeline_recommendation}",
                f"       Ref    : {p.reference_url}",
                "       Steps:",
            ]
            for step in p.steps:
                lines.append(f"         {step.order}. {step.action}")

        lines += ["", "═" * 70]
        return "\n".join(lines)

    def print_summary(self) -> None:
        print(self.to_text())
