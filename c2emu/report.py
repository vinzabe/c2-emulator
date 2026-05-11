"""Aggregate emulation report: execution + detection coverage scoring."""
from __future__ import annotations
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List

from .detection import DetectionEngine, DetectionMatch
from .executor import ExecutionResult


SEVERITY_WEIGHT = {"low": 1, "medium": 3, "high": 7, "critical": 12}


@dataclass
class EmulationReport:
    execution: ExecutionResult
    matches: List[DetectionMatch]
    coverage_score: float                # 0..100
    severity_breakdown: Dict[str, int] = field(default_factory=dict)
    technique_coverage: Dict[str, bool] = field(default_factory=dict)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "coverage_score": round(self.coverage_score, 2),
            "summary": self.summary,
            "severity_breakdown": dict(self.severity_breakdown),
            "technique_coverage": dict(self.technique_coverage),
            "matches": [m.to_dict() for m in self.matches],
            "execution": self.execution.to_dict(),
        }


def build_report(execution: ExecutionResult,
                  engine: DetectionEngine) -> EmulationReport:
    matches = engine.evaluate(execution)
    sev_counts = Counter(m.severity for m in matches)
    weighted = sum(SEVERITY_WEIGHT.get(m.severity, 0) for m in matches)
    # Maximum *possible* if every rule fired at its severity
    max_possible = sum(SEVERITY_WEIGHT.get(r.severity, 0) for r in engine.rules)
    coverage = (weighted / max_possible * 100.0) if max_possible else 0.0
    coverage = min(coverage, 100.0)

    # Technique coverage: per executed technique, did *any* rule match?
    matched_log_lines = {m.matched_log for m in matches if m.matched_log}
    matched_artifact_keys = {
        (m.matched_artifact.get("type"), m.matched_artifact.get("name"))
        for m in matches if m.matched_artifact
    }
    technique_coverage: Dict[str, bool] = {}
    for sr in execution.steps:
        if not sr.evidence:
            technique_coverage[sr.step.technique_id] = False
            continue
        hit = any(line in matched_log_lines for line in sr.evidence.log_lines)
        if not hit:
            for art in sr.evidence.artifacts:
                if (art.type, art.name) in matched_artifact_keys:
                    hit = True
                    break
        technique_coverage[sr.step.technique_id] = hit

    detected_techs = sum(1 for v in technique_coverage.values() if v)
    total_techs = len(technique_coverage)
    summary = (f"Coverage {coverage:.0f}/100 -- "
                 f"{detected_techs}/{total_techs} executed techniques fired at "
                 f"least one detection rule. Severity breakdown: "
                 + ", ".join(f"{k}:{v}" for k, v in sorted(sev_counts.items())))
    return EmulationReport(
        execution=execution, matches=matches,
        coverage_score=coverage, severity_breakdown=dict(sev_counts),
        technique_coverage=technique_coverage, summary=summary,
    )
