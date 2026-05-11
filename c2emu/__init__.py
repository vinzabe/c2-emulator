"""c2-emulator: defensive adversary-emulation harness.

This is *not* a C2 server. It is a sandboxed harness modelled after Atomic
Red Team: each "technique" is a small stub that produces realistic
evidence artifacts (log lines, marker files, registry-style key/value
records) inside a workdir, *without* performing any damaging action and
without any network I/O.

Use it to:
    - chain techniques into multi-stage adversary emulations
    - generate synthetic telemetry for blue-team detection-engineering
    - score Sigma-style rules against the resulting evidence
    - have an LLM plan an emulation campaign from a high-level objective

The framework refuses to run anything outside its sandbox workdir and
enforces a deny-list for technique IDs that would map to destructive
real-world behaviour.
"""
from .techniques.base import (
    Technique, Evidence, EvidenceArtifact,
    TacticPhase,
)
from .registry import TechniqueRegistry, default_registry
from .campaign import Campaign, CampaignStep
from .executor import CampaignExecutor, ExecutionResult
from .detection import DetectionEngine, DetectionRule, DetectionMatch
from .planner import LLMCampaignPlanner, CampaignPlan
from .report import EmulationReport, build_report

__all__ = [
    "Technique", "Evidence", "EvidenceArtifact", "TacticPhase",
    "TechniqueRegistry", "default_registry",
    "Campaign", "CampaignStep",
    "CampaignExecutor", "ExecutionResult",
    "DetectionEngine", "DetectionRule", "DetectionMatch",
    "LLMCampaignPlanner", "CampaignPlan",
    "EmulationReport", "build_report",
]
