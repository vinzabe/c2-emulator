"""Campaign executor: runs each step inside a sandboxed workdir.

Refuses to start unless the workdir is an existing directory and is
writable. All techniques receive the same workdir; they're responsible
for sandboxing their own writes via Technique._safe_join().
"""
from __future__ import annotations
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .campaign import Campaign, CampaignStep
from .registry import DENY_LIST, TechniqueRegistry
from .techniques.base import Evidence


@dataclass
class StepResult:
    step: CampaignStep
    ok: bool
    started_at: float
    elapsed_ms: float
    evidence: Optional[Evidence] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step.to_dict(),
            "ok": self.ok,
            "started_at": self.started_at,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "error": self.error,
        }


@dataclass
class ExecutionResult:
    campaign: Campaign
    workdir: str
    steps: List[StepResult] = field(default_factory=list)

    def all_log_lines(self) -> List[str]:
        out: List[str] = []
        for s in self.steps:
            if s.evidence:
                out.extend(s.evidence.log_lines)
        return out

    def all_artifacts(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for s in self.steps:
            if s.evidence:
                out.extend(a.to_dict() for a in s.evidence.artifacts)
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign": self.campaign.to_dict(),
            "workdir": self.workdir,
            "steps": [s.to_dict() for s in self.steps],
        }


class CampaignExecutor:
    def __init__(self, registry: TechniqueRegistry):
        self.registry = registry

    # ------------------------------------------------------------------
    def execute(self, campaign: Campaign, *, workdir: str,
                  fail_fast: bool = False) -> ExecutionResult:
        if not isinstance(workdir, str) or not workdir:
            raise ValueError("workdir required")
        if not os.path.isdir(workdir):
            raise ValueError(f"workdir does not exist: {workdir}")
        if not os.access(workdir, os.W_OK):
            raise PermissionError(f"workdir not writable: {workdir}")

        result = ExecutionResult(campaign=campaign, workdir=workdir)
        for step in campaign.steps:
            sr = self._execute_step(step, workdir)
            result.steps.append(sr)
            if not sr.ok and fail_fast:
                break
        # Write a campaign-level audit log (defensive forensics output).
        audit_path = os.path.join(workdir, "_campaign_audit.json")
        with open(audit_path, "w") as f:
            json.dump(result.to_dict(), f, indent=2, default=str)
        return result

    # ------------------------------------------------------------------
    def _execute_step(self, step: CampaignStep, workdir: str) -> StepResult:
        t0 = time.time()
        if step.technique_id in DENY_LIST:
            return StepResult(step=step, ok=False, started_at=t0,
                                elapsed_ms=0.0,
                                error=f"technique {step.technique_id} is on the deny list")
        tech = self.registry.get(step.technique_id)
        if tech is None:
            return StepResult(step=step, ok=False, started_at=t0,
                                elapsed_ms=0.0,
                                error=f"technique not registered: {step.technique_id}")
        try:
            ev = tech.run(workdir=workdir, parameters=step.parameters)
        except Exception as e:  # pragma: no cover - defensive
            return StepResult(step=step, ok=False, started_at=t0,
                                elapsed_ms=(time.time() - t0) * 1000.0,
                                error=f"{type(e).__name__}: {e}")
        return StepResult(step=step, ok=True, started_at=t0,
                            elapsed_ms=(time.time() - t0) * 1000.0,
                            evidence=ev)
