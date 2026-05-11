"""Campaign definition: an ordered sequence of technique steps."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class CampaignStep:
    technique_id: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    note: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "parameters": dict(self.parameters),
            "note": self.note,
        }


@dataclass
class Campaign:
    name: str
    objective: str
    steps: List[CampaignStep] = field(default_factory=list)

    def add_step(self, technique_id: str, **parameters) -> CampaignStep:
        step = CampaignStep(
            technique_id=technique_id,
            parameters=parameters.pop("parameters", {}) or {},
            note=parameters.pop("note", None),
        )
        # Allow direct kw passthrough -> parameters dict for ergonomics
        if parameters:
            step.parameters.update(parameters)
        self.steps.append(step)
        return step

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "objective": self.objective,
            "steps": [s.to_dict() for s in self.steps],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Campaign":
        c = cls(name=data["name"], objective=data.get("objective", ""))
        for s in data.get("steps", []):
            c.add_step(s["technique_id"],
                        parameters=s.get("parameters", {}),
                        note=s.get("note"))
        return c
