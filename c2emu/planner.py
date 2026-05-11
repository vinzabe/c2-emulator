"""LLM campaign planner.

Given a high-level objective (e.g. "exercise our EDR's persistence + cred
detections") and the registry of available techniques, the LLM returns a
JSON campaign that the user can execute. The planner refuses to emit
techniques on the deny-list and refuses to emit techniques the registry
does not contain.
"""
from __future__ import annotations
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .campaign import Campaign, CampaignStep
from .registry import DENY_LIST, TechniqueRegistry


@dataclass
class CampaignPlan:
    campaign: Campaign
    rationale: str = ""
    blue_team_focus: List[str] = field(default_factory=list)
    raw: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign": self.campaign.to_dict(),
            "rationale": self.rationale,
            "blue_team_focus": list(self.blue_team_focus),
        }


class LLMCampaignPlanner:
    SYSTEM = (
        "You are a defensive adversary-emulation planner used by blue teams "
        "for tabletop exercises. You output a CAMPAIGN PLAN that maps to a "
        "set of MITRE ATT&CK technique stubs available locally. You never "
        "produce real exploit code, real shellcode, or instructions for "
        "destructive actions. You operate strictly within the provided "
        "technique registry.\n\n"
        "Reply with strict JSON of the form:\n"
        "{ \"name\": str, \"objective\": str, \"steps\": [\n"
        "    { \"technique_id\": str, \"parameters\": object, \"note\": str }\n"
        "  ], \"rationale\": str, \"blue_team_focus\": [str] }\n"
        "Only use technique_id values listed in the AVAILABLE_TECHNIQUES list."
    )

    def __init__(self, llm_client, registry: TechniqueRegistry, *,
                  model: str = "glm-5.1", temperature: float = 0.2,
                  max_tokens: int = 1400):
        self.llm = llm_client
        self.registry = registry
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens

    # ------------------------------------------------------------------
    def plan(self, objective: str, *,
              max_steps: int = 8) -> CampaignPlan:
        catalogue = [{
            "technique_id": t.technique_id,
            "tactic": t.tactic.value,
            "name": t.name,
            "description": t.description,
        } for t in self.registry.all()]
        user = {
            "objective": objective,
            "max_steps": max_steps,
            "available_techniques": catalogue,
            "deny_list": sorted(DENY_LIST),
        }
        msgs = [
            {"role": "system", "content": self.SYSTEM},
            {"role": "user", "content": json.dumps(user, indent=2)},
        ]
        resp = self.llm.chat(msgs, model=self.model,
                              temperature=self.temperature,
                              max_tokens=self.max_tokens)
        return self._parse(resp.content, objective=objective)

    # ------------------------------------------------------------------
    @staticmethod
    def _extract_json(text: str) -> str:
        t = (text or "").strip()
        m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", t, re.DOTALL)
        if m:
            return m.group(1)
        m = re.search(r"\{.*\}", t, re.DOTALL)
        return m.group(0) if m else t

    def _parse(self, content: str, *, objective: str) -> CampaignPlan:
        try:
            data = json.loads(self._extract_json(content))
        except json.JSONDecodeError:
            campaign = Campaign(name="invalid-plan", objective=objective)
            return CampaignPlan(campaign=campaign,
                                  rationale="LLM output unparseable",
                                  raw=content[:2000])
        name = str(data.get("name", "llm-planned-campaign"))
        obj = str(data.get("objective", objective))
        campaign = Campaign(name=name, objective=obj)
        for raw_step in (data.get("steps") or []):
            tid = str(raw_step.get("technique_id", "")).strip()
            if not tid:
                continue
            if tid in DENY_LIST:
                # Silent drop with a note in rationale below
                continue
            if tid not in self.registry:
                continue
            params = raw_step.get("parameters") or {}
            if not isinstance(params, dict):
                params = {}
            note = raw_step.get("note")
            campaign.add_step(tid, parameters=params,
                                note=str(note) if note else None)
        rationale = str(data.get("rationale", "")).strip()
        focus = data.get("blue_team_focus") or []
        if isinstance(focus, str):
            focus = [focus]
        focus = [str(x) for x in focus]
        return CampaignPlan(campaign=campaign, rationale=rationale,
                              blue_team_focus=focus, raw=content[:2000])
