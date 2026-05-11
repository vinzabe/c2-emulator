"""Tests for c2-emulator."""
import json
import os
import sys
import tempfile
import types

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..")))

from c2emu.campaign import Campaign
from c2emu.detection import DetectionEngine, DetectionRule, default_rules
from c2emu.executor import CampaignExecutor
from c2emu.planner import LLMCampaignPlanner, CampaignPlan
from c2emu.registry import (
    DENY_LIST, TechniqueRegistry, default_registry,
)
from c2emu.report import build_report
from c2emu.techniques.base import (
    Evidence, EvidenceArtifact, TacticPhase, Technique,
)


SCENARIO = os.path.normpath(os.path.join(
    _HERE, "..", "scenarios", "persistence_demo.json"))


# ---------------------------------------------------------------------------
# Registry

class TestRegistry:

    def test_default_loads_all(self):
        r = default_registry()
        assert len(r) >= 10
        ids = {t.technique_id for t in r.all()}
        assert "T1057" in ids and "T1003.001" in ids and "T1547.001" in ids

    def test_register_rejects_deny_list(self):
        class Bad(Technique):
            technique_id = "T1486"  # ransomware
            tactic = TacticPhase.IMPACT
            name = "Bad"
        r = TechniqueRegistry()
        with pytest.raises(ValueError) as ex:
            r.register(Bad())
        assert "deny" in str(ex.value).lower()

    def test_register_rejects_dup(self):
        from c2emu.techniques.discovery import T1057_ProcessDiscovery
        r = TechniqueRegistry()
        r.register(T1057_ProcessDiscovery())
        with pytest.raises(ValueError):
            r.register(T1057_ProcessDiscovery())

    def test_register_rejects_missing_id(self):
        class Empty(Technique):
            technique_id = ""
            name = "x"
        with pytest.raises(ValueError):
            TechniqueRegistry().register(Empty())

    def test_by_tactic(self):
        r = default_registry()
        d = r.by_tactic(TacticPhase.DISCOVERY)
        assert all(t.tactic == TacticPhase.DISCOVERY for t in d)
        assert len(d) >= 3


# ---------------------------------------------------------------------------
# Sandbox

class TestSandbox:

    def test_safe_join_blocks_traversal(self, tmp_path):
        from c2emu.techniques.discovery import T1083_FileDirectoryDiscovery
        t = T1083_FileDirectoryDiscovery()
        with pytest.raises(ValueError):
            t._safe_join(str(tmp_path), "..", "etc", "passwd")

    def test_safe_join_allows_inside(self, tmp_path):
        from c2emu.techniques.discovery import T1083_FileDirectoryDiscovery
        t = T1083_FileDirectoryDiscovery()
        p = t._safe_join(str(tmp_path), "sub", "file.txt")
        assert p.startswith(str(tmp_path))


# ---------------------------------------------------------------------------
# Techniques

class TestTechniques:

    def test_process_discovery(self, tmp_path):
        from c2emu.techniques.discovery import T1057_ProcessDiscovery
        ev = T1057_ProcessDiscovery().run(workdir=str(tmp_path))
        assert any(a.name == "tasklist.txt" for a in ev.artifacts)
        assert any("Get-Process" in line for line in ev.log_lines)
        assert os.path.isfile(os.path.join(str(tmp_path), "tasklist.txt"))

    def test_lsass_dump_creates_marker(self, tmp_path):
        from c2emu.techniques.credential import T1003_001_LSASSDump
        ev = T1003_001_LSASSDump().run(workdir=str(tmp_path))
        path = os.path.join(str(tmp_path), "lsass.dmp")
        assert os.path.isfile(path)
        with open(path, "rb") as f:
            blob = f.read()
        assert b"SYNTHETIC" in blob, "must be synthetic marker only"
        assert any(a.detail.get("synthetic") for a in ev.artifacts)

    def test_run_key_recorded(self, tmp_path):
        from c2emu.techniques.persistence import T1547_001_RegistryRunKey
        target = "C:\\evil.exe"
        ev = T1547_001_RegistryRunKey().run(
            workdir=str(tmp_path),
            parameters={"value_name": "Stage1", "target": target})
        a = next(a for a in ev.artifacts if a.type == "registry")
        assert a.detail["value_name"] == "Stage1"
        assert a.detail["target"] == target
        # synthetic registry persistence shows in log
        assert any("Stage1" in l for l in ev.log_lines)

    def test_exfil_no_network(self, tmp_path, monkeypatch):
        from c2emu.techniques.exfiltration import T1041_ExfilC2Channel
        # Monkeypatch socket to ensure no network is touched
        import socket
        def boom(*a, **kw):
            raise AssertionError("network call attempted")
        monkeypatch.setattr(socket, "socket", boom)
        ev = T1041_ExfilC2Channel().run(workdir=str(tmp_path),
                                            parameters={"target_host": "x.invalid",
                                                          "bytes": 100})
        assert any(a.detail.get("synthetic") for a in ev.artifacts)


# ---------------------------------------------------------------------------
# Executor

class TestExecutor:

    def test_run_full_scenario(self, tmp_path):
        with open(SCENARIO) as f:
            campaign = Campaign.from_dict(json.load(f))
        executor = CampaignExecutor(default_registry())
        result = executor.execute(campaign, workdir=str(tmp_path))
        assert all(s.ok for s in result.steps)
        # Audit file written
        assert os.path.isfile(os.path.join(str(tmp_path), "_campaign_audit.json"))
        # All log lines present
        assert len(result.all_log_lines()) >= len(campaign.steps)

    def test_unknown_technique(self, tmp_path):
        c = Campaign(name="t", objective="t")
        c.add_step("T9999")
        executor = CampaignExecutor(default_registry())
        result = executor.execute(c, workdir=str(tmp_path))
        assert not result.steps[0].ok
        assert "not registered" in result.steps[0].error

    def test_deny_list_blocked_at_execute(self, tmp_path):
        c = Campaign(name="t", objective="t")
        c.steps.append(__import__("c2emu.campaign", fromlist=["CampaignStep"]
                                   ).CampaignStep(technique_id="T1486"))
        executor = CampaignExecutor(default_registry())
        result = executor.execute(c, workdir=str(tmp_path))
        assert not result.steps[0].ok
        assert "deny" in result.steps[0].error.lower()

    def test_missing_workdir(self):
        c = Campaign(name="t", objective="t")
        executor = CampaignExecutor(default_registry())
        with pytest.raises(ValueError):
            executor.execute(c, workdir="/no/such/dir/please")

    def test_fail_fast(self, tmp_path):
        c = Campaign(name="t", objective="t")
        c.add_step("T1057")
        c.add_step("T9999")  # bad
        c.add_step("T1083")
        executor = CampaignExecutor(default_registry())
        result = executor.execute(c, workdir=str(tmp_path), fail_fast=True)
        assert len(result.steps) == 2
        assert result.steps[0].ok is True and result.steps[1].ok is False


# ---------------------------------------------------------------------------
# Detection

class TestDetection:

    def _ran(self, tmp_path):
        with open(SCENARIO) as f:
            campaign = Campaign.from_dict(json.load(f))
        executor = CampaignExecutor(default_registry())
        return executor.execute(campaign, workdir=str(tmp_path))

    def test_default_rules_fire(self, tmp_path):
        result = self._ran(tmp_path)
        engine = DetectionEngine(default_rules())
        matches = engine.evaluate(result)
        ids = {m.rule_id for m in matches}
        # Expect lsass + run key + scheduled-task + beacon + exfil rules to fire
        assert "SIGMA_LSASS_DUMP" in ids
        assert "SIGMA_RUN_KEY" in ids
        assert "SIGMA_SCHTASK" in ids
        assert "SIGMA_BEACON" in ids
        assert "SIGMA_EXFIL_HTTPS" in ids

    def test_report_score_in_range(self, tmp_path):
        result = self._ran(tmp_path)
        engine = DetectionEngine(default_rules())
        rep = build_report(result, engine)
        assert 0 <= rep.coverage_score <= 100
        assert rep.severity_breakdown.get("critical", 0) >= 1
        assert "Coverage" in rep.summary

    def test_engine_rejects_dup_rule(self):
        e = DetectionEngine([
            DetectionRule(rule_id="X", name="x", log_patterns=["a"]),
        ])
        with pytest.raises(ValueError):
            e.add_rule(DetectionRule(rule_id="X", name="y", log_patterns=["b"]))

    def test_engine_rejects_invalid_severity(self):
        with pytest.raises(ValueError):
            DetectionEngine([DetectionRule(rule_id="x", name="x",
                                              severity="apocalyptic",
                                              log_patterns=["a"])])

    def test_engine_rejects_missing_id(self):
        e = DetectionEngine()
        with pytest.raises(ValueError):
            e.add_rule(DetectionRule(rule_id="", name="x", log_patterns=["a"]))


# ---------------------------------------------------------------------------
# Planner

class FakeLLM:
    def __init__(self, content): self.content = content
    def chat(self, messages, **kw):
        return types.SimpleNamespace(content=self.content)


class TestPlanner:

    def test_parses_plan(self):
        body = json.dumps({
            "name": "demo",
            "objective": "test",
            "steps": [
                {"technique_id": "T1057", "parameters": {}, "note": "discovery"},
                {"technique_id": "T1547.001",
                  "parameters": {"value_name": "Up"}, "note": "persist"},
            ],
            "rationale": "exercise persistence detections",
            "blue_team_focus": ["registry-monitoring", "EDR persistence rules"],
        })
        planner = LLMCampaignPlanner(FakeLLM(body), default_registry())
        plan = planner.plan("test")
        assert isinstance(plan, CampaignPlan)
        assert len(plan.campaign.steps) == 2
        assert plan.campaign.steps[1].parameters["value_name"] == "Up"
        assert "registry-monitoring" in plan.blue_team_focus

    def test_filters_unknown_techniques(self):
        body = json.dumps({
            "name": "x", "objective": "y",
            "steps": [
                {"technique_id": "T1057"},
                {"technique_id": "T99999"},  # not in registry
            ],
        })
        plan = LLMCampaignPlanner(FakeLLM(body), default_registry()).plan("y")
        ids = [s.technique_id for s in plan.campaign.steps]
        assert ids == ["T1057"]

    def test_filters_deny_list(self):
        body = json.dumps({
            "name": "x", "objective": "y",
            "steps": [
                {"technique_id": "T1057"},
                {"technique_id": "T1486"},  # ransomware
            ],
        })
        plan = LLMCampaignPlanner(FakeLLM(body), default_registry()).plan("y")
        ids = [s.technique_id for s in plan.campaign.steps]
        assert "T1486" not in ids
        assert "T1057" in ids

    def test_handles_garbage(self):
        plan = LLMCampaignPlanner(FakeLLM("nope"), default_registry()).plan("y")
        assert plan.campaign.name == "invalid-plan"
        assert plan.campaign.steps == []

    def test_fenced_json(self):
        body = ("```json\n" +
                  json.dumps({"name": "x", "objective": "y",
                                "steps": [{"technique_id": "T1057"}]})
                  + "\n```")
        plan = LLMCampaignPlanner(FakeLLM(body), default_registry()).plan("y")
        assert len(plan.campaign.steps) == 1


# ---------------------------------------------------------------------------
# Live LLM smoke

@pytest.mark.skipif(not os.environ.get("LLM_LIVE"),
                     reason="LLM_LIVE not set")
def test_live_llm_planner(tmp_path):
    from llm_client import LLMClient
    planner = LLMCampaignPlanner(
        LLMClient(timeout=180), default_registry(), model="glm-5.1")
    plan = planner.plan(
        "Exercise our EDR's persistence + credential-dumping detections "
        "on a Windows endpoint. Use lab/sandbox techniques only.",
        max_steps=6,
    )
    # Must produce >=1 valid step within registry
    assert len(plan.campaign.steps) >= 1
    # Must NOT include deny-list IDs
    for s in plan.campaign.steps:
        assert s.technique_id not in DENY_LIST
    # Should include something persistence- or cred-flavoured
    tids = {s.technique_id for s in plan.campaign.steps}
    assert any(t.startswith(("T1547", "T1053", "T1003", "T1136"))
                  for t in tids), tids

    # Run the plan and confirm detections fire
    executor = CampaignExecutor(default_registry())
    result = executor.execute(plan.campaign, workdir=str(tmp_path))
    rep = build_report(result, DetectionEngine(default_rules()))
    print(f"\n[live] steps={len(plan.campaign.steps)} "
            f"matches={len(rep.matches)} coverage={rep.coverage_score:.1f}")
    assert rep.coverage_score > 0
