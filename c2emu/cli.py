"""CLI for c2-emulator."""
from __future__ import annotations
import argparse
import json
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..")))

from c2emu.campaign import Campaign
from c2emu.detection import DetectionEngine, default_rules
from c2emu.executor import CampaignExecutor
from c2emu.planner import LLMCampaignPlanner
from c2emu.registry import default_registry
from c2emu.report import build_report


def cmd_list(args):
    reg = default_registry()
    out = [{
        "technique_id": t.technique_id, "tactic": t.tactic.value,
        "name": t.name, "description": t.description,
    } for t in reg.all()]
    print(json.dumps(out, indent=2))


def cmd_run(args):
    with open(args.campaign) as f:
        campaign = Campaign.from_dict(json.load(f))
    workdir = args.workdir or tempfile.mkdtemp(prefix="c2emu-")
    os.makedirs(workdir, exist_ok=True)
    executor = CampaignExecutor(default_registry())
    result = executor.execute(campaign, workdir=workdir,
                                 fail_fast=args.fail_fast)
    engine = DetectionEngine(default_rules())
    report = build_report(result, engine)
    print(json.dumps(report.to_dict(), indent=2))


def cmd_plan(args):
    from llm_client import LLMClient
    planner = LLMCampaignPlanner(LLMClient(), default_registry(),
                                    model=args.model)
    plan = planner.plan(args.objective, max_steps=args.max_steps)
    out = plan.to_dict()
    if args.execute:
        workdir = args.workdir or tempfile.mkdtemp(prefix="c2emu-")
        os.makedirs(workdir, exist_ok=True)
        executor = CampaignExecutor(default_registry())
        result = executor.execute(plan.campaign, workdir=workdir)
        engine = DetectionEngine(default_rules())
        report = build_report(result, engine)
        out["report"] = report.to_dict()
    print(json.dumps(out, indent=2))


def main(argv=None):
    p = argparse.ArgumentParser(prog="c2emu",
        description="Defensive adversary-emulation harness (sandboxed).")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="List available techniques").set_defaults(func=cmd_list)

    r = sub.add_parser("run", help="Execute a saved campaign JSON")
    r.add_argument("--campaign", required=True)
    r.add_argument("--workdir", default=None)
    r.add_argument("--fail-fast", action="store_true")
    r.set_defaults(func=cmd_run)

    pl = sub.add_parser("plan", help="LLM-plan a campaign from an objective")
    pl.add_argument("--objective", required=True)
    pl.add_argument("--max-steps", type=int, default=8)
    pl.add_argument("--model", default="glm-5.1")
    pl.add_argument("--execute", action="store_true")
    pl.add_argument("--workdir", default=None)
    pl.set_defaults(func=cmd_plan)

    args = p.parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
