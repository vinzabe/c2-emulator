# c2-emulator

A defensive adversary-emulation harness in the spirit of [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), but with the attacker LLM-driven and the techniques implemented as **fully sandboxed stubs that emit synthetic evidence only**. There is no C2 server, no real network egress, no shellcode, and no destructive actions. The point is to give blue teams a way to:

- chain MITRE ATT&CK techniques into realistic multi-stage scenarios,
- generate per-step synthetic telemetry (logs + artifacts),
- score those scenarios against a Sigma-style rule set, and
- have an LLM plan a campaign from a high-level objective and explain the blue-team focus.

## Safety model

- Every technique is a Python class that *describes* the attacker action and writes a deterministic synthetic evidence file inside a sandboxed `workdir`. None of them touches the real registry, real LSASS, or real network.
- A hard **deny list** rejects any technique ID associated with destructive impact (T1485 data destruction, T1486 ransomware, T1490 inhibit recovery, T1491 defacement, T1495 firmware corruption, T1561 disk wipe). The registry refuses to load such IDs and the executor refuses to run them even if smuggled in by the LLM.
- Every technique uses `_safe_join` to refuse path traversal outside the workdir.
- The LLM planner is constrained: it is shown only the IDs already in the registry and the deny list, and any out-of-registry / on-deny-list step it produces is silently dropped before execution.

## Layout

```
c2emu/
  techniques/
    base.py          Technique, Evidence, EvidenceArtifact, TacticPhase
    discovery.py     T1057 T1083 T1016 T1018
    persistence.py   T1547.001 T1053.005 T1136.001
    credential.py    T1003.001 T1552.001
    exfiltration.py  T1041 T1071.001 T1567.002
  registry.py        TechniqueRegistry + DENY_LIST
  campaign.py        Campaign, CampaignStep
  executor.py        sandboxed CampaignExecutor
  detection.py       DetectionEngine + bundled Sigma-flavoured rules
  planner.py         LLMCampaignPlanner
  report.py          coverage scoring (severity-weighted)
  cli.py             c2emu {list, run, plan}
scenarios/persistence_demo.json   sample 7-step campaign
tests/test_c2emu.py               26 unit + live LLM smoke
```

## Quick start

```bash
pip install -r requirements.txt

# Inspect available techniques
python -m c2emu.cli list

# Execute a saved campaign and grade detections
python -m c2emu.cli run --campaign scenarios/persistence_demo.json

# LLM-plan + execute a campaign from an objective
python -m c2emu.cli plan --objective \
    "exercise our EDR's persistence + credential-dumping detections" \
    --execute
```

## Detection coverage scoring

The bundled rule set (intentionally tiny -- swap in your real Sigma rules) weights matches by severity:

| Severity | Weight |
|----------|--------|
| low      | 1      |
| medium   | 3      |
| high     | 7      |
| critical | 12     |

Coverage = sum(matched rule weights) / sum(all rule weights) capped at 100. The report also lists per-step `technique_coverage` so you can see exactly which TTPs flew under the radar.

## Testing

```bash
pytest tests/ -v
LLM_LIVE=1 pytest tests/ -v
```

## License

MIT
