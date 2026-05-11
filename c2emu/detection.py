"""Detection-rule engine.

Rules are intentionally simple (regex on log lines + artifact-type/name
predicates) so that they can be expressed inline in YAML/JSON without
wiring up a full Sigma compiler. The point of the engine is to grade an
emulation campaign, not to be a SIEM.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Pattern, Sequence

from .executor import ExecutionResult


@dataclass
class DetectionRule:
    rule_id: str
    name: str
    severity: str = "medium"             # low|medium|high|critical
    log_patterns: List[str] = field(default_factory=list)
    artifact_types: List[str] = field(default_factory=list)
    artifact_name_patterns: List[str] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id, "name": self.name,
            "severity": self.severity,
            "log_patterns": list(self.log_patterns),
            "artifact_types": list(self.artifact_types),
            "artifact_name_patterns": list(self.artifact_name_patterns),
            "description": self.description,
        }


@dataclass
class DetectionMatch:
    rule_id: str
    rule_name: str
    severity: str
    matched_log: Optional[str] = None
    matched_artifact: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id, "rule_name": self.rule_name,
            "severity": self.severity,
            "matched_log": self.matched_log,
            "matched_artifact": self.matched_artifact,
        }


class DetectionEngine:
    def __init__(self, rules: Sequence[DetectionRule] = ()):
        self.rules: List[DetectionRule] = []
        self._compiled: Dict[str, List[Pattern[str]]] = {}
        self._compiled_names: Dict[str, List[Pattern[str]]] = {}
        for r in rules:
            self.add_rule(r)

    # ------------------------------------------------------------------
    def add_rule(self, rule: DetectionRule) -> None:
        if not rule.rule_id:
            raise ValueError("rule must have an id")
        if any(r.rule_id == rule.rule_id for r in self.rules):
            raise ValueError(f"duplicate rule_id: {rule.rule_id}")
        if rule.severity not in ("low", "medium", "high", "critical"):
            raise ValueError(f"invalid severity: {rule.severity}")
        self.rules.append(rule)
        self._compiled[rule.rule_id] = [re.compile(p, re.IGNORECASE)
                                          for p in rule.log_patterns]
        self._compiled_names[rule.rule_id] = [re.compile(p, re.IGNORECASE)
                                                for p in rule.artifact_name_patterns]

    # ------------------------------------------------------------------
    def evaluate(self, result: ExecutionResult) -> List[DetectionMatch]:
        matches: List[DetectionMatch] = []
        log_lines = result.all_log_lines()
        artifacts = result.all_artifacts()
        for rule in self.rules:
            patterns = self._compiled[rule.rule_id]
            name_patterns = self._compiled_names[rule.rule_id]

            # Log-line matches
            for line in log_lines:
                if any(p.search(line) for p in patterns):
                    matches.append(DetectionMatch(
                        rule_id=rule.rule_id, rule_name=rule.name,
                        severity=rule.severity, matched_log=line))
                    break  # one line is enough per rule per campaign

            # Artifact matches (type + optional name regex)
            for art in artifacts:
                if rule.artifact_types and art.get("type") not in rule.artifact_types:
                    continue
                name = str(art.get("name", ""))
                if name_patterns and not any(p.search(name) for p in name_patterns):
                    continue
                # If we have artifact_types but no name patterns, the type
                # match is sufficient.
                if rule.artifact_types or name_patterns:
                    matches.append(DetectionMatch(
                        rule_id=rule.rule_id, rule_name=rule.name,
                        severity=rule.severity,
                        matched_artifact=art))
                    break
        return matches


# ---------------------------------------------------------------------------
# A small built-in rule set for the demo.

def default_rules() -> List[DetectionRule]:
    return [
        DetectionRule(
            rule_id="SIGMA_LSASS_DUMP",
            name="Suspicious LSASS dump file",
            severity="critical",
            artifact_types=["file"],
            artifact_name_patterns=[r"^lsass\.dmp$"],
            description="lsass.dmp on disk strongly suggests credential dumping.",
        ),
        DetectionRule(
            rule_id="SIGMA_RUN_KEY",
            name="Run key persistence",
            severity="high",
            log_patterns=[r"REGISTRY HKCU\\.*\\Run set"],
            description="Writes to the autorun Run key.",
        ),
        DetectionRule(
            rule_id="SIGMA_SCHTASK",
            name="Scheduled task created",
            severity="high",
            log_patterns=[r"schtasks /create"],
        ),
        DetectionRule(
            rule_id="SIGMA_BEACON",
            name="Repeating outbound beacon",
            severity="high",
            log_patterns=[r"beacon GET https://.*every \d+s"],
        ),
        DetectionRule(
            rule_id="SIGMA_EXFIL_HTTPS",
            name="Outbound exfiltration over HTTPS",
            severity="critical",
            log_patterns=[r"conn-out POST https://.*\[SYNTHETIC\]"],
        ),
        DetectionRule(
            rule_id="SIGMA_LOCAL_ACCT",
            name="Local account creation",
            severity="medium",
            log_patterns=[r"net user \S+ /add"],
        ),
        DetectionRule(
            rule_id="SIGMA_PROCESS_DISCOVERY",
            name="PowerShell process enumeration",
            severity="low",
            log_patterns=[r"powershell\.exe Get-Process"],
        ),
    ]
