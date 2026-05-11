"""Base classes for adversary-emulation technique stubs."""
from __future__ import annotations
import enum
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class TacticPhase(str, enum.Enum):
    """MITRE ATT&CK tactic phases (Enterprise)."""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class EvidenceArtifact:
    """A single piece of synthetic evidence produced by a technique."""
    type: str                         # process | file | registry | network | log
    name: str
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"type": self.type, "name": self.name, "detail": self.detail}


@dataclass
class Evidence:
    """Wraps the artifacts a technique emits, plus a synthetic log lines list."""
    artifacts: List[EvidenceArtifact] = field(default_factory=list)
    log_lines: List[str] = field(default_factory=list)

    def add_artifact(self, type: str, name: str, **detail) -> EvidenceArtifact:
        a = EvidenceArtifact(type=type, name=name, detail=dict(detail))
        self.artifacts.append(a)
        return a

    def add_log(self, line: str) -> None:
        self.log_lines.append(line)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifacts": [a.to_dict() for a in self.artifacts],
            "log_lines": list(self.log_lines),
        }


class Technique:
    """Base class. Subclasses set technique_id / tactic / name and implement run()."""
    technique_id: str = ""
    tactic: TacticPhase = TacticPhase.DISCOVERY
    name: str = ""
    description: str = ""
    # Subclass may set safe=False to require explicit allow when destructive
    safe: bool = True

    def run(self, *, workdir: str,
              parameters: Optional[Dict[str, Any]] = None) -> Evidence:
        raise NotImplementedError

    # Helpers for subclasses --------------------------------------------------
    @staticmethod
    def _ts(now: Optional[float] = None) -> str:
        now = now if now is not None else time.time()
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now))

    @staticmethod
    def _safe_join(workdir: str, *parts: str) -> str:
        """Resolve `parts` relative to `workdir` and refuse traversal."""
        candidate = os.path.normpath(os.path.join(workdir, *parts))
        wd = os.path.normpath(workdir)
        if not (candidate == wd or candidate.startswith(wd + os.sep)):
            raise ValueError(f"refusing path outside workdir: {candidate}")
        return candidate
