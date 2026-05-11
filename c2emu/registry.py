"""Technique registry and a default population."""
from __future__ import annotations
from typing import Dict, List, Optional

from .techniques.base import TacticPhase, Technique
from .techniques.discovery import (
    T1016_NetworkConfigDiscovery, T1018_RemoteSystemDiscovery,
    T1057_ProcessDiscovery, T1083_FileDirectoryDiscovery,
)
from .techniques.persistence import (
    T1053_005_ScheduledTask, T1136_001_LocalAccount,
    T1547_001_RegistryRunKey,
)
from .techniques.credential import (
    T1003_001_LSASSDump, T1552_001_CredentialsInFiles,
)
from .techniques.exfiltration import (
    T1041_ExfilC2Channel, T1071_001_WebProtocols,
    T1567_002_ExfilToCloud,
)


# Hard deny-list: technique IDs we will never register or execute even if
# someone asks. None of the bundled techniques map to these, but we want
# defence-in-depth against later extensions.
DENY_LIST = {
    "T1485",   # Data Destruction
    "T1486",   # Data Encrypted for Impact (ransomware)
    "T1490",   # Inhibit System Recovery
    "T1491",   # Defacement
    "T1495",   # Firmware Corruption
    "T1561",   # Disk Wipe
}


class TechniqueRegistry:
    def __init__(self):
        self._techniques: Dict[str, Technique] = {}

    def register(self, technique: Technique) -> None:
        if not getattr(technique, "technique_id", ""):
            raise ValueError("technique missing id")
        if technique.technique_id in DENY_LIST:
            raise ValueError(
                f"technique {technique.technique_id} is on the deny list "
                f"and will not be loaded")
        if technique.technique_id in self._techniques:
            raise ValueError(
                f"technique {technique.technique_id} already registered")
        self._techniques[technique.technique_id] = technique

    def get(self, technique_id: str) -> Optional[Technique]:
        return self._techniques.get(technique_id)

    def all(self) -> List[Technique]:
        return list(self._techniques.values())

    def by_tactic(self, tactic: TacticPhase) -> List[Technique]:
        return [t for t in self._techniques.values() if t.tactic == tactic]

    def __contains__(self, tid: str) -> bool:
        return tid in self._techniques

    def __len__(self) -> int:
        return len(self._techniques)


def default_registry() -> TechniqueRegistry:
    r = TechniqueRegistry()
    for cls in (
        T1057_ProcessDiscovery,
        T1083_FileDirectoryDiscovery,
        T1016_NetworkConfigDiscovery,
        T1018_RemoteSystemDiscovery,
        T1547_001_RegistryRunKey,
        T1053_005_ScheduledTask,
        T1136_001_LocalAccount,
        T1003_001_LSASSDump,
        T1552_001_CredentialsInFiles,
        T1041_ExfilC2Channel,
        T1071_001_WebProtocols,
        T1567_002_ExfilToCloud,
    ):
        r.register(cls())
    return r
