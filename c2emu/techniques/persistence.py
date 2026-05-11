"""Persistence-phase technique stubs."""
from __future__ import annotations
from typing import Any, Dict, Optional

from .base import Evidence, TacticPhase, Technique


class T1547_001_RegistryRunKey(Technique):
    technique_id = "T1547.001"
    tactic = TacticPhase.PERSISTENCE
    name = "Boot or Logon Autostart -- Registry Run Keys"
    description = "Synthetically record a Run-key entry (no real registry write)."

    def run(self, *, workdir: str,
              parameters: Optional[Dict[str, Any]] = None) -> Evidence:
        params = parameters or {}
        value_name = str(params.get("value_name", "WindowsUpdate"))
        target = str(params.get("target", "C:\\\\Users\\\\Public\\\\update.exe"))
        ev = Evidence()
        out = self._safe_join(workdir, "registry_run.json")
        import json
        with open(out, "w") as f:
            json.dump({
                "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "value_name": value_name,
                "value_data": target,
            }, f)
        ev.add_artifact("registry", "Run", value_name=value_name,
                          target=target, hive="HKCU")
        ev.add_log(f"{self._ts()} REGISTRY HKCU\\...\\Run set {value_name}={target}")
        return ev


class T1053_005_ScheduledTask(Technique):
    technique_id = "T1053.005"
    tactic = TacticPhase.PERSISTENCE
    name = "Scheduled Task/Job"
    description = "Synthetically record a scheduled-task creation."

    def run(self, *, workdir: str,
              parameters: Optional[Dict[str, Any]] = None) -> Evidence:
        params = parameters or {}
        task_name = str(params.get("task_name", "GoogleUpdater"))
        cadence = str(params.get("cadence", "every 1 hour"))
        ev = Evidence()
        out = self._safe_join(workdir, f"scheduled_task_{task_name}.txt")
        with open(out, "w") as f:
            f.write(f"Task: {task_name}\nCadence: {cadence}\nAction: synthetic-noop\n")
        ev.add_artifact("file", f"scheduled_task_{task_name}.txt",
                          path=out, task_name=task_name)
        ev.add_log(f"{self._ts()} EXECUTION schtasks /create /tn {task_name}")
        return ev


class T1136_001_LocalAccount(Technique):
    technique_id = "T1136.001"
    tactic = TacticPhase.PERSISTENCE
    name = "Create Account -- Local Account"
    description = "Synthetically record a 'net user' style account creation."

    def run(self, *, workdir: str,
              parameters: Optional[Dict[str, Any]] = None) -> Evidence:
        params = parameters or {}
        username = str(params.get("username", "support_helper"))
        ev = Evidence()
        ev.add_artifact("user", username, action="create_local")
        ev.add_log(f"{self._ts()} EXECUTION net user {username} /add (synthetic)")
        return ev
