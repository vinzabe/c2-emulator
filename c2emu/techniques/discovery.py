"""Discovery-phase technique stubs (T1057 process discovery, T1083 file/dir,
T1018 remote system, T1016 network configuration)."""
from __future__ import annotations
import os
import socket
from typing import Any, Dict, Optional

from .base import Evidence, TacticPhase, Technique


class T1057_ProcessDiscovery(Technique):
    technique_id = "T1057"
    tactic = TacticPhase.DISCOVERY
    name = "Process Discovery"
    description = "Synthetically enumerate running processes and write a tasklist."

    def run(self, *, workdir: str,
              parameters: Optional[Dict[str, Any]] = None) -> Evidence:
        ev = Evidence()
        # Synthetic process list - never reads /proc, never executes ps.
        synth = [
            {"pid": 4, "name": "System"},
            {"pid": 612, "name": "svchost.exe"},
            {"pid": 1024, "name": "explorer.exe"},
            {"pid": 2048, "name": "powershell.exe"},
            {"pid": 4096, "name": "cmd.exe"},
        ]
        out = self._safe_join(workdir, "tasklist.txt")
        with open(out, "w") as f:
            for p in synth:
                f.write(f"{p['pid']:>6}  {p['name']}\n")
        ev.add_artifact("file", os.path.basename(out),
                          path=out, count=len(synth))
        ev.add_log(f"{self._ts()} EXECUTION powershell.exe Get-Process -> {out}")
        return ev


class T1083_FileDirectoryDiscovery(Technique):
    technique_id = "T1083"
    tactic = TacticPhase.DISCOVERY
    name = "File and Directory Discovery"
    description = "Walk the workdir and write the layout (no real fs walking outside sandbox)."

    def run(self, *, workdir: str,
              parameters: Optional[Dict[str, Any]] = None) -> Evidence:
        ev = Evidence()
        listing_path = self._safe_join(workdir, "dir_listing.txt")
        entries = []
        for root, dirs, files in os.walk(workdir):
            for d in dirs:
                entries.append(os.path.join(os.path.relpath(root, workdir), d) + "/")
            for fn in files:
                entries.append(os.path.join(os.path.relpath(root, workdir), fn))
        # Always include the file itself in the count even if first-run
        with open(listing_path, "w") as f:
            for e in entries:
                f.write(e + "\n")
        ev.add_artifact("file", "dir_listing.txt",
                          path=listing_path, count=len(entries))
        ev.add_log(f"{self._ts()} EXECUTION cmd.exe dir /s -> {listing_path}")
        return ev


class T1016_NetworkConfigDiscovery(Technique):
    technique_id = "T1016"
    tactic = TacticPhase.DISCOVERY
    name = "System Network Configuration Discovery"
    description = "Synthetically write hostname + a fake ipconfig dump."

    def run(self, *, workdir: str,
              parameters: Optional[Dict[str, Any]] = None) -> Evidence:
        ev = Evidence()
        hn = socket.gethostname()  # local hostname only - benign
        out = self._safe_join(workdir, "ipconfig.txt")
        with open(out, "w") as f:
            f.write(f"Host Name . . . . . . . . . : {hn}\n")
            f.write("IPv4 Address. . . . . . . . . : 10.0.0.42\n")
            f.write("Subnet Mask . . . . . . . . . : 255.255.255.0\n")
            f.write("Default Gateway . . . . . . . : 10.0.0.1\n")
        ev.add_artifact("file", "ipconfig.txt",
                          path=out, hostname=hn)
        ev.add_log(f"{self._ts()} EXECUTION ipconfig /all -> {out}")
        return ev


class T1018_RemoteSystemDiscovery(Technique):
    technique_id = "T1018"
    tactic = TacticPhase.DISCOVERY
    name = "Remote System Discovery"
    description = "Synthetic neighbour list (no scanning, no probing)."

    def run(self, *, workdir: str,
              parameters: Optional[Dict[str, Any]] = None) -> Evidence:
        ev = Evidence()
        out = self._safe_join(workdir, "neighbors.txt")
        with open(out, "w") as f:
            for ip in ("10.0.0.1", "10.0.0.5", "10.0.0.42", "10.0.0.99"):
                f.write(ip + "\n")
        ev.add_artifact("file", "neighbors.txt", path=out, count=4)
        ev.add_log(f"{self._ts()} EXECUTION net view -> {out}")
        return ev
