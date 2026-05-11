"""Credential-access stubs (synthetic only - no real secret extraction)."""
from __future__ import annotations
from typing import Any, Dict, Optional

from .base import Evidence, TacticPhase, Technique


class T1003_001_LSASSDump(Technique):
    technique_id = "T1003.001"
    tactic = TacticPhase.CREDENTIAL_ACCESS
    name = "OS Credential Dumping -- LSASS Memory"
    description = "Synthetically write a marker file resembling an lsass.dmp."

    def run(self, *, workdir: str,
              parameters: Optional[Dict[str, Any]] = None) -> Evidence:
        ev = Evidence()
        out = self._safe_join(workdir, "lsass.dmp")
        with open(out, "wb") as f:
            f.write(b"SYNTHETIC-LSASS-MARKER\n")  # not a real minidump
        ev.add_artifact("file", "lsass.dmp", path=out,
                          synthetic=True, size=len(b"SYNTHETIC-LSASS-MARKER\n"))
        ev.add_log(f"{self._ts()} EXECUTION procdump-like tool -> {out}")
        return ev


class T1552_001_CredentialsInFiles(Technique):
    technique_id = "T1552.001"
    tactic = TacticPhase.CREDENTIAL_ACCESS
    name = "Unsecured Credentials -- Credentials In Files"
    description = "Synthetically grep for common secret-bearing filenames."

    def run(self, *, workdir: str,
              parameters: Optional[Dict[str, Any]] = None) -> Evidence:
        ev = Evidence()
        # Synthetic hits - we never actually read the user's filesystem
        out = self._safe_join(workdir, "credgrep.txt")
        hits = [
            ("/srv/app/.env", "DB_PASSWORD=<SYNTH>"),
            ("/home/user/.aws/credentials", "aws_access_key_id=<SYNTH>"),
            ("/etc/nginx/htpasswd", "<SYNTH>"),
        ]
        with open(out, "w") as f:
            for p, h in hits:
                f.write(f"{p}: {h}\n")
        ev.add_artifact("file", "credgrep.txt", path=out, hits=len(hits))
        ev.add_log(f"{self._ts()} EXECUTION grep -r 'password|secret|api_key' -> {out}")
        return ev
