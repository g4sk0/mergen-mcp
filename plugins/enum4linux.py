import json
import re
from typing import Any, Dict, List

from plugins import register
from plugins.base import BaseTool, ToolResult


@register
class Enum4LinuxPlugin(BaseTool):
    name = "enum4linux"
    description = "SMB/LDAP enumeration: users, groups, shares, password policies."
    category = "enum"
    requires = ["enum4linux-ng"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        cmd = [
            "enum4linux-ng",
            "-A",        # all checks
            "-oJ", "-",  # JSON to stdout
            target,
        ]

        stdout, stderr, rc = await self._exec(cmd, timeout=180)

        findings, suggested = self._parse(stdout, stderr)

        return ToolResult(
            tool=self.name,
            target=target,
            success=bool(findings),
            raw_output=stdout or stderr,
            findings=findings,
            suggested_next=suggested,
            risk_score=self._risk(findings),
            metadata={"target": target},
        )

    def _parse(self, stdout: str, stderr: str) -> tuple:
        findings = []
        suggested = set()

        try:
            data = json.loads(stdout)
            users = data.get("users", {})
            for uid, udata in users.items():
                findings.append({"type": "user", "username": udata.get("username", uid)})
                suggested.add("hydra")

            shares = data.get("shares", {})
            for share, sdata in shares.items():
                findings.append({
                    "type": "share",
                    "name": share,
                    "access": sdata.get("access", "?"),
                })
                if sdata.get("access") in ["READ", "READ, WRITE"]:
                    suggested.add("smbmap")

            groups = data.get("groups", {})
            for gname in groups:
                findings.append({"type": "group", "name": gname})

        except (json.JSONDecodeError, AttributeError):
            for line in (stdout + stderr).splitlines():
                um = re.search(r"user:\[(\w+)\]", line)
                if um:
                    findings.append({"type": "user", "username": um.group(1)})
                    suggested.add("hydra")
                sm = re.search(r"Sharename\s+(\S+)", line)
                if sm:
                    findings.append({"type": "share", "name": sm.group(1)})

        return findings, list(suggested)

    def _risk(self, findings: List[Dict]) -> float:
        score = 0.0
        for f in findings:
            if f.get("type") == "user":
                score += 0.5
            elif f.get("type") == "share":
                score += 1.0
        return min(round(score, 1), 8.0)
