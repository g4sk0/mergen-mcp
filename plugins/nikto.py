import re
from typing import Any, Dict, List

from plugins import register
from plugins.base import BaseTool, ToolResult


SEVERITY_MAP = {
    "OSVDB": "medium",
    "CVE":   "high",
    "XSS":   "high",
    "SQL":   "critical",
}


@register
class NiktoPlugin(BaseTool):
    name = "nikto"
    description = "Web server vulnerability scanner. Checks for dangerous files, outdated software, misconfigs."
    category = "web"
    requires = ["nikto"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        port = options.get("port", "")
        ssl = options.get("ssl", target.startswith("https"))
        mode = options.get("mode", "default")

        cmd = ["nikto", "-h", target, "-nointeractive", "-maxtime", "5m"]

        if mode == "default" or mode == "stealth":
            cmd += ["-Tuning", "123b"]  # Faster scan
        elif mode == "ctf" or mode == "bugbounty":
            cmd += ["-Tuning", "1234568b"]

        if port:
            cmd += ["-p", str(port)]
        if ssl:
            cmd.append("-ssl")

        stdout, stderr, rc = await self._exec(cmd, timeout=360)

        findings = self._parse(stdout)
        risk = max((f.get("risk_score", 0) for f in findings), default=0.0)

        return ToolResult(
            tool=self.name,
            target=target,
            success=(rc != -1),
            raw_output=stdout,
            findings=findings,
            suggested_next=["nuclei"] if findings else [],
            risk_score=risk,
            metadata={"ssl": ssl},
        )

    def _parse(self, output: str) -> List[Dict]:
        findings = []
        for line in output.splitlines():
            if not line.startswith("+ "):
                continue
            content = line[2:].strip()
            severity = "info"
            risk_score = 1.0
            for keyword, sev in SEVERITY_MAP.items():
                if keyword in content:
                    severity = sev
                    risk_score = {"critical": 9.5, "high": 7.5, "medium": 5.0, "info": 1.0}[sev]
                    break
            findings.append({
                "finding": content[:200],
                "severity": severity,
                "risk_score": risk_score,
            })
        return findings
