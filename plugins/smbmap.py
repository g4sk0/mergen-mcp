import re
from typing import Any, Dict, List
from plugins import register
from plugins.base import BaseTool, ToolResult

@register
class SMBMapPlugin(BaseTool):
    name = "smbmap"
    description = "SMB share enumeration: lists shares, tests access, searches for sensitive files."
    category = "enum"
    requires = ["smbmap"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        username = options.get("username", "")
        password = options.get("password", "")
        domain = options.get("domain", "")
        recursive = options.get("recursive", False)
        cmd = ["smbmap", "-H", target]
        if username:
            cmd += ["-u", username, "-p", password or ""]
        else:
            cmd += ["-u", "anonymous"]
        if domain:
            cmd += ["-d", domain]
        if recursive:
            cmd += ["-R"]
        stdout, stderr, rc = await self._exec(cmd, timeout=60)
        findings = self._parse(stdout)
        return ToolResult(
            tool=self.name, target=target, success=bool(findings),
            raw_output=stdout, findings=findings,
            suggested_next=["enum4linux", "crackmapexec"] if findings else [],
            risk_score=self._risk(findings),
            metadata={"recursive": recursive},
        )

    def _parse(self, output: str) -> List[Dict]:
        findings = []
        for line in output.splitlines():
            m = re.search(r"\s+([\w\$]+)\s+(READ|WRITE|READ, WRITE|NO ACCESS)", line)
            if m:
                findings.append({"share": m.group(1), "access": m.group(2)})
        return findings

    def _risk(self, findings: List[Dict]) -> float:
        score = 0.0
        for f in findings:
            if "WRITE" in f.get("access", ""):
                score += 3.0
            elif "READ" in f.get("access", ""):
                score += 1.5
        return min(round(score, 1), 9.0)
