import re
from typing import Any, Dict, List
from plugins import register
from plugins.base import BaseTool, ToolResult

@register
class FiercePlugin(BaseTool):
    name = "fierce"
    description = "DNS recon: locates non-contiguous IP space and subdomains via zone transfer attempts."
    category = "recon"
    requires = ["fierce"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        cmd = ["fierce", "--domain", target]
        stdout, stderr, rc = await self._exec(cmd, timeout=600)
        findings = self._parse(stdout)
        
        success = bool(findings)
        return ToolResult(
            tool=self.name, target=target, success=success,
            raw_output=stdout, findings=findings,
            suggested_next=["nmap", "httpx"] if findings else [],
            risk_score=min(len(findings) * 0.3, 5.0),
            metadata={"domain": target},
        )

    def _parse(self, output: str) -> List[Dict]:
        findings = []
        for line in output.splitlines():
            m = re.search(r"(\S+\.\S+)\s+\d+\s+IN\s+A\s+(\d+\.\d+\.\d+\.\d+)", line)
            if m:
                findings.append({"hostname": m.group(1), "ip": m.group(2)})
            zt = re.search(r"Zone Transfer was successful", line)
            if zt:
                findings.append({"type": "zone_transfer", "note": "CRITICAL: Zone transfer succeeded!"})
        return findings
