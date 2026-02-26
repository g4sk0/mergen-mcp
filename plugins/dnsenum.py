import re
from typing import Any, Dict, List
from plugins import register
from plugins.base import BaseTool, ToolResult

@register
class DNSenumPlugin(BaseTool):
    name = "dnsenum"
    description = "DNS enumeration: zone transfers, brute-force subdomains, reverse lookups."
    category = "recon"
    requires = ["dnsenum"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        cmd = ["dnsenum", "--nocolor", "--noreverse", target]
        stdout, stderr, rc = await self._exec(cmd, timeout=120)
        findings = self._parse(stdout)
        
        # In dnsenum, even if rc != 0 (e.g., no NS record), if we parsed A/MX records, it's a success in terms of findings
        success = bool(findings)
        return ToolResult(
            tool=self.name, target=target, success=success,
            raw_output=stdout, findings=findings,
            suggested_next=["subfinder", "amass"] if findings else [],
            risk_score=min(len(findings) * 0.2, 5.0),
            metadata={"domain": target},
        )

    def _parse(self, output: str) -> List[Dict]:
        findings = []
        for line in output.splitlines():
            ip_m = re.search(r"(\S+)\s+\d+\s+IN\s+A\s+(\d+\.\d+\.\d+\.\d+)", line)
            if ip_m:
                findings.append({"hostname": ip_m.group(1), "ip": ip_m.group(2)})
            mx_m = re.search(r"(\S+)\s+\d+\s+IN\s+MX\s+(\S+)", line)
            if mx_m:
                findings.append({"type": "MX", "hostname": mx_m.group(1), "mail": mx_m.group(2)})
        return findings
