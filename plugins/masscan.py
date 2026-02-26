import re
from typing import Any, Dict, List
from plugins import register
from plugins.base import BaseTool, ToolResult

RATES = {"ctf": 10000, "bugbounty": 500, "internal": 5000, "stealth": 100, "default": 1000}

@register
class MasscanPlugin(BaseTool):
    name = "masscan"
    description = "Ultra-fast port scanner for large IP ranges. Mode-aware rate limiting."
    category = "recon"
    requires = ["masscan"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        mode = options.get("mode", "default")
        rate = options.get("rate", RATES.get(mode, 1000))
        ports = options.get("ports", "1-65535")
        cmd = ["masscan", target, "-p", ports, "--rate", str(rate), "--open", "-oG", "-"]
        stdout, stderr, rc = await self._exec(cmd, timeout=300)
        findings = self._parse(stdout)
        return ToolResult(
            tool=self.name, target=target, success=bool(findings),
            raw_output=stdout, findings=findings,
            suggested_next=["nmap"] if findings else [],
            risk_score=min(len(findings) * 0.4, 8.0),
            metadata={"rate": rate, "ports": ports},
        )

    def _parse(self, output: str) -> List[Dict]:
        findings = []
        for line in output.splitlines():
            m = re.search(r"Host: (\S+) .* Ports: (\d+)/open/(\w+)", line)
            if m:
                findings.append({"ip": m.group(1), "port": int(m.group(2)), "protocol": m.group(3)})
        return findings
