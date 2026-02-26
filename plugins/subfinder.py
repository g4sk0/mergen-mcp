import json
from typing import Any, Dict, List
from plugins import register
from plugins.base import BaseTool, ToolResult

@register
class SubfinderPlugin(BaseTool):
    name = "subfinder"
    description = "Passive subdomain discovery using multiple OSINT sources."
    category = "recon"
    requires = ["subfinder"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        mode = options.get("mode", "default")
        cmd = ["subfinder", "-d", target, "-silent", "-json"]
        if mode in ["internal", "ctf"]:
            cmd += ["-all"]  # use all sources
        stdout, stderr, rc = await self._exec(cmd, timeout=120)
        findings = self._parse(stdout)
        return ToolResult(
            tool=self.name, target=target, success=bool(findings),
            raw_output=stdout, findings=findings,
            suggested_next=["httpx", "nmap"] if findings else [],
            risk_score=min(len(findings) * 0.2, 6.0),
            metadata={"domain": target, "count": len(findings)},
        )

    def _parse(self, output: str) -> List[Dict]:
        findings = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                findings.append({"subdomain": data.get("host", line), "source": data.get("source", "")})
            except json.JSONDecodeError:
                findings.append({"subdomain": line})
        return findings
