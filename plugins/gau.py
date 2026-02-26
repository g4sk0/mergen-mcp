from typing import Any, Dict, List
from plugins import register
from plugins.base import BaseTool, ToolResult

@register
class GauPlugin(BaseTool):
    name = "gau"
    description = "Passive URL discovery from Wayback Machine, Common Crawl, OTX, URLScan."
    category = "recon"
    requires = ["gau"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        cmd = ["gau", "--json", target]
        if options.get("include_subs"):
            cmd.append("--subs")
        stdout, stderr, rc = await self._exec(cmd, timeout=120)
        findings = []
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("http"):
                findings.append({"url": line})
        return ToolResult(
            tool=self.name, target=target, success=bool(findings),
            raw_output=stdout, findings=findings,
            suggested_next=["katana", "arjun"] if findings else [],
            risk_score=min(len(findings) * 0.05, 3.0),
            metadata={"source": "gau", "count": len(findings)},
        )
