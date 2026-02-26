from typing import Any, Dict, List
from plugins import register
from plugins.base import BaseTool, ToolResult

@register
class WaybackurlsPlugin(BaseTool):
    name = "waybackurls"
    description = "Fetches historical URLs from the Wayback Machine for a domain."
    category = "recon"
    requires = ["waybackurls"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        cmd = ["waybackurls", target]
        stdout, stderr, rc = await self._exec(cmd, timeout=120)
        findings = [{"url": line.strip()} for line in stdout.splitlines() if line.strip().startswith("http")]
        interesting = [f for f in findings if any(x in f["url"] for x in [".php", ".asp", "?", "/api/", "/admin", "="])]
        return ToolResult(
            tool=self.name, target=target, success=bool(findings),
            raw_output=stdout[:3000], findings=interesting or findings[:50],
            suggested_next=["arjun", "sqlmap"] if interesting else [],
            risk_score=min(len(interesting) * 0.2, 5.0),
            metadata={"total_urls": len(findings), "interesting": len(interesting)},
        )
