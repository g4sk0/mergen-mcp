import re
from typing import Any, Dict, List
from plugins import register
from plugins.base import BaseTool, ToolResult

@register
class Wafw00fPlugin(BaseTool):
    name = "wafw00f"
    description = "WAF detection: identifies firewall type before launching attacks."
    category = "recon"
    requires = ["wafw00f"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        cmd = ["wafw00f", target, "-a", "-o", "-"]
        stdout, stderr, rc = await self._exec(cmd, timeout=60)
        findings = self._parse(stdout)
        return ToolResult(
            tool=self.name, target=target, success=(rc != -1),
            raw_output=stdout, findings=findings,
            suggested_next=["nuclei"] if not findings else [],
            risk_score=0.0,
            metadata={"waf_detected": bool(findings)},
        )

    def _parse(self, output: str) -> List[Dict]:
        findings = []
        for line in output.splitlines():
            m = re.search(r"is behind (.+?) WAF", line, re.IGNORECASE)
            if m:
                findings.append({"waf": m.group(1).strip()})
            if "No WAF detected" in line:
                findings.append({"waf": None, "note": "No WAF detected"})
        return findings
