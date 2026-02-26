import json
from typing import Any, Dict, List
from plugins import register
from plugins.base import BaseTool, ToolResult

@register
class KatanaPlugin(BaseTool):
    name = "katana"
    description = "Next-gen JS-aware web crawler for endpoint and form discovery."
    category = "web"
    requires = ["katana"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        mode = options.get("mode", "default")
        depth = 5 if mode == "internal" else (2 if mode == "stealth" else 3)
        cmd = [
            "katana", "-u", target,
            "-depth", str(depth),
            "-js-crawl",
            "-silent",
            "-j",
            "-no-color",
        ]
        if mode == "ctf":
            cmd += ["-form-extraction"]
        stdout, stderr, rc = await self._exec(cmd, timeout=300)
        findings = self._parse(stdout)
        return ToolResult(
            tool=self.name, target=target, success=bool(findings),
            raw_output=stdout, findings=findings,
            suggested_next=["arjun", "ffuf"] if findings else [],
            risk_score=min(len(findings) * 0.1, 4.0),
            metadata={"depth": depth, "js_crawl": True},
        )

    def _parse(self, output: str) -> List[Dict]:
        findings = []
        for line in output.splitlines():
            try:
                d = json.loads(line)
                findings.append({
                    "endpoint": d.get("endpoint", ""),
                    "method": d.get("method", "GET"),
                    "source": d.get("source", ""),
                })
            except Exception:
                if line.startswith("http"):
                    findings.append({"endpoint": line.strip()})
        return findings
