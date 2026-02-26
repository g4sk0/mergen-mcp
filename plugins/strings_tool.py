import re
from typing import Any, Dict, List
from plugins import register
from plugins.base import BaseTool, ToolResult

INTERESTING_PATTERNS = [
    (r"https?://\S+", "url"),
    (r"password\s*[=:]\s*\S+", "credential"),
    (r"api[_-]?key\s*[=:]\s*\S+", "api_key"),
    (r"[A-Za-z0-9+/]{40,}={0,2}", "base64"),
    (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "ip_address"),
    (r"[A-Fa-f0-9]{32,64}", "hash"),
]

@register
class StringsPlugin(BaseTool):
    name = "strings"
    description = "Extract printable strings from binaries: URLs, credentials, IPs, hashes."
    category = "binary"
    requires = ["strings"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        min_len = options.get("min_len", 8)
        cmd = ["strings", "-n", str(min_len), target]
        stdout, stderr, rc = await self._exec(cmd, timeout=60)
        findings = self._parse(stdout)
        return ToolResult(
            tool=self.name, target=target, success=True,
            raw_output=stdout[:5000],  # cap raw output
            findings=findings,
            suggested_next=["binwalk"] if findings else [],
            risk_score=min(len(findings) * 0.3, 6.0),
            metadata={"min_len": min_len, "total_strings": len(stdout.splitlines())},
        )

    def _parse(self, output: str) -> List[Dict]:
        findings = []
        seen = set()
        for line in output.splitlines():
            for pattern, ptype in INTERESTING_PATTERNS:
                m = re.search(pattern, line, re.IGNORECASE)
                if m:
                    val = m.group(0)
                    if val not in seen:
                        seen.add(val)
                        findings.append({"type": ptype, "value": val})
        return findings
