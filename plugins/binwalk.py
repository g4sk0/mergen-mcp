import re
from typing import Any, Dict, List
from plugins import register
from plugins.base import BaseTool, ToolResult

@register
class BinwalkPlugin(BaseTool):
    name = "binwalk"
    description = "Firmware/binary analysis: extracts embedded files, filesystems, and signatures."
    category = "binary"
    requires = ["binwalk"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        extract = options.get("extract", False)
        cmd = ["binwalk", target]
        if extract:
            cmd += ["-e", "--directory", "/tmp/binwalk_extract"]
        stdout, stderr, rc = await self._exec(cmd, timeout=120)
        findings = self._parse(stdout)
        return ToolResult(
            tool=self.name, target=target, success=(rc != -1),
            raw_output=stdout, findings=findings,
            suggested_next=["strings"] if findings else [],
            risk_score=min(len(findings) * 0.5, 5.0),
            metadata={"extracted": extract},
        )

    def _parse(self, output: str) -> List[Dict]:
        findings = []
        for line in output.splitlines():
            m = re.match(r"(\d+)\s+0x([0-9A-Fa-f]+)\s+(.+)", line)
            if m:
                findings.append({
                    "offset_dec": int(m.group(1)),
                    "offset_hex": m.group(2),
                    "description": m.group(3).strip(),
                })
        return findings
