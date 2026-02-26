import re
from typing import Any, Dict, List
from plugins import register
from plugins.base import BaseTool, ToolResult

@register
class Radare2Plugin(BaseTool):
    name = "radare2"
    description = "Advanced binary analysis: disassembly, function analysis, ROP gadgets, patching."
    category = "binary"
    requires = ["r2"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        action = options.get("action", "info")
        commands = {
            "info":      ["r2", "-q", "-c", "iI;aaa;afl", target],
            "functions": ["r2", "-q", "-c", "aaa;afl", target],
            "rop":       ["r2", "-q", "-c", "/R", target],
            "strings":   ["r2", "-q", "-c", "iz", target],
        }
        cmd = commands.get(action, commands["info"])
        stdout, stderr, rc = await self._exec(cmd, timeout=120)
        findings = self._parse(stdout, action)
        return ToolResult(
            tool=self.name, target=target, success=(rc != -1),
            raw_output=stdout[:5000],
            findings=findings,
            suggested_next=["pwntools"] if action == "rop" and findings else [],
            risk_score=0.0,
            metadata={"action": action},
        )

    def _parse(self, output: str, action: str) -> List[Dict]:
        findings = []
        for line in output.splitlines():
            if action == "functions":
                m = re.match(r"(0x[0-9a-f]+)\s+\d+\s+\d+\s+(\S+)", line)
                if m:
                    findings.append({"address": m.group(1), "name": m.group(2)})
            elif action == "rop":
                if "ret" in line.lower() or "pop" in line.lower():
                    findings.append({"gadget": line.strip()})
            elif action == "strings":
                m = re.search(r"\d+\s+\d+\s+\S+\s+\S+\s+(.+)", line)
                if m:
                    findings.append({"string": m.group(1).strip()})
            else:
                if "=" in line:
                    parts = line.split("=", 1)
                    findings.append({"key": parts[0].strip(), "value": parts[1].strip()})
        return findings[:50]
