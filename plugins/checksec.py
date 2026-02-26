import json
from typing import Any, Dict, List
from plugins import register
from plugins.base import BaseTool, ToolResult

@register
class ChecksecPlugin(BaseTool):
    name = "checksec"
    description = "Binary security checker: NX, PIE, RELRO, Stack Canary, ASLR, Fortify."
    category = "binary"
    requires = ["checksec"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        cmd = ["checksec", "--file", target, "--output", "json"]
        stdout, stderr, rc = await self._exec(cmd, timeout=30)
        findings, risk = self._parse(stdout, target)
        return ToolResult(
            tool=self.name, target=target, success=(rc != -1),
            raw_output=stdout, findings=findings,
            suggested_next=self._suggest(findings),
            risk_score=risk,
            metadata={"binary": target},
        )

    def _parse(self, output: str, target: str) -> tuple:
        findings = []
        risk = 0.0
        try:
            data = json.loads(output)
            props = data.get(target, data.get(list(data.keys())[0], {})) if data else {}
            checks = {
                "nx": props.get("nx", "?"),
                "pie": props.get("pie", "?"),
                "relro": props.get("relro", "?"),
                "canary": props.get("canary", "?"),
                "fortify": props.get("fortify_source", "?"),
            }
            findings.append(checks)
            if checks["nx"] in ["disabled", "no"]:
                risk += 2.0
            if checks["pie"] in ["disabled", "no"]:
                risk += 2.0
            if checks["canary"] in ["disabled", "no"]:
                risk += 2.0
            if checks["relro"] in ["no", "partial"]:
                risk += 1.5
        except Exception:
            pass
        return findings, min(round(risk, 1), 9.0)

    def _suggest(self, findings: List[Dict]) -> List[str]:
        if not findings:
            return []
        f = findings[0]
        suggested = []
        if f.get("nx") in ["disabled", "no"]:
            suggested.append("pwntools")
        if f.get("pie") in ["disabled", "no"]:
            suggested.append("ghidra")
        return suggested
