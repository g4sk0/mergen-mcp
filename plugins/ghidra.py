import re
from typing import Any, Dict, List
from plugins import register
from plugins.base import BaseTool, ToolResult

@register
class GhidraPlugin(BaseTool):
    name = "ghidra"
    description = "NSA reverse engineering framework: headless binary analysis, function listing, decompilation."
    category = "binary"
    requires = ["ghidra"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        timeout = options.get("timeout", 300)
        project_dir = options.get("project_dir", "/tmp/ghidra_proj")
        import os
        ghidra_home = os.environ.get("GHIDRA_HOME", "/opt/ghidra")
        headless = f"{ghidra_home}/support/analyzeHeadless"
        script_dir = "/tmp"
        cmd = [
            headless, project_dir, "besthack_project",
            "-import", target,
            "-overwrite",
            "-analysisTimeoutPerFile", str(timeout),
            "-scriptPath", script_dir,
            "-postScript", "PrintFunctionNames.java",
        ]
        stdout, stderr, rc = await self._exec(cmd, timeout=timeout + 30)
        findings = self._parse(stdout + stderr)
        return ToolResult(
            tool=self.name, target=target, success=bool(findings),
            raw_output=(stdout + stderr)[:5000],
            findings=findings,
            suggested_next=["pwntools", "checksec"],
            risk_score=0.0,
            metadata={"binary": target, "timeout": timeout},
        )

    def _parse(self, output: str) -> List[Dict]:
        findings = []
        for line in output.splitlines():
            if "FUNCTION:" in line or "FUN_" in line:
                m = re.search(r"(FUN_[0-9a-f]+|[a-zA-Z_]\w+)\s*\(", line)
                if m:
                    findings.append({"function": m.group(1)})
        return findings[:50]  # cap at 50 functions
