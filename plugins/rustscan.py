import re
from typing import Any, Dict, List

from plugins import register
from plugins.base import BaseTool, ToolResult


@register
class RustscanPlugin(BaseTool):
    name = "rustscan"
    description = "Ultra-fast port scanner. Discovers open ports quickly, then passes to Nmap for service detection."
    category = "recon"
    requires = ["rustscan"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        mode = options.get("mode", "default")
        ulimit = 5000 if mode == "ctf" else (1000 if mode in ["stealth", "bugbounty"] else 3000)
        batch = options.get("batch_size", 2500)

        cmd = [
            "rustscan",
            "-a", target,
            "--ulimit", str(ulimit),
            "--batch-size", str(batch),
            "--no-config",
            "--",
            "-sV", "--open",
        ]

        stdout, stderr, rc = await self._exec(cmd, timeout=120)

        findings = self._parse(stdout)

        return ToolResult(
            tool=self.name,
            target=target,
            success=bool(findings) or rc == 0,
            raw_output=stdout,
            findings=findings,
            suggested_next=["nmap"] if findings else [],
            risk_score=min(len(findings) * 0.5, 8.0),
            metadata={"ulimit": ulimit, "mode": mode},
        )

    def _parse(self, output: str) -> List[Dict]:
        findings = []
        for line in output.splitlines():
            m = re.findall(r"(\d+)/tcp", line)
            for port in m:
                findings.append({"port": int(port), "protocol": "tcp"})
        return findings
