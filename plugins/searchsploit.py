import json
import re
from typing import Any, Dict, List

from plugins import register
from plugins.base import BaseTool, ToolResult


@register
class SearchsploitPlugin(BaseTool):
    name = "searchsploit"
    description = "Search ExploitDB for exploits matching a service name and version."
    category = "exploit"
    requires = ["searchsploit"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        exact = options.get("exact", False)
        cmd = ["searchsploit", "--json"]
        if exact:
            cmd.append("--exact")
        cmd.extend(target.split())

        stdout, stderr, rc = await self._exec(cmd, timeout=30)

        findings = self._parse(stdout)
        risk = 8.0 if findings else 0.0

        return ToolResult(
            tool=self.name,
            target=target,
            success=(rc != -1),
            raw_output=stdout,
            findings=findings,
            suggested_next=["metasploit"] if any(f.get("type") == "remote" for f in findings) else [],
            risk_score=risk,
            metadata={"query": target, "count": len(findings)},
        )

    def _parse(self, output: str) -> List[Dict]:
        findings = []
        try:
            data = json.loads(output)
            for item in data.get("RESULTS_EXPLOIT", []):
                title = item.get("Title", "")
                path = item.get("Path", "")
                edb_id = item.get("EDB-ID", "")
                exploit_type = "remote" if "remote" in title.lower() else "local"
                findings.append({
                    "title": title,
                    "edb_id": edb_id,
                    "path": path,
                    "type": exploit_type,
                })
        except (json.JSONDecodeError, KeyError):
            pass
        return findings
