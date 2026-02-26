from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from plugins import register
from plugins.base import BaseTool, ToolResult


@register
class ArjunPlugin(BaseTool):
    name = "arjun"
    description = "HTTP parameter discovery: finds hidden GET/POST parameters in web apps."
    category = "web"
    requires = ["arjun"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        method = options.get("method", "GET,POST")

        with tempfile.TemporaryDirectory(prefix="besthack_arjun_") as tmpdir:
            outfile = Path(tmpdir) / "arjun_out.json"
            cmd = [
                "arjun",
                "-u", target,
                "-m", method,
                "--stable",
                "-oJ", str(outfile),
                "-q",
            ]
            stdout, stderr, rc = await self._exec(cmd, timeout=180)
            findings = self._parse(outfile, target)

        return ToolResult(
            tool=self.name, target=target, success=bool(findings),
            raw_output=stdout, findings=findings,
            suggested_next=["sqlmap", "dalfox"] if findings else [],
            risk_score=min(len(findings) * 0.5, 7.0),
            metadata={"method": method},
        )

    def _parse(self, outfile: Path, target: str) -> List[Dict]:
        findings = []
        if not outfile.exists():
            return findings
        try:
            data = json.loads(outfile.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                for url, params in data.items():
                    param_list = params if isinstance(params, list) else params.get("params", [])
                    for p in param_list:
                        findings.append({"url": url, "parameter": p})
            elif isinstance(data, list):
                for p in data:
                    findings.append({"url": target, "parameter": p})
        except (json.JSONDecodeError, OSError):
            pass
        return findings
