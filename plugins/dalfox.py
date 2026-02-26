import re
import json
from typing import Any, Dict, List

from plugins import register
from plugins.base import BaseTool, ToolResult


@register
class DalfoxPlugin(BaseTool):
    name = "dalfox"
    description = "Advanced XSS scanner. Pass 'params' list from arjun/katana for targeted scanning instead of blind discovery."
    category = "web"
    requires = ["dalfox"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        mode      = options.get("mode", "default")
        blind_url = options.get("blind_url", "")
        cookie    = options.get("cookie", "")
        headers   = options.get("headers", {})
        params    = options.get("params", [])
        worker    = options.get("worker", 20 if mode == "ctf" else (5 if mode in ["stealth", "bugbounty"] else 10))
        scan_url  = options.get("url", target)

        # Build target URL with known params if provided and URL has no query string
        if params and "?" not in scan_url:
            param_str = "&".join(f"{p}=FUZZ" for p in params[:5])
            scan_url = f"{scan_url.rstrip('/')}?{param_str}"

        cmd = [
            "dalfox", "url", scan_url,
            "--worker", str(worker),
            "--mining-dom",
            "--silence",
            "--format", "json",
        ]

        # Only use --mining-dict if we don't already have params
        if not params:
            cmd.append("--mining-dict")

        if blind_url:
            cmd += ["--blind", blind_url]
        if cookie:
            cmd += ["--cookie", cookie]
        for hname, hval in headers.items():
            cmd += ["--header", f"{hname}: {hval}"]
        if mode == "stealth":
            cmd += ["--delay", "500"]
        if mode == "bugbounty":
            cmd += ["--delay", "200"]

        stdout, stderr, rc = await self._exec(cmd, timeout=300)
        findings = self._parse(stdout)

        return ToolResult(
            tool=self.name,
            target=target,
            success=bool(findings),
            raw_output=stdout,
            findings=findings,
            suggested_next=["write_and_exec"] if findings else [],
            risk_score=8.5 if findings else 0.0,
            metadata={"mode": mode, "worker": worker, "params_provided": len(params), "scan_url": scan_url},
        )

    def _parse(self, output: str) -> List[Dict]:
        findings = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                findings.append({
                    "param":   data.get("param", "?"),
                    "payload": data.get("evidence", "?"),
                    "type":    data.get("type", "reflected"),
                    "poc":     data.get("poc", ""),
                })
            except Exception:
                if "[POC]" in line or "VULN" in line.upper():
                    findings.append({"raw": line})
        return findings
