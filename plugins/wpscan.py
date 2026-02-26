import json
from typing import Any, Dict, List
from plugins import register
from plugins.base import BaseTool, ToolResult

@register
class WPScanPlugin(BaseTool):
    name = "wpscan"
    description = "WordPress vulnerability scanner: version, plugins, themes, CVEs, user enumeration."
    category = "web"
    requires = ["wpscan"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        mode = options.get("mode", "default")
        api_token = options.get("api_token", "")
        enumerate = options.get("enumerate", "vp,vt,u")  # vulnerable plugins, themes, users
        stealthy = mode in ["stealth", "bugbounty"]
        cmd = [
            "wpscan",
            "--url", target,
            "--enumerate", enumerate,
            "--format", "json",
            "--no-banner",
        ]
        if api_token:
            cmd += ["--api-token", api_token]
        if stealthy:
            cmd += ["--random-user-agent", "--throttle", "500"]
        stdout, stderr, rc = await self._exec(cmd, timeout=300)
        findings, risk = self._parse(stdout)
        return ToolResult(
            tool=self.name, target=target, success=(rc != -1),
            raw_output=stdout, findings=findings,
            suggested_next=["nuclei", "hydra"] if findings else [],
            risk_score=risk,
            metadata={"enumerate": enumerate, "stealthy": stealthy},
        )

    def _parse(self, output: str) -> tuple:
        findings = []
        risk = 0.0
        try:
            data = json.loads(output)
            wp_ver = data.get("version", {})
            if wp_ver:
                findings.append({"type": "wp_version", "version": wp_ver.get("number", "?"), "vulnerabilities": wp_ver.get("vulnerabilities", [])})
                risk = max(risk, 4.0 if wp_ver.get("vulnerabilities") else 1.0)
            for slug, pdata in data.get("plugins", {}).items():
                vulns = pdata.get("vulnerabilities", [])
                findings.append({"type": "plugin", "name": slug, "version": pdata.get("version", {}).get("number", "?"), "vulnerabilities": len(vulns)})
                if vulns:
                    risk = max(risk, 8.0)
            for user in data.get("users", {}).values():
                findings.append({"type": "user", "username": user.get("username", "?")})
                risk = max(risk, 5.0)
        except Exception:
            pass
        return findings, round(risk, 1)
