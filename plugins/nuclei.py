import json
import re
from typing import Any, Dict, List

from plugins import register
from plugins.base import BaseTool, ToolResult


MODE_SEVERITY = {
    "ctf":       "critical,high,medium",
    "bugbounty": "critical,high,medium",
    "internal":  "critical,high,medium,low",
    "stealth":   "critical,high",
    "default":   "critical,high,medium",
}

MODE_TAGS = {
    "ctf":       "rce,sqli,lfi,xss,ssrf,idor,auth-bypass,misconfig",
    "bugbounty": "rce,sqli,lfi,xss,ssrf,idor,auth-bypass,exposure",
    "internal":  "",
    "stealth":   "rce,sqli",
    "default":   "rce,sqli,lfi,xss,ssrf",
}

MODE_RATE = {
    "ctf":       150,
    "bugbounty": 25,
    "stealth":   5,
    "internal":  100,
    "default":   50,
}


@register
class NucleiPlugin(BaseTool):
    name = "nuclei"
    description = "Template-based vulnerability scanner. Accepts 'tags', 'templates', 'severity', 'rate_limit', 'concurrency' options."
    category = "web"
    requires = ["nuclei"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        mode        = options.get("mode", "default")
        severity    = options.get("severity", MODE_SEVERITY.get(mode, "critical,high,medium"))
        tags        = options.get("tags", MODE_TAGS.get(mode, ""))
        templates   = options.get("templates", "")
        custom_tpl  = options.get("custom_templates", [])
        fuzzing     = options.get("fuzzing", False)
        rate_limit  = int(options.get("rate_limit", MODE_RATE.get(mode, 50)))
        concurrency = int(options.get("concurrency", 10))
        headers     = options.get("headers", {})
        template_ids= options.get("template_ids", [])

        cmd = [
            "nuclei",
            "-u", target,
            "-jsonl",
            "-no-color",
            "-rl",  str(rate_limit),
            "-c",   str(concurrency),
            "-timeout", "10",
        ]

        if custom_tpl:
            for ct in custom_tpl:
                cmd += ["-t", ct]
        elif template_ids:
            for tid in template_ids:
                cmd += ["-id", tid]
        else:
            cmd += ["-severity", severity]
            if tags:
                cmd += ["-tags", tags]
            if templates:
                cmd += ["-t", templates]

        if fuzzing:
            cmd += ["-dast"]

        for hname, hval in headers.items():
            cmd += ["-H", f"{hname}: {hval}"]

        stdout, stderr, rc = await self._exec(cmd, timeout=900)
        findings, risk = self._parse(stdout)
        suggested = self._suggest(findings)

        return ToolResult(
            tool=self.name,
            target=target,
            success=(rc != -1),
            raw_output=stdout,
            findings=findings,
            suggested_next=suggested,
            risk_score=risk,
            metadata={"mode": mode, "severity": severity, "tags": tags, "rate_limit": rate_limit},
        )

    def _parse(self, output: str):
        findings = []
        max_risk  = 0.0
        severity_scores = {"critical": 10, "high": 8, "medium": 5, "low": 2, "info": 0}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                sev  = data.get("info", {}).get("severity", "info").lower()
                score = severity_scores.get(sev, 0)
                max_risk = max(max_risk, score)
                findings.append({
                    "template":     data.get("template-id", "?"),
                    "name":         data.get("info", {}).get("name", "?"),
                    "severity":     sev,
                    "matched_at":   data.get("matched-at", "?"),
                    "cve":          data.get("info", {}).get("classification", {}).get("cve-id", []),
                    "cvss":         data.get("info", {}).get("classification", {}).get("cvss-score", None),
                    "curl_command": data.get("curl-command", ""),
                })
            except json.JSONDecodeError:
                pass

        if not findings:
            findings.append({
                "template": "info", "name": "Scan completed — 0 vulnerabilities found",
                "severity": "info", "matched_at": "N/A", "cve": [], "cvss": 0.0, "curl_command": "",
            })

        return findings, round(max_risk, 1)

    def _suggest(self, findings: List[Dict]) -> List[str]:
        suggested = set()
        for f in findings:
            name = f.get("name", "").lower()
            if "sql" in name:      suggested.add("sqlmap")
            if "xss" in name:      suggested.add("dalfox")
            if "rce" in name:      suggested.add("write_and_exec")
            if "lfi" in name:      suggested.add("write_and_exec")
            if "exposure" in name: suggested.add("ffuf")  # enumerate further, don't re-run nuclei
        return list(suggested)
