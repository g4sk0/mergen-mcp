import re
from typing import Any, Dict, List

from plugins import register
from plugins.base import BaseTool, ToolResult


MODE_PARAMS = {
    "ctf":       {"level": 3, "risk": 2, "threads": 10, "tamper": ""},
    "bugbounty": {"level": 2, "risk": 1, "threads": 3,  "tamper": "space2comment"},
    "internal":  {"level": 5, "risk": 3, "threads": 5,  "tamper": "space2comment,between"},
    "stealth":   {"level": 1, "risk": 1, "threads": 1,  "tamper": "randomcase"},
    "default":   {"level": 2, "risk": 1, "threads": 5,  "tamper": ""},
}


@register
class SQLMapPlugin(BaseTool):
    name = "sqlmap"
    description = "Automated SQL injection detection. Mode-aware level/risk/tamper selection."
    category = "exploit"
    requires = ["sqlmap"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        mode = options.get("mode", "default")
        params = MODE_PARAMS.get(mode, MODE_PARAMS["default"])
        data = options.get("data", "")      # POST data
        cookie = options.get("cookie", "")
        dbs = options.get("dbs", False)     # enumerate databases

        cmd = [
            "sqlmap",
            "-u", target,
            "--level", str(params["level"]),
            "--risk", str(params["risk"]),
            "--threads", str(params["threads"]),
            "--batch",
            "--output-dir", "/tmp/sqlmap_out",
        ]

        if params["tamper"]:
            cmd += ["--tamper", params["tamper"]]
        if data:
            cmd += ["--data", data]
        if cookie:
            cmd += ["--cookie", cookie]
        if dbs:
            cmd.append("--dbs")

        stdout, stderr, rc = await self._exec(cmd, timeout=300)

        findings = self._parse(stdout)
        risk = 9.5 if findings else 0.0

        return ToolResult(
            tool=self.name,
            target=target,
            success=bool(findings),
            raw_output=stdout,
            findings=findings,
            suggested_next=["run_command:sqlmap --dump"] if findings else [],
            risk_score=risk,
            metadata={"mode": mode, "level": params["level"], "risk": params["risk"]},
        )

    def _parse(self, output: str) -> List[Dict]:
        findings = []
        vuln_types = re.findall(r"Type: (.+)", output)
        payloads   = re.findall(r"Payload: (.+)", output)
        dbs        = re.findall(r"\[\*\] (.+)", output)

        for i, vtype in enumerate(vuln_types):
            findings.append({
                "type": vtype.strip(),
                "payload": payloads[i].strip() if i < len(payloads) else "",
            })

        for db in dbs:
            if db.strip() and db.strip() not in [f.get("db") for f in findings]:
                findings.append({"db": db.strip()})

        return findings
