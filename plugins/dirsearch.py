from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from plugins import register
from plugins.base import BaseTool, ToolResult

WORDLISTS = {
    "ctf":       "/usr/share/wordlists/dirb/common.txt",
    "bugbounty": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "internal":  "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
    "stealth":   "/usr/share/wordlists/dirb/small.txt",
    "default":   "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
}

SKIP_STATUSES = {400, 403, 404, 429, 500, 503}


@register
class DirsearchPlugin(BaseTool):
    name = "dirsearch"
    description = "Fast web path scanner with extension support and smart filtering."
    category = "web"
    requires = ["dirsearch"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        mode = options.get("mode", "default")
        extensions = options.get("extensions", "php,html,js,txt,json,xml,bak,old,zip")
        threads = 30 if mode == "ctf" else (5 if mode == "stealth" else 15)

        with tempfile.TemporaryDirectory(prefix="besthack_dirsearch_") as tmpdir:
            outfile = Path(tmpdir) / "results.json"
            cmd = [
                "dirsearch",
                "-u", target,
                "-e", extensions,
                "-t", str(threads),
                "--format", "json",
                "-o", str(outfile),
                "-q",
            ]
            stdout, stderr, rc = await self._exec(cmd, timeout=300)
            findings = self._parse(outfile)

        return ToolResult(
            tool=self.name, target=target, success=bool(findings),
            raw_output=stdout, findings=findings,
            suggested_next=["nuclei"] if findings else [],
            risk_score=min(len(findings) * 0.2, 6.0),
            metadata={"extensions": extensions, "threads": threads},
        )

    def _parse(self, outfile: Path) -> List[Dict]:
        findings = []
        if not outfile.exists():
            return findings
        try:
            data = json.loads(outfile.read_text(encoding="utf-8"))
            for item in data.get("results", []):
                status = item.get("status", 0)
                if isinstance(status, int) and status not in SKIP_STATUSES:
                    findings.append({
                        "path":   item.get("path", ""),
                        "status": status,
                        "size":   item.get("content_length", 0),
                    })
        except (json.JSONDecodeError, OSError):
            pass
        return findings
