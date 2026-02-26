import json
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

@register
class FeroxbusterPlugin(BaseTool):
    name = "feroxbuster"
    description = "Fast recursive content discovery with auto-recursion and smart filtering."
    category = "web"
    requires = ["feroxbuster"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        mode = options.get("mode", "default")
        wordlist = options.get("wordlist", WORDLISTS.get(mode, WORDLISTS["default"]))
        threads = 50 if mode == "ctf" else (10 if mode == "stealth" else 25)
        depth = options.get("depth", 3)
        cmd = [
            "feroxbuster",
            "--url", target,
            "--wordlist", wordlist,
            "--threads", str(threads),
            "--depth", str(depth),
            "--json",
            "--quiet",
            "--no-state",
            "--filter-status", "404,400,403",
        ]
        stdout, stderr, rc = await self._exec(cmd, timeout=600)
        findings = self._parse(stdout)
        return ToolResult(
            tool=self.name, target=target, success=bool(findings),
            raw_output=stdout, findings=findings,
            suggested_next=["nuclei"] if findings else [],
            risk_score=min(len(findings) * 0.2, 6.0),
            metadata={"wordlist": wordlist, "depth": depth},
        )

    def _parse(self, output: str) -> List[Dict]:
        findings = []
        for line in output.splitlines():
            try:
                d = json.loads(line)
                if d.get("type") == "response" and d.get("status", 0) not in [404, 400, 403]:
                    findings.append({
                        "url": d.get("url", ""),
                        "status": d.get("status", 0),
                        "words": d.get("word_count", 0),
                        "lines": d.get("line_count", 0),
                    })
            except Exception:
                pass
        return findings
