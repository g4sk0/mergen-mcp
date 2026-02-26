import re
from typing import Any, Dict, List

from plugins import register
from plugins.base import BaseTool, ToolResult


WORDLISTS = {
    "ctf":       "/usr/share/wordlists/dirb/common.txt",
    "bugbounty": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "internal":  "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
    "stealth":   "/usr/share/wordlists/dirb/small.txt",
    "default":   "/usr/share/wordlists/dirb/common.txt",
}

THREADS = {
    "ctf": 50, "bugbounty": 10, "internal": 30, "stealth": 5, "default": 20,
}


@register
class GobusterPlugin(BaseTool):
    name = "gobuster"
    description = "Directory/DNS brute-forcer. Mode-aware wordlist and thread selection."
    category = "web"
    requires = ["gobuster"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        mode = options.get("mode", "default")
        scan_mode = options.get("scan_mode", "dir")  # dir | dns | vhost
        wordlist = options.get("wordlist", WORDLISTS.get(mode, WORDLISTS["default"]))
        threads = options.get("threads", THREADS.get(mode, 20))
        extensions = options.get("extensions", "php,html,js,txt,json,xml,bak,old")

        cmd = [
            "gobuster", scan_mode,
            "-u", target,
            "-w", wordlist,
            "-t", str(threads),
            "--no-error",
        ]

        if scan_mode == "dir":
            cmd += ["-x", extensions, "-b", "404,403"]

        stdout, stderr, rc = await self._exec(cmd, timeout=600)

        findings = self._parse(stdout)
        suggested = self._suggest(findings)

        return ToolResult(
            tool=self.name,
            target=target,
            success=rc == 0 or bool(findings),
            raw_output=stdout,
            findings=findings,
            suggested_next=suggested,
            risk_score=min(len(findings) * 0.3, 8.0),
            metadata={"mode": mode, "wordlist": wordlist, "threads": threads},
            error=stderr if rc != 0 and not findings else None,
        )

    def _parse(self, output: str) -> List[Dict]:
        findings = []
        for line in output.splitlines():
            m = re.match(r"(/\S*)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]", line)
            if m:
                findings.append({
                    "path": m.group(1),
                    "status": int(m.group(2)),
                    "size": int(m.group(3)),
                })
        return findings

    def _suggest(self, findings: List[Dict]) -> List[str]:
        suggested = set()
        for f in findings:
            path = f.get("path", "")
            if any(x in path for x in ["/admin", "/login", "/wp-admin", "/phpmyadmin"]):
                suggested.add("hydra")
                suggested.add("nuclei")
            if any(x in path for x in [".git", ".env", ".bak", ".old"]):
                suggested.add("nuclei")
        return list(suggested)
