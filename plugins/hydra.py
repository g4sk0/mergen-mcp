import re
from typing import Any, Dict, List

from plugins import register
from plugins.base import BaseTool, ToolResult


WORDLISTS = {
    "user": "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    "pass": "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
    "pass_ctf": "/usr/share/wordlists/rockyou.txt",
}

THREADS = {"ctf": 16, "bugbounty": 4, "internal": 8, "stealth": 2, "default": 8}


@register
class HydraPlugin(BaseTool):
    name = "hydra"
    description = "Network login brute-forcer. Supports SSH, FTP, HTTP, SMB, RDP, MySQL, etc."
    category = "exploit"
    requires = ["hydra"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        mode = options.get("mode", "default")
        service = options.get("service", "ssh")
        port = options.get("port", "")
        username = options.get("username", "")
        password = options.get("password", "")
        userlist = options.get("userlist", WORDLISTS["user"])
        passlist = options.get("passlist", WORDLISTS["pass_ctf"] if mode == "ctf" else WORDLISTS["pass"])
        threads = THREADS.get(mode, 8)

        cmd = ["hydra", "-t", str(threads), "-f"]  # -f = stop on first found

        if username:
            cmd += ["-l", username]
        else:
            cmd += ["-L", userlist]

        if password:
            cmd += ["-p", password]
        else:
            cmd += ["-P", passlist]

        if port:
            cmd += ["-s", str(port)]

        cmd += [target, service]

        stdout, stderr, rc = await self._exec(cmd, timeout=600)

        findings = self._parse(stdout)

        return ToolResult(
            tool=self.name,
            target=target,
            success=bool(findings),
            raw_output=stdout,
            findings=findings,
            suggested_next=["ssh_login", "ftp_login"] if findings else [],
            risk_score=9.0 if findings else 0.0,
            metadata={"service": service, "mode": mode, "threads": threads},
        )

    def _parse(self, output: str) -> List[Dict]:
        findings = []
        for line in output.splitlines():
            m = re.search(r"\[(\d+)\]\[(\w+)\] host: (\S+)\s+login: (\S+)\s+password: (\S+)", line)
            if m:
                findings.append({
                    "port": m.group(1),
                    "service": m.group(2),
                    "host": m.group(3),
                    "login": m.group(4),
                    "password": m.group(5),
                })
        return findings
