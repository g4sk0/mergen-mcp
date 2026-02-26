import re
from typing import Any, Dict, List
from plugins import register
from plugins.base import BaseTool, ToolResult

@register
class NetExecPlugin(BaseTool):
    name = "netexec"
    description = "Network exploitation: SMB/WinRM/LDAP/SSH credential testing and post-exploitation."
    category = "exploit"
    requires = ["netexec"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        protocol = options.get("protocol", "smb")
        username = options.get("username", "")
        password = options.get("password", "")
        userlist = options.get("userlist", "")
        passlist = options.get("passlist", "")
        shares = options.get("shares", False)
        cmd = ["netexec", protocol, target]
        if username and password:
            cmd += ["-u", username, "-p", password]
        elif userlist and passlist:
            cmd += ["-u", userlist, "-p", passlist]
        if shares:
            cmd.append("--shares")
        stdout, stderr, rc = await self._exec(cmd, timeout=120)
        findings = self._parse(stdout)
        return ToolResult(
            tool=self.name, target=target, success=bool(findings),
            raw_output=stdout, findings=findings,
            suggested_next=["smbmap"] if findings else [],
            risk_score=9.0 if any(f.get("pwned") for f in findings) else 3.0,
            metadata={"protocol": protocol},
        )

    def _parse(self, output: str) -> List[Dict]:
        findings = []
        for line in output.splitlines():
            pwned = "(Pwn3d!)" in line
            m = re.search(r"\[([+\-*])\]\s+(\S+)\s+(\S+)\s+(.+)", line)
            if m:
                findings.append({
                    "status": m.group(1),
                    "host": m.group(2),
                    "protocol": m.group(3),
                    "info": m.group(4).strip(),
                    "pwned": pwned,
                })
        return findings
