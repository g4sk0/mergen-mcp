import re
from typing import Any, Dict, List
from plugins import register
from plugins.base import BaseTool, ToolResult

@register
class JohnPlugin(BaseTool):
    name = "john"
    description = "Password hash cracker: MD5, SHA, NTLM, bcrypt, and 400+ formats."
    category = "exploit"
    requires = ["john"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        wordlist = options.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        fmt = options.get("format", "")
        rules = options.get("rules", True)
        cmd = ["john", target, f"--wordlist={wordlist}"]
        if fmt:
            cmd.append(f"--format={fmt}")
        if rules:
            cmd.append("--rules")
        stdout, stderr, rc = await self._exec(cmd, timeout=600)
        show_out, _, _ = await self._exec(["john", "--show", target], timeout=10)
        findings = self._parse(show_out)
        return ToolResult(
            tool=self.name, target=target, success=bool(findings),
            raw_output=stdout, findings=findings,
            suggested_next=[] if not findings else ["hydra"],
            risk_score=9.5 if findings else 0.0,
            metadata={"wordlist": wordlist, "format": fmt},
        )

    def _parse(self, output: str) -> List[Dict]:
        findings = []
        for line in output.splitlines():
            m = re.match(r"(\S+):(\S+)", line)
            if m and "password hash" not in line:
                findings.append({"username": m.group(1), "password": m.group(2)})
        return findings
