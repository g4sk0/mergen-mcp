import json
import shutil
import subprocess
from typing import Any, Dict, List
from plugins import register
from plugins.base import BaseTool, ToolResult

@register
class HttpxPlugin(BaseTool):
    name = "httpx"
    description = "Fast HTTP probing: status codes, tech detection, title extraction, CDN detection."
    category = "recon"
    requires = ["httpx"]

    def is_available(self) -> bool:
        """Check that the installed httpx is ProjectDiscovery's tool, not Python's httpx CLI.

        Problem: pip installs a Python 'httpx' CLI that shadows ProjectDiscovery's httpx binary.
        ProjectDiscovery's httpx -version output contains 'projectdiscovery'.
        Python's httpx CLI does not.
        """
        if not shutil.which("httpx"):
            return False
        try:
            result = subprocess.run(
                ["httpx", "-version"],
                capture_output=True, text=True, timeout=5
            )
            output = (result.stdout + result.stderr).lower()
            # ProjectDiscovery httpx always prints its branding
            if "projectdiscovery" in output:
                return True
            # Python httpx CLI: shows "usage: httpx [options] url" style help, no projectdiscovery
            # If -version is unrecognized AND the tool doesn't print projectdiscovery, it's the wrong binary
            return False
        except Exception:
            return False

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        mode = options.get("mode", "default")
        threads = 50 if mode == "ctf" else (10 if mode == "stealth" else 25)
        cmd = [
            "httpx", "-silent",
            "-tech-detect",
            "-title",
            "-status-code",
            "-content-length",
            "-web-server",
            "-threads", str(threads),
            target
        ]
        stdout, stderr, rc = await self._exec(cmd, timeout=120)
        findings = self._parse(stdout)
        return ToolResult(
            tool=self.name, target=target, success=bool(findings),
            raw_output=stdout, findings=findings,
            suggested_next=["gobuster", "nuclei"] if findings else [],
            risk_score=min(len(findings) * 0.3, 5.0),
            metadata={"threads": threads},
        )

    def _parse(self, output: str) -> List[Dict]:
        findings = []
        for line in output.splitlines():
            try:
                d = json.loads(line)
                findings.append({
                    "url": d.get("url", ""),
                    "status": d.get("status_code", 0),
                    "title": d.get("title", ""),
                    "tech": d.get("tech", []),
                    "webserver": d.get("webserver", ""),
                    "content_length": d.get("content_length", 0),
                })
            except Exception:
                pass
        return findings
