import json
import re
from typing import Any, Dict, List

from plugins import register
from plugins.base import BaseTool, ToolResult


CMS_EXPLOIT_MAP = {
    "WordPress": ["wpscan", "nuclei"],
    "Joomla":    ["nuclei"],
    "Drupal":    ["nuclei"],
    "phpMyAdmin":["nuclei", "hydra"],
    "Jenkins":   ["nuclei"],
    "Tomcat":    ["nuclei", "hydra"],
}


@register
class WhatWebPlugin(BaseTool):
    name = "whatweb"
    description = "Web technology fingerprinter. Identifies CMS, frameworks, and server software."
    category = "recon"
    requires = ["whatweb"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        mode = options.get("mode", "default")
        aggression = 3 if mode == "ctf" else (1 if mode == "stealth" else 3)
        proxy = options.get("proxy", "")
        headers = options.get("headers", {})

        cmd = [
            "whatweb",
            "--aggression", str(aggression),
            "--log-json=-",
            "--quiet",
        ]
        
        if proxy:
            cmd += ["--proxy", proxy]
            
        for k, v in headers.items():
            cmd += ["--header", f"{k}: {v}"]
            
        cmd.append(target)

        # Use a slightly larger _exec timeout to let WhatWeb timeout internally
        stdout, stderr, rc = await self._exec(cmd, timeout=75)

        if "ERROR Opening" in stdout or "execution expired" in stdout:
            return ToolResult(
                tool=self.name,
                target=target,
                success=False,
                raw_output=stdout,
                findings=[],
                error=stdout.strip()[:100],
                metadata={"aggression": aggression, "error": True},
            )

        findings, suggested = self._parse(stdout)

        return ToolResult(
            tool=self.name,
            target=target,
            success=bool(findings),
            raw_output=stdout,
            findings=findings,
            suggested_next=suggested,
            risk_score=min(len(findings) * 0.3, 5.0),
            metadata={"aggression": aggression, "proxy": proxy},
        )

    def _parse(self, output: str) -> tuple:
        findings = []
        suggested = set()

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if isinstance(data, list):
                    if not data:
                        continue
                    data = data[0]

                target_url = data.get("target", "")
                http_status = data.get("http_status", "")
                plugins = data.get("plugins", {})

                for name, info in plugins.items():
                    # Extract the most meaningful value available
                    version = info.get("version", [])
                    string  = info.get("string", [])
                    os_info = info.get("os", [])
                    module  = info.get("module", [])
                    account = info.get("account", [])

                    value = (
                        version[0] if version else
                        string[0]  if string  else
                        os_info[0] if os_info else
                        module[0]  if module  else
                        account[0] if account else
                        None
                    )

                    findings.append({
                        "technology": name,
                        "version": value,
                        "url": target_url,
                        "http_status": http_status,
                    })

                    for cms, tools in CMS_EXPLOIT_MAP.items():
                        if cms.lower() in name.lower():
                            for t in tools:
                                suggested.add(t)

            except json.JSONDecodeError:
                # Fallback: parse bracket notation [Technology]
                for match in re.findall(r"\[([^\]]+)\]", line):
                    findings.append({"technology": match, "version": None})

        return findings, list(suggested)
