import json
import re
from typing import Any, Dict, List

from plugins import register
from plugins.base import BaseTool, ToolResult


@register
class TrufflehogPlugin(BaseTool):
    name = "trufflehog"
    description = "Scans git repos and filesystem paths for leaked secrets, API keys, and credentials."
    category = "recon"
    requires = ["trufflehog"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        mode = options.get("mode", "default")
        depth = options.get("depth", 10)

        if target.startswith("http://") or target.startswith("https://"):
            cmd = ["trufflehog", "git", target, "--json", "--no-update", f"--depth={depth}"]
        else:
            cmd = ["trufflehog", "filesystem", target, "--json", "--no-update"]

        stdout, stderr, rc = await self._exec(cmd, timeout=300)

        findings = self._parse(stdout + stderr)
        risk = max((f.get("risk_score", 0) for f in findings), default=0.0)

        return ToolResult(
            tool=self.name,
            target=target,
            success=rc in (0, 1),
            raw_output=stdout,
            findings=findings,
            suggested_next=[],
            risk_score=risk,
            metadata={"secret_count": len(findings)},
        )

    def _parse(self, output: str) -> List[Dict]:
        findings = []
        for line in output.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
                detector = obj.get("DetectorName", obj.get("detector_name", "unknown"))
                raw = obj.get("Raw", obj.get("raw", ""))
                source = obj.get("SourceMetadata", {})
                file_path = ""
                if isinstance(source, dict):
                    data = source.get("Data", {})
                    if isinstance(data, dict):
                        file_path = (
                            data.get("Git", {}).get("file", "")
                            or data.get("Filesystem", {}).get("file", "")
                        )
                redacted = raw[:6] + "..." if len(raw) > 6 else raw
                findings.append({
                    "type": "secret",
                    "detector": detector,
                    "secret_preview": redacted,
                    "file": file_path,
                    "severity": "critical",
                    "risk_score": 9.5,
                })
            except json.JSONDecodeError:
                if re.search(r"Found verified", line, re.IGNORECASE):
                    findings.append({
                        "type": "secret",
                        "detector": "unknown",
                        "raw_line": line[:200],
                        "severity": "critical",
                        "risk_score": 9.0,
                    })
        return findings
