from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, Dict, List

from plugins import register
from plugins.base import BaseTool, ToolResult

ATTACK_MODES: Dict[str, int] = {
    "dictionary": 0,
    "combinator": 1,
    "brute":      3,
    "hybrid":     6,
}


@register
class HashcatPlugin(BaseTool):
    name = "hashcat"
    description = "GPU-accelerated password cracker: 300+ hash types, dictionary/brute/rule attacks."
    category = "exploit"
    requires = ["hashcat"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        hash_type = int(options.get("hash_type", 0))
        wordlist = options.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        attack = options.get("attack", "dictionary")
        rules = options.get("rules", "")
        attack_mode = ATTACK_MODES.get(attack, 0)

        with tempfile.TemporaryDirectory(prefix="besthack_hashcat_") as tmpdir:
            outfile = Path(tmpdir) / "cracked.txt"
            cmd = [
                "hashcat",
                "-m", str(hash_type),
                "-a", str(attack_mode),
                target, wordlist,
                "-o", str(outfile),
                "--force",
                "--quiet",
            ]
            if rules:
                cmd += ["-r", f"/usr/share/hashcat/rules/{rules}"]

            stdout, stderr, rc = await self._exec(cmd, timeout=600)
            findings = self._parse(outfile)

        return ToolResult(
            tool=self.name, target=target, success=bool(findings),
            raw_output=stdout, findings=findings,
            suggested_next=["hydra"] if findings else [],
            risk_score=9.5 if findings else 0.0,
            metadata={"hash_type": hash_type, "attack": attack},
        )

    def _parse(self, outfile: Path) -> List[Dict]:
        findings = []
        if not outfile.exists():
            return findings
        try:
            for line in outfile.read_text(encoding="utf-8").splitlines():
                parts = line.strip().rsplit(":", 1)
                if len(parts) == 2:
                    findings.append({"hash": parts[0], "password": parts[1]})
        except OSError:
            pass
        return findings
