import json
from typing import Any, Dict, List

from plugins import register
from plugins.base import BaseTool, ToolResult


WORDLISTS = {
    "dir":    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "small":  "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
    "large":  "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
    "param":  "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
    "vhost":  "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "api":    "/usr/share/seclists/Discovery/Web-Content/api/objects.txt",
    "backup": "/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt",
}


@register
class FfufPlugin(BaseTool):
    name = "ffuf"
    description = "Fast web fuzzer. Supports dir/param/vhost fuzzing. Accepts 'path' option to fuzz a specific endpoint instead of root."
    category = "web"
    requires = ["ffuf"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        mode         = options.get("mode", "default")
        fuzz_type    = options.get("fuzz_type", "dir")
        wordlist     = options.get("wordlist", WORDLISTS.get(fuzz_type, WORDLISTS["dir"]))
        threads      = options.get("threads", 40 if mode == "ctf" else (10 if mode in ["bugbounty", "stealth"] else 25))
        # 403 is intentionally NOT filtered by default: forbidden endpoints indicate resources
        # exist but need auth — valuable in bug bounty. Pass filter_codes="404,400,403" to suppress.
        filter_codes = options.get("filter_codes", "404,400")
        extensions   = options.get("extensions", "")

        # Allow Claude to pass the exact path/URL
        custom_url = options.get("url", "")       # full URL with FUZZ already placed
        base_path  = options.get("path", "")      # path to append /FUZZ to

        base = target.rstrip("/")

        if custom_url:
            url = custom_url
        elif base_path:
            url = base + "/" + base_path.lstrip("/").rstrip("/") + "/FUZZ"
        elif fuzz_type == "dir":
            url = base + "/FUZZ"
        elif fuzz_type == "param":
            url = base + "?FUZZ=mergen"
        elif fuzz_type == "vhost":
            url = base
        else:
            url = base + "/FUZZ"

        cmd = [
            "ffuf",
            "-u", url,
            "-w", wordlist,
            "-t", str(threads),
            "-o", "/dev/stdout",
            "-of", "json",
            "-fc", filter_codes,
            "-s",
        ]

        if extensions:
            cmd += ["-e", extensions]

        if fuzz_type == "vhost":
            domain = base.replace("https://", "").replace("http://", "").split("/")[0]
            cmd += ["-H", f"Host: FUZZ.{domain}"]

        if mode == "stealth":
            cmd += ["-rate", "10"]
        elif mode == "bugbounty":
            cmd += ["-rate", "50"]

        for arg in options.get("extra_args", []):
            cmd.append(arg)

        stdout, stderr, rc = await self._exec(cmd, timeout=600)
        findings = self._parse(stdout)

        return ToolResult(
            tool=self.name,
            target=target,
            success=(rc != -1),
            raw_output=stdout,
            findings=findings,
            suggested_next=["nuclei", "dalfox"] if findings else [],
            risk_score=min(len(findings) * 0.4, 7.0),
            metadata={"fuzz_type": fuzz_type, "wordlist": wordlist, "url": url},
        )

    def _parse(self, output: str) -> List[Dict]:
        findings = []
        try:
            data = json.loads(output)
            for r in data.get("results", []):
                findings.append({
                    "url":    r.get("url", ""),
                    "status": r.get("status", 0),
                    "length": r.get("length", 0),
                    "words":  r.get("words", 0),
                    "lines":  r.get("lines", 0),
                })
        except json.JSONDecodeError:
            for line in output.splitlines():
                line = line.strip()
                if line and "[Status:" in line:
                    findings.append({"raw": line})
        return findings
