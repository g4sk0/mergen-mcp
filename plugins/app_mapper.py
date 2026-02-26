"""
app_mapper.py — Logic Mapper
Builds a structured application model: endpoints, params, tech stack,
interesting targets. Used by LLM to generate hypotheses before scanning.
"""
import json
import re
import asyncio
from typing import Any, Dict, List
from urllib.parse import urlparse

from plugins import register
from plugins.base import BaseTool, ToolResult


@register
class AppMapperPlugin(BaseTool):
    name        = "app_map"
    description = "Build a structured Logic Map of the target app: endpoints, params, tech stack, interesting targets. Run this FIRST before any scanner."
    category    = "web"
    requires    = ["katana"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        depth   = int(options.get("depth", 3))
        cookie  = options.get("cookie", "")
        headers = options.get("headers", {})
        timeout = int(options.get("timeout", 120))

        katana_out   = await self._spider_katana(target, depth, cookie, headers, timeout)
        headers_out  = await self._fetch_headers(target, cookie)
        logic_map    = self._build_map(target, katana_out, headers_out, options)
        findings     = [{"type": "logic_map", "data": logic_map}]

        return ToolResult(
            tool=self.name,
            target=target,
            success=True,
            raw_output=katana_out + "\n" + headers_out,
            findings=findings,
            suggested_next=["diff_check", "nuclei", "arjun"],
            risk_score=0.0,
            metadata={"endpoints_found": len(logic_map.get("endpoints", []))},
        )

    async def _spider_katana(self, target: str, depth: int, cookie: str, headers: Dict, timeout: int) -> str:
        cmd = [
            "katana", "-u", target,
            "-d", str(depth),
            "-jc", "-fx", "-silent",
            "-o", "/dev/stdout",
        ]
        if cookie:
            cmd += ["-H", f"Cookie: {cookie}"]
        for h, v in headers.items():
            cmd += ["-H", f"{h}: {v}"]
        stdout, _, _ = await self._exec(cmd, timeout=timeout, simulate_progress=False)
        return stdout

    async def _fetch_headers(self, target: str, cookie: str) -> str:
        cmd = ["curl", "-sI", "--max-time", "10", target]
        if cookie:
            cmd += ["-b", cookie]
        stdout, _, _ = await self._exec(cmd, timeout=15, simulate_progress=False)
        return stdout

    def _build_map(self, target: str, spider_out: str, headers_out: str, options: Dict) -> Dict:
        base = target.rstrip("/")
        parsed_base = urlparse(base)
        base_domain = parsed_base.netloc or parsed_base.path

        endpoints: Dict[str, Dict] = {}
        js_secrets: List[Dict]     = []
        api_endpoints: List[str]   = []

        for line in spider_out.splitlines():
            url = line.strip()
            if not url or not url.startswith("http"):
                continue
            parsed = urlparse(url)
            path   = parsed.path or "/"
            params = [p.split("=")[0] for p in (parsed.query or "").split("&") if p]

            ep = endpoints.get(path, {"path": path, "params": [], "methods": ["GET"], "urls": []})
            for p in params:
                if p and p not in ep["params"]:
                    ep["params"].append(p)
            ep["urls"].append(url)
            endpoints[path] = ep

            if re.search(r"/api/|/v\d+/|/graphql|/rest/", path, re.I):
                api_endpoints.append(url)

            if path.endswith((".js", ".jsx", ".ts")):
                js_secrets.append({"file": url, "note": "JS file — may contain API keys or endpoints"})

        technologies = self._detect_tech(headers_out, spider_out)

        interesting = {
            "idor_candidates":  [p for p in endpoints if re.search(r"/\d+|/[a-f0-9-]{36}", p)],
            "upload_endpoints": [p for p in endpoints if re.search(r"upload|import|file|avatar|image", p, re.I)],
            "admin_panels":     [p for p in endpoints if re.search(r"admin|dashboard|manage|console|panel", p, re.I)],
            "auth_endpoints":   [p for p in endpoints if re.search(r"login|logout|auth|oauth|sso|token|password", p, re.I)],
            "api_endpoints":    api_endpoints[:20],
        }

        auth_required = list(set(interesting["admin_panels"] + interesting["auth_endpoints"]))

        return {
            "target":        target,
            "base_domain":   base_domain,
            "endpoints":     list(endpoints.values())[:100],
            "technologies":  technologies,
            "interesting":   interesting,
            "auth_required": auth_required[:20],
            "js_files":      js_secrets[:10],
            "total_found":   len(endpoints),
        }

    def _detect_tech(self, headers: str, content: str) -> List[str]:
        tech     = []
        combined = (headers + content).lower()
        checks   = [
            ("Laravel",    ["laravel", "laravel_session"]),
            ("WordPress",  ["wp-content", "wp-json", "wordpress"]),
            ("Django",     ["django", "csrftoken"]),
            ("Rails",      ["_rails_session", "x-runtime:"]),
            ("Express",    ["x-powered-by: express"]),
            ("Spring",     ["jsessionid", "spring"]),
            ("PHP",        ["x-powered-by: php", ".php", "phpsessid"]),
            ("ASP.NET",    ["x-powered-by: asp.net", "viewstate"]),
            ("Nginx",      ["server: nginx"]),
            ("Apache",     ["server: apache"]),
            ("Cloudflare", ["server: cloudflare", "cf-ray:"]),
            ("JWT",        ["authorization: bearer", "eyj"]),
        ]
        for name, patterns in checks:
            if any(p in combined for p in patterns):
                tech.append(name)
        return tech
