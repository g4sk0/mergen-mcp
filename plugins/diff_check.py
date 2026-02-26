"""
diff_check.py — Differential Analyzer
Compare responses for the same endpoint under different auth contexts.
Detects IDOR, privilege escalation, auth bypass.
"""
import json
import re
import asyncio
from typing import Any, Dict, List, Optional

from plugins import register
from plugins.base import BaseTool, ToolResult


@register
class DiffCheckPlugin(BaseTool):
    name        = "diff_check"
    description = "Detect auth bypass/IDOR by comparing responses under different auth tokens. Pass token_a, token_b (or no_auth vs token_a)."
    category    = "web"
    requires    = ["curl"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        token_a   = options.get("token_a", "")
        token_b   = options.get("token_b", "")
        endpoints = options.get("endpoints", [target])
        method    = options.get("method", "GET")
        body      = options.get("body", "")
        id_range  = options.get("id_range", [])
        id_pattern= options.get("id_pattern", "")

        findings = []

        if id_pattern and id_range and token_a:
            findings += await self._test_idor(target, token_a, id_pattern, id_range[:50], method)

        for ep in endpoints[:20]:
            result = await self._compare(ep, token_a, token_b, method, body)
            if result:
                findings.append(result)

        risk = 9.0 if any(f.get("severity") == "critical" for f in findings) else \
               7.0 if findings else 0.0

        return ToolResult(
            tool=self.name,
            target=target,
            success=bool(findings),
            raw_output=json.dumps(findings, indent=2),
            findings=findings,
            suggested_next=["write_and_exec"] if findings else [],
            risk_score=risk,
            metadata={"endpoints_tested": len(endpoints), "id_range_size": len(id_range)},
        )

    async def _fetch(self, url: str, token: str, method: str, body: str) -> Dict:
        cmd = ["curl", "-s", "-w", "\n__STATUS__:%{http_code}", "--max-time", "10", "-X", method]
        if token:
            if token.startswith("Bearer ") or re.match(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$", token):
                cmd += ["-H", f"Authorization: Bearer {token.replace('Bearer ', '')}"]
            else:
                cmd += ["-b", token]
        if body:
            cmd += ["-d", body, "-H", "Content-Type: application/json"]
        cmd.append(url)

        stdout, _, _ = await self._exec(cmd, timeout=15)
        lines  = stdout.rsplit("\n__STATUS__:", 1)
        body_r = lines[0][:2000] if lines else ""
        status = int(lines[1].strip()) if len(lines) > 1 and lines[1].strip().isdigit() else 0
        return {"status": status, "body_preview": body_r[:500]}

    async def _compare(self, url: str, token_a: str, token_b: str, method: str, body: str) -> Dict | None:
        r_a, r_b = await asyncio.gather(
            self._fetch(url, token_a, method, body),
            self._fetch(url, token_b, method, body),
        )
        # Auth-bypass: requires token_a to be a real credential; token_b is anonymous/absent.
        # If both tokens are empty the comparison is meaningless — skip it.
        if r_a["status"] == 200 and r_b["status"] == 200 and token_a:
            if not token_b or "anonymous" in token_b.lower():
                return {
                    "type":     "auth_bypass",
                    "url":      url,
                    "severity": "critical",
                    "detail":   "Endpoint returns 200 without authentication",
                    "evidence": r_b["body_preview"][:200],
                }
        if r_a["status"] == 200 and r_b["status"] == 200 and token_a and token_b:
            body_a = r_a["body_preview"]
            body_b = r_b["body_preview"]
            if body_a and body_b and body_a[:100] != body_b[:100] and len(body_b) > 50:
                return {
                    "type":       "potential_idor",
                    "url":        url,
                    "severity":   "high",
                    "detail":     "Different users see different data — verify ownership check",
                    "evidence_a": body_a[:100],
                    "evidence_b": body_b[:100],
                }
        return None

    async def _test_idor(self, target: str, token: str, pattern: str, id_range: List, method: str) -> List[Dict]:
        findings = []
        baseline = await self._fetch(target, token, method, "")
        baseline_body = baseline.get("body_preview", "")

        urls = [re.sub(pattern, str(id_val), target) for id_val in id_range]

        # Batch concurrent requests to avoid exhausting OS process limits and triggering
        # target-side rate limiting. Process BATCH_SIZE URLs at a time.
        BATCH_SIZE = 5
        all_results: List[Any] = []
        for i in range(0, len(urls), BATCH_SIZE):
            batch = urls[i : i + BATCH_SIZE]
            batch_results = await asyncio.gather(
                *[self._fetch(url, token, method, "") for url in batch],
                return_exceptions=True,
            )
            all_results.extend(batch_results)
            if i + BATCH_SIZE < len(urls):
                await asyncio.sleep(0.2)  # brief pause between batches

        for url, result in zip(urls, all_results):
            if isinstance(result, Exception):
                continue
            if result["status"] == 200 and result["body_preview"] != baseline_body and len(result["body_preview"]) > 20:
                findings.append({
                    "type":     "idor_confirmed",
                    "url":      url,
                    "severity": "critical",
                    "detail":   f"Different response body for ID in {url}",
                    "evidence": result["body_preview"][:200],
                })
        return findings
