# server/coverage_matrix.py
"""
Coverage Matrix — Hangi endpoint/parameter test edilmedi takip eder.
Session boyunca test edilmemiş alanları raporlar.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set
from urllib.parse import urlparse


_DEFAULT_TESTS = ["GET", "sqli", "xss", "idor", "auth"]


@dataclass
class CoverageMatrix:
    target: str
    endpoints: Dict[str, Set[str]] = field(default_factory=dict)

    def add_endpoint(self, path: str) -> None:
        if path not in self.endpoints:
            self.endpoints[path] = set()

    def mark_tested(self, path: str, test_type: str) -> None:
        self.endpoints.setdefault(path, set()).add(test_type)

    def get_untested(self, required_tests: List[str] = None) -> Dict[str, List[str]]:
        required = required_tests or _DEFAULT_TESTS
        return {
            path: [t for t in required if t not in tested]
            for path, tested in self.endpoints.items()
            if any(t not in tested for t in required)
        }

    def coverage_pct(self, required_tests: List[str] = None) -> float:
        required = required_tests or _DEFAULT_TESTS
        if not self.endpoints:
            return 100.0
        total = len(self.endpoints) * len(required)
        covered = sum(
            sum(1 for t in required if t in tested)
            for tested in self.endpoints.values()
        )
        return round((covered / total) * 100, 1) if total > 0 else 100.0

    def summary(self) -> str:
        pct = self.coverage_pct()
        untested = self.get_untested()
        lines = [f"Coverage: {pct}% | Endpoints: {len(self.endpoints)}"]
        for path, missing in list(untested.items())[:5]:
            lines.append(f"  UNTESTED: {path} → missing: {', '.join(missing)}")
        return "\n".join(lines)


def build_matrix_from_findings(target: str, findings: List[Dict[str, Any]]) -> CoverageMatrix:
    """Tool çıktılarından coverage matrix oluşturur."""
    matrix = CoverageMatrix(target=target)
    for f in findings:
        url = f.get("url", f.get("path", ""))
        if not url:
            continue
        try:
            path = urlparse(url).path or url
        except Exception:
            path = url
        matrix.add_endpoint(path)
        tool = str(f.get("tool", "")).lower()
        ftype = str(f.get("type", "")).lower()
        if "sqlmap" in tool or "sqli" in ftype:
            matrix.mark_tested(path, "sqli")
        if "dalfox" in tool or "xss" in ftype:
            matrix.mark_tested(path, "xss")
        if "ffuf" in tool or "gobuster" in tool or "feroxbuster" in tool:
            matrix.mark_tested(path, "GET")
        if "auth" in ftype or "idor" in ftype:
            matrix.mark_tested(path, "auth")
            matrix.mark_tested(path, "idor")
    return matrix
