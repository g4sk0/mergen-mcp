# server/reporter.py
"""
Layer 4 — Dual Reporting System
compact (default): bulgu, CVSS, endpoint, PoC, fix
verbose: narrative, regulatory, triage prediction (--verbose flag ile)
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from server.correlation_engine import ChainFinding

_SEVERITY_TAG = {"critical": "[CRITICAL]", "high": "[HIGH]", "medium": "[MEDIUM]", "low": "[LOW]", "info": "[INFO]"}

_REGULATORY: Dict[str, List[str]] = {
    "pii": ["GDPR Art. 33 (72h notification)", "KVKK Madde 12", "CCPA §1798.150"],
    "payment": ["PCI-DSS 6.5.1", "PCI-DSS Req. 6"],
    "auth": ["OWASP A07:2021", "NIST SP 800-63"],
    "sql_injection": ["OWASP A03:2021", "PCI-DSS 6.5.1"],
    "rce": ["OWASP A03:2021 (Injection)"],
}

_FIX_MAP: Dict[str, str] = {
    "ssrf": "Validate/whitelist URLs; enforce IMDSv2; block 169.254.0.0/16",
    "sqli": "Use parameterized queries; disable verbose errors",
    "xss": "Encode output; implement strict CSP; use HttpOnly cookies",
    "jwt": "Use RS256 with key rotation; validate alg header server-side",
    "graphql": "Disable introspection in production; implement query depth limits",
    "rce": "Sanitize all user input; run app with minimal privileges",
    "file_upload": "Whitelist extensions; store outside web root; rename uploaded files",
    "xxe": "Disable external entity processing in XML parser",
}


@dataclass
class ReportConfig:
    mode: str = "bb"
    verbose: bool = False
    narrative: bool = False
    regulatory: bool = False
    format: str = "markdown"


def _auto_poc(finding: Dict[str, Any]) -> str:
    url = finding.get("url", "TARGET_URL")
    ftype = str(finding.get("type", "")).lower()
    if "ssrf" in ftype:
        return f'curl -s "{url}" -d \'url=http://169.254.169.254/latest/meta-data/\''
    if "sqli" in ftype or "sql" in ftype:
        return f'sqlmap -u "{url}" --dbs --batch'
    if "xss" in ftype:
        return f'curl -s "{url}?q=<script>alert(1)</script>"'
    if "graphql" in ftype:
        gql_payload = '\'{"query":"{__schema{types{name}}}"}\''
        return f'curl -s -X POST "{url}" -H "Content-Type: application/json" -d {gql_payload}'
    if "jwt" in ftype:
        return "jwt_tool TOKEN -X a  # alg:none bypass"
    return f'curl -s "{url}"  # manual verification required'


def _auto_fix(finding: Dict[str, Any]) -> str:
    ftype = str(finding.get("type", "")).lower()
    for k, v in _FIX_MAP.items():
        if k in ftype:
            return v
    return "Review OWASP remediation guidance for this vulnerability class"


def _finding_compact(finding: Dict[str, Any], chain: Optional[ChainFinding] = None) -> str:
    sev = str(finding.get("severity", finding.get("risk_level", "medium"))).lower()
    title = finding.get("name", finding.get("title", "Finding"))
    asset = finding.get("asset", finding.get("url", "unknown"))
    cvss = finding.get("cvss", finding.get("risk_score", 0))
    lines = [
        f"{_SEVERITY_TAG.get(sev, '[?]')} {title}",
        f"  Asset: {asset}  CVSS: {cvss}",
        f"  PoC: {_auto_poc(finding)}",
        f"  Fix: {_auto_fix(finding)}",
    ]
    if chain:
        lines.append(f"  Chain: {chain.chain_name} (score={chain.final_score})")
    return "\n".join(lines)


def generate_bb_report(
    findings: List[Dict[str, Any]],
    chains: List[ChainFinding],
    target: str,
    config: ReportConfig,
) -> str:
    parts = [f"# Bug Bounty Report — {target}\n"]
    if chains:
        parts.append("## Attack Chains\n")
        for c in chains:
            parts.append(f"### {_SEVERITY_TAG.get(c.severity, '[?]')} {c.chain_name}")
            parts.append(f"**CVSS:** {c.final_score} | **Chain:** {c.start_finding} → {c.pivot} → {c.end_impact}\n")
            if config.verbose and config.narrative:
                parts.append(
                    f"> An attacker exploiting {c.start_finding} can pivot through "
                    f"{c.pivot} to achieve {c.end_impact} (EDF={c.edf}).\n"
                )
    if findings:
        parts.append("## Findings\n")
        for f in findings:
            parts.append(_finding_compact(f))
            parts.append("")
    if config.verbose and config.regulatory:
        parts.append("## Regulatory Impact\n")
        for tag, regs in _REGULATORY.items():
            if any(tag in str(f.get("type", "")).lower() for f in findings):
                parts.append(f"**{tag.upper()}:** {', '.join(regs)}")
    return "\n".join(parts)


def generate_pentest_report(
    findings: List[Dict[str, Any]],
    chains: List[ChainFinding],
    target: str,
    config: ReportConfig,
    surface_map: Dict[str, Any] = None,
) -> str:
    sm = surface_map or {}
    crit = sum(1 for c in chains if c.severity == "critical")
    high = sum(1 for f in findings if str(f.get("severity", "")).lower() == "high")
    risk = "CRITICAL" if crit > 0 else ("HIGH" if high > 0 else "MEDIUM")
    parts = [
        f"# Penetration Test Report — {target}\n",
        "## Executive Summary\n",
        f"**Risk:** {risk} | **Critical Chains:** {crit} | **Total Findings:** {len(findings)}",
        f"**Target:** {sm.get('type', 'unknown')} | OS: {sm.get('os_guess', 'unknown')}\n",
    ]
    if chains:
        parts.append("## Attack Paths\n")
        for c in chains:
            parts.append(f"- **{c.chain_name}**: {c.start_finding} → {c.pivot} → {c.end_impact} (CVSS {c.final_score})")
        parts.append("")
    parts.append("## Findings\n")
    for f in findings:
        parts.append(_finding_compact(f))
        parts.append("")
    parts.append("## Remediation Roadmap\n**Week 1 (Critical):**")
    for c in chains:
        if c.severity == "critical":
            parts.append(f"- [ ] {c.chain_name}")
    parts.append("\n**Month 1 (High):**")
    for f in findings:
        if str(f.get("severity", "")).lower() == "high":
            parts.append(f"- [ ] {f.get('name', 'Finding')}")
    return "\n".join(parts)


def generate_report(
    findings: List[Dict[str, Any]],
    chains: List[ChainFinding],
    target: str,
    config: ReportConfig,
    surface_map: Dict[str, Any] = None,
) -> str:
    if config.mode == "pentest":
        return generate_pentest_report(findings, chains, target, config, surface_map)
    return generate_bb_report(findings, chains, target, config)


def to_json(findings: List[Dict], chains: List[ChainFinding]) -> str:
    return json.dumps({
        "findings": findings,
        "chains": [{"id": c.chain_id, "name": c.chain_name, "severity": c.severity,
                    "score": c.final_score, "start": c.start_finding,
                    "pivot": c.pivot, "end": c.end_impact} for c in chains],
    }, indent=2)


_CSV_INJECTION_CHARS = ('=', '-', '+', '@', '\t', '\r')

def _csv_sanitize(value: str) -> str:
    """Prevent CSV injection by prefixing dangerous leading characters."""
    s = str(value).replace('"', '""')
    if s and s[0] in _CSV_INJECTION_CHARS:
        s = "'" + s
    return f'"{s}"'

def to_csv(findings: List[Dict]) -> str:
    header = "severity,title,asset,cvss\n"
    rows = [
        ",".join([
            _csv_sanitize(f.get("severity", "")),
            _csv_sanitize(f.get("name", "")),
            _csv_sanitize(f.get("url", "")),
            _csv_sanitize(f.get("cvss", f.get("risk_score", ""))),
        ])
        for f in findings
    ]
    return header + "\n".join(rows)
