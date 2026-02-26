# server/correlation_engine.py
"""
Layer 4 — Correlation Engine
Chain detection, EDF, Business Impact Classifier, deduplication.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ChainFinding:
    chain_id: str
    chain_name: str
    findings: List[Dict[str, Any]]
    start_finding: str
    pivot: str
    end_impact: str
    base_cvss: float
    chain_multiplier: float
    edf: float
    business_multiplier: float
    final_score: float
    severity: str
    assets: List[str] = field(default_factory=list)


CHAIN_TEMPLATES = [
    {"id": "ssrf_aws_takeover", "name": "SSRF → AWS Takeover",
     "start": "ssrf", "pivot": "imds_v1", "end": "aws_admin_access",
     "requires": ["ssrf", "aws_metadata"], "multiplier": 1.8, "edf": 1.0},
    {"id": "xss_full_ato", "name": "XSS → Full Account Takeover",
     "start": "xss_stored", "pivot": "session_cookie_theft", "end": "account_takeover",
     "requires": ["xss", "session_cookie"], "multiplier": 1.5, "edf": 0.8},
    {"id": "upload_rce", "name": "File Upload → RCE",
     "start": "file_upload", "pivot": "path_traversal", "end": "remote_code_execution",
     "requires": ["file_upload", "rce_indicator"], "multiplier": 1.9, "edf": 0.9},
    {"id": "sqli_data_exfil", "name": "SQLi → Data Exfiltration",
     "start": "sql_injection", "pivot": "database_dump", "end": "pii_data_leak",
     "requires": ["sqli"], "multiplier": 1.6, "edf": 0.9},
    {"id": "ssrf_internal_pivot", "name": "SSRF → Internal Service Pivot",
     "start": "ssrf", "pivot": "internal_redis_memcached", "end": "auth_bypass",
     "requires": ["ssrf", "internal_service"], "multiplier": 1.5, "edf": 0.7},
    {"id": "ad_full_takeover", "name": "AD Kerberoast → Domain Takeover",
     "start": "kerberoasting", "pivot": "hash_crack", "end": "dcsync_domain_admin",
     "requires": ["kerberoastable_user", "smb_access"], "multiplier": 2.0, "edf": 0.6},
    {"id": "jwt_ato", "name": "JWT Bypass → ATO",
     "start": "jwt_vulnerability", "pivot": "token_forgery", "end": "account_takeover",
     "requires": ["jwt_vuln"], "multiplier": 1.7, "edf": 0.9},
    {"id": "graphql_idor_chain", "name": "GraphQL Introspection → IDOR → Data Leak",
     "start": "graphql_introspection", "pivot": "alias_idor", "end": "user_data_exfil",
     "requires": ["graphql_exposed"], "multiplier": 1.4, "edf": 0.8},
    {"id": "cicd_aws_deploy", "name": "CI/CD Secret → AWS Deploy",
     "start": "cicd_secret_exposure", "pivot": "aws_key_usage", "end": "prod_infrastructure_compromise",
     "requires": ["cicd_secret", "aws_key"], "multiplier": 2.0, "edf": 0.8},
    {"id": "subdomain_takeover_ato", "name": "Subdomain Takeover → Cookie ATO",
     "start": "subdomain_takeover", "pivot": "samesite_none_cookie", "end": "session_hijack",
     "requires": ["subdomain_takeover", "session_cookie"], "multiplier": 1.6, "edf": 0.7},
]

ASSET_CRITICALITY: Dict[str, float] = {
    "payment": 2.0, "auth": 1.8, "pii_storage": 1.7,
    "admin_panel": 1.6, "api_gateway": 1.4,
    "static_cdn": 0.5, "dev_staging": 0.3,
}

TAG_MAP: Dict[str, List[str]] = {
    "ssrf": ["ssrf", "server-side request"],
    "sqli": ["sql injection", "sqli", "blind sql"],
    "xss": ["xss", "cross-site scripting", "stored xss"],
    "jwt_vuln": ["jwt", "alg:none", "token forgery"],
    "graphql_exposed": ["graphql introspection", "graphql schema"],
    "file_upload": ["file upload", "upload bypass"],
    "rce_indicator": ["rce", "remote code execution", "command injection"],
    "aws_metadata": ["169.254.169.254", "imds", "iam/security-credentials"],
    "kerberoastable_user": ["kerberoast", "spn", "serviceprincipalname"],
    "cicd_secret": ["github actions secret", "jenkins credential", "gitlab ci token"],
    "aws_key": ["accesskeyid", "secretaccesskey", "awsaccesskey"],
    "subdomain_takeover": ["subdomain takeover", "unclaimed subdomain"],
    "session_cookie": ["set-cookie", "session hijack", "cookie theft", "httponly", "auth token", "session token"],
    "smb_access": ["smb", "cifs", "netbios"],
    "internal_service": ["redis", "memcached", "internal"],
}


def _detect_tags(finding: Dict[str, Any]) -> List[str]:
    combined = " ".join([
        str(finding.get("name", "")),
        str(finding.get("type", "")),
        str(finding.get("url", "")),
        str(finding.get("detail", "")),
    ]).lower()
    return [tag for tag, kws in TAG_MAP.items() if any(kw in combined for kw in kws)]


def _business_multiplier(assets: List[str]) -> float:
    if not assets:
        return 1.0
    return max(ASSET_CRITICALITY.get(a, 1.0) for a in assets)


def _final_score(base: float, chain_mult: float, edf: float, biz_mult: float) -> float:
    # EDF (Exploitability Difficulty Factor):
    #   1.0 = trivially easy (full multiplier applied)
    #   0.1 = very hard (10% multiplier — deprioritize hard-to-exploit chains)
    # Note: Design doc used 1/EDF (inverse). We use EDF directly so that
    # easy-to-exploit chains score higher — more actionable for operators.
    return round(min(base * chain_mult * max(edf, 0.1) * biz_mult, 10.0), 1)


def _severity(score: float) -> str:
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    return "low"


def correlate(
    all_findings: List[Dict[str, Any]],
    assets: List[str] = None,
) -> Tuple[List[ChainFinding], List[Dict[str, Any]]]:
    assets = assets or []
    biz_mult = _business_multiplier(assets)

    tagged = [{**f, "_tags": _detect_tags(f)} for f in all_findings]
    all_tags = set(t for f in tagged for t in f["_tags"])

    chains: List[ChainFinding] = []
    for tmpl in CHAIN_TEMPLATES:
        if set(tmpl["requires"]).issubset(all_tags):
            req_set = set(tmpl["requires"])
            chain_findings = [f for f in tagged if any(t in req_set for t in f.get("_tags", []))]
            base = max((f.get("cvss", 0) or f.get("risk_score", 0) or 5.0) for f in chain_findings) if chain_findings else 5.0
            fs = _final_score(base, tmpl["multiplier"], tmpl["edf"], biz_mult)
            chains.append(ChainFinding(
                chain_id=tmpl["id"], chain_name=tmpl["name"],
                findings=chain_findings, start_finding=tmpl["start"],
                pivot=tmpl["pivot"], end_impact=tmpl["end"],
                base_cvss=base, chain_multiplier=tmpl["multiplier"],
                edf=tmpl["edf"], business_multiplier=biz_mult,
                final_score=fs, severity=_severity(fs), assets=assets,
            ))

    chains.sort(key=lambda c: c.final_score, reverse=True)

    seen: set = set()
    deduped = []
    for f in all_findings:
        key = (f.get("url", ""), f.get("type", ""), f.get("name", ""))
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return chains, deduped
