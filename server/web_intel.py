# server/web_intel.py
"""
Layer 0.5 — Web Intelligence Research
Discovered tech stack için CVE, H1 writeup ve GitHub PoC araştırır.
Çıktı: priority_hints[] → AI Playbook Selector'a beslenir.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
from typing import Any, Dict, List
from dataclasses import dataclass, field

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

_log = logging.getLogger(__name__)

# Named constant for summary truncation (S2)
_SUMMARY_MAX_HINTS = 5

# Named constant for bonus accumulation cap (I4)
MAX_PLAYBOOK_BONUS = 40


@dataclass
class PriorityHint:
    source: str          # "nvd", "github", "h1_public"
    tech: str            # "express 4.17.1"
    hint_type: str       # "cve", "poc", "writeup"
    title: str
    score_bonus: int     # 0-30, playbook selector'da ağırlık olarak kullanılır
    playbooks: List[str] = field(default_factory=list)  # hangi playbook'ları tetikler
    detail: str = ""


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_API = "https://api.github.com/search/repositories"


async def _fetch_nvd(session: "aiohttp.ClientSession", keyword: str) -> List[PriorityHint]:
    """NVD API'den CVE'leri çeker (CVSS >= 7.0 filtreli)."""
    hints = []
    try:
        params = {"keywordSearch": keyword, "resultsPerPage": 5}
        async with session.get(NVD_API, params=params, timeout=aiohttp.ClientTimeout(total=10)) as r:
            if r.status != 200:
                return hints
            data = await r.json()
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")[:120]
                        break
                metrics = cve.get("metrics", {})
                score = 0.0
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    entries = metrics.get(key, [])
                    if entries:
                        score = entries[0].get("cvssData", {}).get("baseScore", 0) or 0
                        break
                if score >= 7.0:
                    hints.append(PriorityHint(
                        source="nvd",
                        tech=keyword,
                        hint_type="cve",
                        title=f"{cve_id} (CVSS {score})",
                        score_bonus=25 if score >= 9.0 else 15,
                        playbooks=_cve_to_playbooks(desc),
                        detail=desc,
                    ))
    except Exception as exc:
        _log.debug("web_intel: %s failed for %r: %s: %s", "_fetch_nvd", keyword, type(exc).__name__, exc)
    return hints


async def _fetch_github_pocs(session: "aiohttp.ClientSession", keyword: str) -> List[PriorityHint]:
    """GitHub'da PoC repoları arar."""
    hints = []
    try:
        query = f"{keyword} exploit poc"
        params = {"q": query, "sort": "stars", "per_page": 3}
        gh_token = os.environ.get("GITHUB_TOKEN", "")
        headers = {"Accept": "application/vnd.github+json"}
        if gh_token:
            headers["Authorization"] = f"Bearer {gh_token}"
        async with session.get(GITHUB_API, params=params, headers=headers,
                               timeout=aiohttp.ClientTimeout(total=8)) as r:
            if r.status != 200:
                return hints
            data = await r.json()
            for repo in data.get("items", []):
                if repo.get("stargazers_count", 0) >= 10:
                    hints.append(PriorityHint(
                        source="github",
                        tech=keyword,
                        hint_type="poc",
                        title=repo.get("full_name", ""),
                        score_bonus=10,
                        playbooks=_poc_to_playbooks(repo.get("description", "")),
                        detail=repo.get("description", "")[:120],
                    ))
    except Exception as exc:
        _log.debug("web_intel: %s failed for %r: %s: %s", "_fetch_github_pocs", keyword, type(exc).__name__, exc)
    return hints


def _cve_to_playbooks(desc: str) -> List[str]:
    """CVE açıklamasından ilgili playbook'ları tahmin eder."""
    desc_lower = desc.lower()
    playbooks = []
    mapping = {
        "sql injection": "rest_api_owasp",
        "xss": "xss_ato",
        "ssrf": "ssrf_full_chain",
        "rce": "file_upload_rce",
        "jwt": "jwt_attack_chain",
        "graphql": "graphql_full_chain",
        "deserialization": "deserialization",
        "xxe": "xxe_full_chain",
        "template injection": "template_injection",
        "directory traversal": "file_upload_rce",
        "authentication bypass": "oauth_oidc",
    }
    for keyword, playbook in mapping.items():
        if re.search(r'\b' + re.escape(keyword) + r'\b', desc_lower):
            playbooks.append(playbook)
    return playbooks


def _poc_to_playbooks(desc: str) -> List[str]:
    return _cve_to_playbooks(desc)


async def generate_priority_hints(
    tech_list: List[str],
    target: str = "",
) -> List[PriorityHint]:
    """
    Ana fonksiyon — tech stack için CVE + GitHub PoC araştırır.

    Args:
        tech_list: ["express 4.17.1", "WordPress 6.2", "nginx 1.18"]
        target: opsiyonel, loglama için

    Returns:
        PriorityHint listesi — score_bonus değerleriyle sıralı
    """
    if not HAS_AIOHTTP or not tech_list:
        return []

    all_hints: List[PriorityHint] = []

    async with aiohttp.ClientSession() as session:
        tasks = []
        for tech in tech_list[:8]:  # max 8 tech, rate limit aşımını önle
            tasks.append(_fetch_nvd(session, tech))
            tasks.append(_fetch_github_pocs(session, tech))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                all_hints.extend(r)

    # score_bonus'a göre sırala
    all_hints.sort(key=lambda h: h.score_bonus, reverse=True)
    _log.debug("web_intel: %d hints for target=%r techs=%r", len(all_hints), target, tech_list)
    return all_hints[:20]  # max 20 hint döndür


def hints_to_playbook_bonus(hints: List[PriorityHint]) -> Dict[str, int]:
    """
    PriorityHint listesini playbook_name → bonus_score dict'ine çevirir.
    AI Playbook Selector bu dict'i kullanır.
    """
    bonuses: Dict[str, int] = {}
    for hint in hints:
        for playbook in hint.playbooks:
            bonuses[playbook] = min(bonuses.get(playbook, 0) + hint.score_bonus, MAX_PLAYBOOK_BONUS)
    return bonuses


def hints_summary(hints: List[PriorityHint]) -> str:
    """Kompakt özet string — memory hint'e eklenir."""
    if not hints:
        return ""
    lines = [f"Web Intel ({len(hints)} hints):"]
    for h in hints[:_SUMMARY_MAX_HINTS]:
        lines.append(f"  [{h.source}] {h.tech}: {h.title} (+{h.score_bonus}pts → {', '.join(h.playbooks) or 'general'})")
    return "\n".join(lines)
