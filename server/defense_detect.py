# server/defense_detect.py
"""
Defense Detection Layer (DDL)
WAF, rate limiting ve IDS varlığını tespit eder.
"""
from __future__ import annotations
import asyncio
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List

_log = logging.getLogger(__name__)

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


@dataclass
class DefenseProfile:
    waf_detected: bool = False
    waf_vendor: str = ""
    rate_limited: bool = False
    rate_limit_rps: int = 0
    ids_indicators: List[str] = field(default_factory=list)
    bypass_strategies: List[str] = field(default_factory=list)
    stealth_required: bool = False


WAF_SIGNATURES: Dict[str, List[str]] = {
    "cloudflare": ["cf-ray", "cloudflare", "__cfduid", "cf_clearance"],
    "akamai": ["akamai", "ak_bmsc", "bm_sz"],
    "aws_waf": ["x-amzn-waf", "awswaf"],
    "modsecurity": ["mod_security", "modsec", "naxsi"],
    "imperva": ["imperva", "incapsula", "_incap_"],
    "f5_big_ip": ["bigipserver", "f5-", "ts="],
    "sucuri": ["sucuri", "x-sucuri"],
    "barracuda": ["barracuda"],
}

BYPASS_STRATEGIES: Dict[str, List[str]] = {
    "cloudflare": ["case_variation_payloads", "unicode_normalization_bypass", "http2_smuggling", "chunked_encoding"],
    "akamai": ["http2_vectors", "parameter_pollution", "json_encoding"],
    "modsecurity": ["chunked_encoding", "parameter_pollution", "comment_obfuscation"],
    "aws_waf": ["json_encoding", "case_variation_payloads"],
    "unknown": ["case_variation_payloads", "url_encoding", "parameter_pollution"],
}


async def detect_defenses(target_url: str) -> DefenseProfile:
    profile = DefenseProfile()
    if not HAS_AIOHTTP:
        return profile
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(target_url, timeout=aiohttp.ClientTimeout(total=10),
                                   allow_redirects=True) as resp:
                headers_str = str(dict(resp.headers)).lower()
                body_sample = ""
                try:
                    body_sample = (await resp.text())[:500].lower()
                except Exception:
                    pass
                combined = headers_str + " " + body_sample
                best_vendor = ""
                best_count = 0
                for vendor, sigs in WAF_SIGNATURES.items():
                    count = sum(1 for sig in sigs if sig in combined)
                    if count > best_count:
                        best_count = count
                        best_vendor = vendor
                if best_count > 0:
                    profile.waf_detected = True
                    profile.waf_vendor = best_vendor

            # Rate limit probe
            blocked = 0
            for _ in range(5):
                try:
                    async with session.get(target_url, timeout=aiohttp.ClientTimeout(total=3)) as r:
                        if r.status in [429, 503]:
                            blocked += 1
                except Exception:
                    blocked += 1
                await asyncio.sleep(0.1)
            if blocked >= 2:
                profile.rate_limited = True
                profile.rate_limit_rps = max(1, 5 - blocked)
    except Exception as exc:
        _log.debug("defense_detect: %s failed: %s: %s", target_url, type(exc).__name__, exc)

    vendor = profile.waf_vendor or "unknown"
    profile.bypass_strategies = BYPASS_STRATEGIES.get(vendor, BYPASS_STRATEGIES["unknown"])
    profile.stealth_required = profile.waf_detected or profile.rate_limited
    return profile


def defense_to_surface_update(profile: DefenseProfile) -> Dict[str, Any]:
    return {
        "waf_detected": profile.waf_detected,
        "waf": profile.waf_vendor if profile.waf_detected else None,
        "rate_limited": profile.rate_limited,
        "stealth_required": profile.stealth_required,
        "bypass_strategies": profile.bypass_strategies,
    }
