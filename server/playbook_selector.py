# server/playbook_selector.py
"""
Layer 2 — AI Playbook Selector
Evidence Accumulation Model: tech stack + web intel + surface map + mode + memory.
"""
from __future__ import annotations
from typing import Any, Dict, List, Tuple
from server.playbooks import ALL_PLAYBOOKS, PlaybookDef


def score_playbook(
    pb: PlaybookDef,
    surface_map: Dict[str, Any],
    mode: str,
    intel_bonuses: Dict[str, int],
    memory_bonuses: Dict[str, int],
) -> int:
    score = pb.base_score

    # 1. Tech stack eşleşmesi (+max 30)
    tech_str = " ".join([
        str(surface_map.get("tech", "")),
        str(surface_map.get("web_server", "")),
        str(surface_map.get("cms", "")),
        " ".join(str(v) for v in surface_map.get("response_headers", {}).values()),
    ]).lower()
    matched = sum(1 for kw in pb.tech_keywords if kw.lower() in tech_str)
    score += min(matched * 10, 30)

    # 2. Web Intelligence bonus (+max 25)
    score += min(intel_bonuses.get(pb.id, 0), 25)

    # 3. Surface map koşulları (+max 20)
    total = len(pb.requires) or 1
    met = sum(1 for req in pb.requires if surface_map.get(req))
    score += int((met / total) * 20)

    # 4. Memory bonus (+max 15)
    score += min(memory_bonuses.get(pb.id, 0), 15)

    # 5. Mode ağırlığı
    mode_key = mode if mode in pb.mode_weight else "bb"
    score = int(score * pb.mode_weight[mode_key])

    return min(score, 100)


def select_playbooks(
    surface_map: Dict[str, Any],
    mode: str,
    intel_bonuses: Dict[str, int] = None,
    memory_bonuses: Dict[str, int] = None,
    threshold_immediate: int = 70,
    threshold_conditional: int = 40,
) -> Tuple[List[PlaybookDef], List[PlaybookDef], List[PlaybookDef]]:
    intel_bonuses = intel_bonuses or {}
    memory_bonuses = memory_bonuses or {}

    scored = [
        (score_playbook(pb, surface_map, mode, intel_bonuses, memory_bonuses), pb)
        for pb in ALL_PLAYBOOKS
    ]
    scored.sort(key=lambda x: x[0], reverse=True)

    immediate = [pb for s, pb in scored if s >= threshold_immediate]
    conditional = [pb for s, pb in scored if threshold_conditional <= s < threshold_immediate]
    low_priority = [pb for s, pb in scored if s < threshold_conditional]

    if mode == "pentest":
        conditional = conditional + low_priority
        low_priority = []

    return immediate, conditional, low_priority


def selection_summary(immediate: List[PlaybookDef], conditional: List[PlaybookDef]) -> str:
    lines = [f"Playbook Selection: {len(immediate)} immediate, {len(conditional)} conditional"]
    for pb in immediate[:5]:
        lines.append(f"  [IMMEDIATE] {pb.name} ({pb.category})")
    for pb in conditional[:3]:
        lines.append(f"  [CONDITIONAL] {pb.name} ({pb.category})")
    return "\n".join(lines)
