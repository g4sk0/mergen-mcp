from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

DB_PATH = Path(__file__).parent.parent / "data" / "sessions.db"


import asyncio

def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    return con


async def init_memory_db() -> None:
    def _do_init():
        con = _connect()
        con.execute("""
            CREATE TABLE IF NOT EXISTS operations (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                mode        TEXT NOT NULL,
                target      TEXT NOT NULL,
                session     TEXT NOT NULL,
                started_at  REAL NOT NULL,
                finished_at REAL,
                tools_used  TEXT,
                findings_count INTEGER DEFAULT 0,
                risk_max    REAL DEFAULT 0.0,
                summary     TEXT,
                errors      TEXT
            )
        """)
        # Recon cache: stores per-target tool results with TTL-based expiry.
        # Prevents redundant re-runs of expensive scans (nmap, subfinder, etc.)
        con.execute("""
            CREATE TABLE IF NOT EXISTS recon_cache (
                target       TEXT NOT NULL,
                tool         TEXT NOT NULL,
                findings_json TEXT,
                raw_output   TEXT,
                risk_score   REAL DEFAULT 0.0,
                created_at   REAL NOT NULL,
                ttl_hours    REAL NOT NULL,
                PRIMARY KEY (target, tool)
            )
        """)
        con.commit()
        con.close()
    await asyncio.to_thread(_do_init)


# TTL in hours per tool — how long cached results are considered fresh
RECON_TTL: Dict[str, float] = {
    "nmap":        6.0,
    "rustscan":    6.0,
    "naabu":       6.0,
    "subfinder":  24.0,
    "gau":        24.0,
    "waybackurls":24.0,
    "whois":      48.0,
    "whatweb":    12.0,
    "app_map":    12.0,
    "katana":     12.0,
    "httpx":      12.0,
}


async def save_operation(
    mode: str,
    target: str,
    session: str,
    tools_used: List[str],
    findings_count: int,
    risk_max: float,
    summary: str,
    errors: Optional[List[str]] = None,
    started_at: Optional[float] = None,
) -> None:
    def _do_save():
        con = _connect()
        con.execute(
            """
            INSERT INTO operations
                (mode, target, session, started_at, finished_at, tools_used,
                 findings_count, risk_max, summary, errors)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                mode,
                target,
                session,
                started_at or time.time(),
                time.time(),
                json.dumps(tools_used),
                findings_count,
                risk_max,
                summary,
                json.dumps(errors or []),
            ),
        )
        
        # Ouroboros Phase 18: Auto-Rotation
        # Prevent database infinite growth by keeping only the last 5000 operations
        con.execute(
            "DELETE FROM operations WHERE id NOT IN "
            "(SELECT id FROM operations ORDER BY id DESC LIMIT 5000)"
        )
        
        con.commit()
        con.close()
    await asyncio.to_thread(_do_save)


async def get_past_operations(mode: str, limit: int = 10) -> List[Dict[str, Any]]:
    def _do_get():
        con = _connect()
        rows = con.execute(
            """
            SELECT * FROM operations
            WHERE mode = ?
            ORDER BY started_at DESC
            LIMIT ?
            """,
            (mode, limit),
        ).fetchall()
        con.close()
        result = []
        for row in rows:
            d = dict(row)
            d["tools_used"] = json.loads(d.get("tools_used") or "[]")
            d["errors"] = json.loads(d.get("errors") or "[]")
            result.append(d)
        return result
    return await asyncio.to_thread(_do_get)


async def get_all_operations(limit: int = 50) -> List[Dict[str, Any]]:
    def _do_get():
        con = _connect()
        rows = con.execute(
            "SELECT * FROM operations ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        con.close()
        result = []
        for row in rows:
            d = dict(row)
            d["tools_used"] = json.loads(d.get("tools_used") or "[]")
            d["errors"] = json.loads(d.get("errors") or "[]")
            result.append(d)
        return result
    return await asyncio.to_thread(_do_get)


async def generate_memory_hint(mode: str, target: str) -> str:
    ops = await get_past_operations(mode, limit=5)
    if not ops:
        return ""

    lines = [f"Past {mode} operations ({len(ops)} found):"]
    for op in ops:
        tools = ", ".join(op["tools_used"]) if op["tools_used"] else "unknown"
        errors = "; ".join(op["errors"][:2]) if op["errors"] else "none"
        lines.append(
            f"- target={op['target']} tools={tools} "
            f"findings={op['findings_count']} risk={op['risk_max']:.1f} "
            f"errors={errors} | {op.get('summary', '')[:120]}"
        )
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────
# MEMORY LEARNINGS — cross-operation knowledge base
# ─────────────────────────────────────────────────────────

TECH_PLAYBOOK_SEED = {
    "Laravel":    {"vulns": ["IDOR_api_resources", "mass_assignment", "debug_RCE"], "bypasses": ["X-Forwarded-For: 127.0.0.1"], "tools": ["sqlmap", "dalfox", "arjun"]},
    "WordPress":  {"vulns": ["xmlrpc_bruteforce", "user_enum", "plugin_CVEs"],      "bypasses": ["/?author=1 user enum"],          "tools": ["wpscan", "nuclei", "sqlmap"]},
    "PHP":        {"vulns": ["upload_phtml_bypass", "LFI_wrapper", "object_injection"], "bypasses": [".phtml", "php://filter"],     "tools": ["ffuf", "dalfox", "sqlmap"]},
    "JWT":        {"vulns": ["algorithm_confusion", "none_alg", "weak_secret"],     "bypasses": ["alg: none", "RS256→HS256"],       "tools": ["jwt_tool", "nuclei"]},
    "Express":    {"vulns": ["prototype_pollution", "nosql_injection", "path_traversal"], "bypasses": ["__proto__", "$where"],      "tools": ["nuclei", "sqlmap"]},
    "Django":     {"vulns": ["debug_mode_info", "admin_brute", "SSTI"],             "bypasses": ["{{7*7}} SSTI"],                   "tools": ["nuclei", "dalfox"]},
    "Spring":     {"vulns": ["actuator_exposed", "SpEL_injection", "Log4Shell"],    "bypasses": ["${jndi:ldap://...}"],             "tools": ["nuclei", "searchsploit"]},
    "Apache":     {"vulns": ["path_traversal_CVE", "mod_status_exposed"],           "bypasses": ["/../", "/.htaccess"],             "tools": ["nuclei", "nikto"]},
    "Nginx":      {"vulns": ["alias_traversal", "off_by_slash"],                    "bypasses": ["/static../etc/passwd"],           "tools": ["nuclei", "ffuf"]},
    "MySQL":      {"vulns": ["error_based_sqli", "time_based_sqli", "stacked_query"], "bypasses": ["', SLEEP(5)--"],                "tools": ["sqlmap"]},
}


async def init_learnings_db() -> None:
    """Create memory_learnings and tech_playbook tables + seed playbook."""
    def _do():
        con = _connect()
        con.execute("""
            CREATE TABLE IF NOT EXISTS memory_learnings (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                tech_stack       TEXT,
                vuln_type        TEXT NOT NULL,
                endpoint_pattern TEXT,
                payload          TEXT,
                tool             TEXT,
                success          INTEGER DEFAULT 1,
                notes            TEXT,
                target           TEXT,
                created_at       REAL DEFAULT (strftime('%s','now'))
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_ml_tech ON memory_learnings(tech_stack)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_ml_vuln ON memory_learnings(vuln_type)")

        con.execute("""
            CREATE TABLE IF NOT EXISTS tech_playbook (
                tech       TEXT PRIMARY KEY,
                known_vulns TEXT,
                bypasses    TEXT,
                best_tools  TEXT,
                updated_at  REAL DEFAULT (strftime('%s','now'))
            )
        """)

        # Seed default playbook entries (INSERT OR IGNORE so re-runs are safe)
        for tech, data in TECH_PLAYBOOK_SEED.items():
            con.execute(
                "INSERT OR IGNORE INTO tech_playbook (tech, known_vulns, bypasses, best_tools) VALUES (?,?,?,?)",
                (tech, json.dumps(data["vulns"]), json.dumps(data["bypasses"]), json.dumps(data["tools"]))
            )
        con.commit()
        con.close()
    await asyncio.to_thread(_do)


async def save_learning(
    vuln_type: str,
    success: bool,
    tech_stack: str = "",
    endpoint_pattern: str = "",
    payload: str = "",
    tool: str = "",
    notes: str = "",
    target: str = "",
) -> None:
    """Record what worked (or didn't) for future hypothesis boosting."""
    def _do():
        con = _connect()
        try:
            con.execute("BEGIN IMMEDIATE")
            con.execute(
                """INSERT INTO memory_learnings
                   (tech_stack, vuln_type, endpoint_pattern, payload, tool, success, notes, target)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (tech_stack, vuln_type, endpoint_pattern, payload, tool, int(success), notes, target)
            )
            # Also update tech_playbook if we have a new confirmed vuln for this tech
            if success and tech_stack:
                row = con.execute("SELECT known_vulns FROM tech_playbook WHERE tech=?", (tech_stack,)).fetchone()
                if row:
                    vulns = json.loads(row[0] or "[]")
                    if vuln_type not in vulns:
                        vulns.append(vuln_type)
                        con.execute("UPDATE tech_playbook SET known_vulns=?, updated_at=strftime('%s','now') WHERE tech=?",
                                    (json.dumps(vulns), tech_stack))
                else:
                    con.execute("INSERT INTO tech_playbook (tech, known_vulns, bypasses, best_tools) VALUES (?,?,?,?)",
                                (tech_stack, json.dumps([vuln_type]), json.dumps([]), json.dumps([tool] if tool else [])))
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()
    await asyncio.to_thread(_do)


async def get_playbook(tech_stack: str) -> Dict[str, Any]:
    """Return known vulns, bypasses, and best tools for a detected tech stack."""
    def _do():
        con = _connect()
        techs = [t.strip() for t in tech_stack.replace(",", " ").split() if len(t) > 2]
        results = {}
        for tech in techs:
            row = con.execute(
                "SELECT * FROM tech_playbook WHERE tech LIKE ?", (f"%{tech}%",)
            ).fetchone()
            if row:
                results[row["tech"]] = {
                    "known_vulns": json.loads(row["known_vulns"] or "[]"),
                    "bypasses":    json.loads(row["bypasses"]    or "[]"),
                    "best_tools":  json.loads(row["best_tools"]  or "[]"),
                }
        # Filter recent successes to the queried tech stacks for higher signal quality.
        # Fall back to global recent successes only if no tech-specific records found.
        if techs:
            placeholders = ",".join("?" for _ in techs)
            like_clauses  = " OR ".join("tech_stack LIKE ?" for _ in techs)
            tech_params   = [f"%{t}%" for t in techs]
            recent = con.execute(
                f"SELECT vuln_type, endpoint_pattern, tool FROM memory_learnings"
                f" WHERE success=1 AND ({like_clauses}) ORDER BY created_at DESC LIMIT 20",
                tech_params,
            ).fetchall()
            if not recent:
                recent = con.execute(
                    "SELECT vuln_type, endpoint_pattern, tool FROM memory_learnings WHERE success=1 ORDER BY created_at DESC LIMIT 20"
                ).fetchall()
        else:
            recent = con.execute(
                "SELECT vuln_type, endpoint_pattern, tool FROM memory_learnings WHERE success=1 ORDER BY created_at DESC LIMIT 20"
            ).fetchall()
        results["_recent_successes"] = [dict(r) for r in recent]
        con.close()
        return results
    return await asyncio.to_thread(_do)


async def get_all_learnings(limit: int = 100) -> List[Dict[str, Any]]:
    """Retrieve all memory learnings for the memory tab."""
    def _do():
        con = _connect()
        rows = con.execute(
            "SELECT * FROM memory_learnings ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        con.close()
        return [dict(r) for r in rows]
    return await asyncio.to_thread(_do)


# ── Recon Cache ───────────────────────────────────────────────────────────────

async def get_cached_recon(target: str, tool: str) -> Optional[Dict[str, Any]]:
    """
    Return cached findings for (target, tool) if still within TTL.
    Returns None if not found or expired so the caller re-runs the tool.
    """
    def _do():
        con = _connect()
        try:
            row = con.execute(
                "SELECT findings_json, raw_output, risk_score, created_at, ttl_hours "
                "FROM recon_cache WHERE target=? AND tool=?",
                (target, tool),
            ).fetchone()
            if not row:
                return None
            age_hours = (time.time() - row["created_at"]) / 3600.0
            if age_hours > row["ttl_hours"]:
                return None  # expired
            return {
                "findings":   json.loads(row["findings_json"] or "[]"),
                "raw_output": row["raw_output"] or "",
                "risk_score": row["risk_score"] or 0.0,
                "cached_at":  row["created_at"],
                "age_hours":  round(age_hours, 1),
            }
        finally:
            con.close()
    return await asyncio.to_thread(_do)


async def save_recon_cache(
    target: str,
    tool: str,
    findings: List[Dict[str, Any]],
    raw_output: str,
    risk_score: float = 0.0,
) -> None:
    """Upsert recon results for (target, tool) into the cache."""
    ttl = RECON_TTL.get(tool, 12.0)
    def _do():
        con = _connect()
        try:
            con.execute(
                """INSERT INTO recon_cache (target, tool, findings_json, raw_output, risk_score, created_at, ttl_hours)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(target, tool) DO UPDATE SET
                     findings_json=excluded.findings_json,
                     raw_output=excluded.raw_output,
                     risk_score=excluded.risk_score,
                     created_at=excluded.created_at,
                     ttl_hours=excluded.ttl_hours""",
                (target, tool, json.dumps(findings), raw_output[:20000], risk_score, time.time(), ttl),
            )
            con.commit()
        finally:
            con.close()
    await asyncio.to_thread(_do)


async def get_target_recon_summary(target: str) -> Dict[str, Any]:
    """
    Return all non-expired cached recon for a target, keyed by tool.
    Used by StructuredContextBuilder to avoid re-running recon and to
    build richer LLM context from known data.
    """
    def _do():
        con = _connect()
        try:
            rows = con.execute(
                "SELECT tool, findings_json, raw_output, risk_score, created_at, ttl_hours "
                "FROM recon_cache WHERE target=? ORDER BY created_at DESC",
                (target,),
            ).fetchall()
            summary: Dict[str, Any] = {}
            now = time.time()
            for row in rows:
                age_hours = (now - row["created_at"]) / 3600.0
                if age_hours <= row["ttl_hours"]:
                    summary[row["tool"]] = {
                        "findings":  json.loads(row["findings_json"] or "[]"),
                        "risk_score": row["risk_score"] or 0.0,
                        "age_hours":  round(age_hours, 1),
                    }
            return summary
        finally:
            con.close()
    return await asyncio.to_thread(_do)
