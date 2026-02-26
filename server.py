import asyncio
import contextlib
import json
import logging
import os
import sys
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import aiosqlite
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from mcp.server.fastmcp import FastMCP

sys.path.insert(0, str(Path(__file__).parent))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("mergen")

from plugins import discover_plugins
from plugins.base import ToolResult
from server.process_manager import process_manager, JobStatus
from server.attack_planner import (
    TargetProfiler, KillChainBuilder, AdaptiveExecutionEngine,
    TargetType, AttackPlan, StructuredContextBuilder,
)
from server.memory import (
    init_memory_db, init_learnings_db, save_operation, get_past_operations,
    get_all_operations, generate_memory_hint,
    save_learning, get_playbook, get_all_learnings,
    get_cached_recon, save_recon_cache, get_target_recon_summary, RECON_TTL,
)
from server.mode_profiles import get_profile
from server.web_intel import generate_priority_hints, hints_to_playbook_bonus, hints_summary
from server.playbook_selector import select_playbooks, selection_summary
from server.defense_detect import detect_defenses, defense_to_surface_update
from server.correlation_engine import correlate
from server.reporter import generate_report, ReportConfig, to_json, to_csv
from server.coverage_matrix import build_matrix_from_findings

_profiler = TargetProfiler()
_chain_builder = KillChainBuilder()

STATIC_DIR     = Path(__file__).parent / "static"
DASHBOARD_HTML = Path(__file__).parent / "dashboard" / "index.html"
DB_PATH        = Path(__file__).parent / "data" / "sessions.db"

PLUGINS: Dict[str, Any] = {}

@contextlib.asynccontextmanager
async def lifespan(app: "FastAPI"):
    global PLUGINS
    init_db()
    await init_memory_db()
    await init_learnings_db()
    cleanup_old_findings(days=7)
    PLUGINS = discover_plugins()
    logger.info(f"{len(PLUGINS)} plugins loaded: {', '.join(sorted(PLUGINS.keys()))}")
    # Establish psutil CPU baseline — first call always returns 0.0, so prime it now
    try:
        import psutil
        psutil.cpu_percent(interval=None)
    except ImportError:
        pass
    yield

app = FastAPI(title="Mergen", version="2.0.0", docs_url="/docs", lifespan=lifespan)
mcp = FastMCP("mergen")

app.mount("/sse", mcp.sse_app())

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def init_db():
    try:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)  # ensure data/ exists
        con = sqlite3.connect(str(DB_PATH))
        con.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session TEXT,
                tool TEXT,
                target TEXT,
                risk_score REAL,
                findings_json TEXT,
                created_at TEXT
            )
        """)
        # Indexes for faster session queries
        con.execute("CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_findings_created_at ON findings(created_at)")
        con.commit()
        con.close()
        logger.info(f"DB Initialized at {DB_PATH}")
    except Exception as e:
        logger.error(f"init_db failed: {e}")

def cleanup_old_findings(days: int = 7):
    """Deletes findings older than `days` to prevent database bloat."""
    try:
        con = sqlite3.connect(str(DB_PATH))
        threshold = (datetime.now(timezone.utc) - __import__('datetime').timedelta(days=days)).isoformat()
        res = con.execute("DELETE FROM findings WHERE created_at < ?", (threshold,))
        deleted_count = res.rowcount
        con.commit()
        con.close()
        if deleted_count > 0:
            logger.info(f"Cleaned up {deleted_count} old DB findings.")
    except Exception as e:
        logger.error(f"cleanup_old_findings failed: {e}")

async def save_finding(session: str, result: ToolResult):
    def _do_save():
        try:
            con = sqlite3.connect(str(DB_PATH))
            con.execute(
                "INSERT INTO findings (session, tool, target, risk_score, findings_json, created_at) VALUES (?,?,?,?,?,?)",
                (session, result.tool, result.target, result.risk_score,
                 json.dumps(result.findings), datetime.now(timezone.utc).isoformat())
            )
            con.commit()
            con.close()
            logger.info(f"Saved finding: session={session} tool={result.tool} target={result.target}")
        except Exception as e:
            logger.error(f"save_finding failed: {e}")
    await asyncio.to_thread(_do_save)

async def get_session_findings(session: str) -> List[Dict]:
    def _do_get():
        try:
            con = sqlite3.connect(str(DB_PATH))
            rows = con.execute(
                "SELECT tool, target, risk_score, findings_json, created_at FROM findings WHERE session=? ORDER BY created_at",
                (session,)
            ).fetchall()
            con.close()
            return [
                {"tool": r[0], "target": r[1], "risk_score": r[2],
                 "findings": json.loads(r[3]), "created_at": r[4]}
                for r in rows
            ]
        except Exception as e:
            logger.error(f"get_session_findings failed: {e}")
            return []
    return await asyncio.to_thread(_do_get)



@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    if DASHBOARD_HTML.exists():
        return HTMLResponse(DASHBOARD_HTML.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Dashboard not found.</h1>")

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()

    async def send(event: Dict[str, Any]):
        await ws.send_text(json.dumps(event))

    sub = process_manager.subscribe(send)
    await ws.send_text(json.dumps({
        "event": "init",
        "jobs": process_manager.list_jobs(),
        "plugins": [
            {"name": p.name, "category": p.category, "available": p.is_available()}
            for p in PLUGINS.values()
        ],
    }))

    try:
        while True:
            data = await ws.receive_text()
            msg = json.loads(data)
            if msg.get("action") == "kill":
                await process_manager.kill_job(msg.get("job_id", ""))
    except WebSocketDisconnect:
        process_manager.unsubscribe(sub)


@app.get("/api/jobs")
async def list_jobs():
    return {"jobs": process_manager.list_jobs()}

@app.get("/api/system")
async def get_system_metrics():
    try:
        import psutil
        mem = psutil.virtual_memory()
        return {
            "cpu_percent": psutil.cpu_percent(interval=None),
            "mem_percent": mem.percent,
            "mem_used_gb": round(mem.used / (1024**3), 1),
            "mem_total_gb": round(mem.total / (1024**3), 1),
        }
    except ImportError:
        # Fallback: read Linux /proc/stat and /proc/meminfo directly
        try:
            import subprocess as _sp
            # CPU: use top in batch mode for a one-shot reading
            cpu_out = _sp.run(
                ["top", "-bn1"],
                capture_output=True, text=True, timeout=3
            ).stdout
            cpu_pct = 0.0
            for line in cpu_out.splitlines():
                if "Cpu(s)" in line or "%Cpu" in line:
                    # Format: "%Cpu(s):  X.X us, Y.Y sy, ..."
                    import re as _re
                    m = _re.search(r"(\d+\.?\d*)\s*us", line)
                    if m:
                        cpu_pct = float(m.group(1))
                    break
            # Memory: read /proc/meminfo
            mem_total_kb, mem_avail_kb = 0, 0
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        mem_total_kb = int(line.split()[1])
                    elif line.startswith("MemAvailable:"):
                        mem_avail_kb = int(line.split()[1])
            mem_used_kb = mem_total_kb - mem_avail_kb
            mem_pct = round(mem_used_kb / mem_total_kb * 100, 1) if mem_total_kb else 0.0
            return {
                "cpu_percent": cpu_pct,
                "mem_percent": mem_pct,
                "mem_used_gb": round(mem_used_kb / (1024**2), 1),
                "mem_total_gb": round(mem_total_kb / (1024**2), 1),
            }
        except Exception:
            return {
                "cpu_percent": 0.0,
                "mem_percent": 0.0,
                "mem_used_gb": 0.0,
                "mem_total_gb": 0.0,
                "error": "psutil not installed — run: pip install psutil"
            }


@app.get("/api/plugins")
async def list_plugins_api():
    return {
        "plugins": [
            {"name": p.name, "description": p.description,
             "category": p.category, "available": p.is_available()}
            for p in sorted(PLUGINS.values(), key=lambda x: x.category)
        ]
    }

@app.get("/api/jobs/{job_id}")
async def get_job_api(job_id: str):
    job = process_manager.get_job(job_id)
    if not job:
        from fastapi.responses import JSONResponse
        return JSONResponse({"error": f"Job '{job_id}' not found."}, status_code=404)
    return job.to_dict()

from fastapi import BackgroundTasks
@app.delete("/api/jobs/{job_id}")
async def kill_job_api(job_id: str):
    ok = await process_manager.kill_job(job_id)
    return {"killed": ok}

@app.get("/api/sessions/{session}/report")
async def get_report(session: str):
    findings = await get_session_findings(session)
    html = _generate_html_report(session, findings)
    return HTMLResponse(html)

@app.get("/api/sessions/{session}/report/json")
async def get_report_json(session: str):
    findings = await get_session_findings(session)
    from server.reporter import to_json
    flat_findings = []
    for f in findings:
        for finding in f.get("findings", []):
            if isinstance(finding, dict):
                # Ensure each finding has context
                finding["url"] = finding.get("url", f.get("target"))
                # Sometimes Nikto returns a simple string finding, but our schema expects dict
                flat_findings.append(finding)
            elif isinstance(finding, str):
                flat_findings.append({"name": "Finding", "severity": "info", "asset": f.get("target"), "finding": finding})
    
    return JSONResponse(json.loads(to_json(flat_findings, [])))

@app.get("/api/sessions/{session}/report/csv")
async def get_report_csv(session: str):
    from fastapi.responses import PlainTextResponse
    findings = await get_session_findings(session)
    from server.reporter import to_csv
    flat_findings = []
    for f in findings:
        for finding in f.get("findings", []):
            if isinstance(finding, dict):
                finding["url"] = finding.get("url", f.get("target"))
                flat_findings.append(finding)
            elif isinstance(finding, str):
                flat_findings.append({"name": "Finding", "severity": "info", "url": f.get("target"), "finding": finding})
    csv_data = to_csv(flat_findings)
    return PlainTextResponse(csv_data, media_type="text/csv")

from pydantic import BaseModel, Field

class ToolRequest(BaseModel):
    tool: str
    target: str
    options: Optional[Dict[str, Any]] = None
    mode: str = "default"
    session: str = "default"

class CommandRequest(BaseModel):
    command: str
    timeout: int = 120

class EliteHuntRequest(BaseModel):
    target: str
    mode: str = "bb"
    session: str = "default"
    objective: str = "full_compromise"
    report_verbose: bool = False
    report_format: str = "markdown"
    assets: List[str] = Field(default_factory=list)

class LearningRequest(BaseModel):
    vuln_type: str
    success: bool = True
    tech_stack: str = ""
    endpoint_pattern: str = ""
    payload: str = ""
    tool: str = ""
    notes: str = ""
    target: str = ""

@app.post("/api/command")
async def execute_command_api(req: CommandRequest):
    job = await process_manager.run(
        tool="shell", target=req.command[:60],
        cmd=["bash", "-c", req.command], timeout=req.timeout,
    )
    # Wait for the job to finish so callers get actual output
    await process_manager.wait(job)
    return {
        "job_id": job.id,
        "command": req.command,
        "status": job.status.value,
        "output": "\n".join(job.output_lines),
        "return_code": job.return_code,
    }

@app.post("/api/write_and_exec")
async def write_and_exec(data: Dict[str, Any]):
    """
    Write content to a file on disk then execute a command.
    Used by Claude to run custom exploit scripts.
    """
    filename = data.get("filename", "")
    content  = data.get("content", "")
    command  = data.get("command", "")
    timeout  = int(data.get("timeout", 60))
    workdir  = data.get("workdir", "/tmp/mergen_exploits")

    if not command:
        return JSONResponse({"error": "command is required"}, status_code=400)

    # Resolve workdir to an absolute path and create it
    resolved_workdir = Path(workdir).resolve()
    resolved_workdir.mkdir(parents=True, exist_ok=True)

    filepath = None
    if content and filename:
        # Guard against path traversal: ensure the resolved filepath stays under workdir
        filepath = (resolved_workdir / filename).resolve()
        if not str(filepath).startswith(str(resolved_workdir)):
            return JSONResponse(
                {"error": f"Path traversal detected: filename must stay within workdir ({resolved_workdir})"},
                status_code=400,
            )
        filepath.write_text(content)

    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(resolved_workdir),
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            output = stdout.decode("utf-8", errors="replace")
            return {
                "success": proc.returncode == 0,
                "return_code": proc.returncode,
                "output": output[-10000:],
                "file_written": str(filepath) if filepath else None,
                "command": command,
            }
        except asyncio.TimeoutError:
            proc.kill()
            return {
                "success": False,
                "error": f"Command timed out after {timeout}s",
                "command": command,
            }
    except Exception as e:
        return JSONResponse({"error": str(e), "success": False}, status_code=500)


@app.post("/api/tools/execute")
async def execute_tool_api(req: ToolRequest, bg_tasks: BackgroundTasks):
    plugin = PLUGINS.get(req.tool)
    if not plugin:
        return JSONResponse({"error": f"Unknown tool '{req.tool}'"}, status_code=404)
    if not plugin.is_available():
        return JSONResponse({"error": f"Tool '{req.tool}' not installed"}, status_code=400)

    opts = {"mode": req.mode}
    if req.options:
        opts.update(req.options)

    start_t = time.time()
    result: ToolResult = await plugin.run(target=req.target, options=opts)

    # Always save to session DB regardless of whether findings is empty —
    # this ensures every tool run (including failures) appears in the Sessions tab.
    await save_finding(req.session, result)

    await save_operation(
        mode=req.mode,
        target=req.target,
        session=req.session,
        tools_used=[req.tool],
        findings_count=len(result.findings),
        risk_max=result.risk_score,
        summary=f"Single tool execution: {req.tool} (Success: {result.success})",
        errors=[result.error] if result.error else [],
        started_at=start_t
    )

    return result.to_dict()


@app.post("/api/tools/execute_async")
async def execute_tool_async_api(req: ToolRequest):
    """Fire-and-forget tool execution. Returns job_id immediately so MCP doesn't timeout.
    Use GET /api/jobs/{job_id} to poll for results."""
    plugin = PLUGINS.get(req.tool)
    if not plugin:
        return JSONResponse({"error": f"Unknown tool '{req.tool}'"}, status_code=404)
    if not plugin.is_available():
        return JSONResponse({"error": f"Tool '{req.tool}' not installed"}, status_code=400)

    opts = {"mode": req.mode}
    if req.options:
        opts.update(req.options)

    # Snapshot existing job IDs before firing so we can identify the new one
    existing_ids = set(process_manager._jobs.keys())

    async def _bg():
        start_t = time.time()
        result = await plugin.run(target=req.target, options=opts)
        await save_finding(req.session, result)
        await save_operation(
            mode=req.mode,
            target=req.target,
            session=req.session,
            tools_used=[req.tool],
            findings_count=len(result.findings),
            risk_max=result.risk_score,
            summary=f"Async tool: {req.tool} → {len(result.findings)} findings (success={result.success})",
            errors=[result.error] if result.error else [],
            started_at=start_t,
        )

    asyncio.ensure_future(_bg())

    # Poll up to 2 s (40 × 50 ms) for the subprocess job to register
    job_id = None
    for _ in range(40):
        await asyncio.sleep(0.05)
        new_ids = set(process_manager._jobs.keys()) - existing_ids
        if new_ids:
            job_id = sorted(new_ids)[0]
            break

    return {
        "job_id": job_id,
        "tool": req.tool,
        "target": req.target,
        "session": req.session,
        "status": "started",
        "message": (
            f"Tool '{req.tool}' running in background. "
            f"Poll with get_job_output('{job_id}') until status='done'."
        ),
    }


@app.get("/api/sessions")
async def list_all_sessions():
    try:
        con = sqlite3.connect(str(DB_PATH))
        # Merge sessions from both findings table and operations table
        rows = con.execute("""
            SELECT session, SUM(cnt) as total, MAX(last_scan) as last_scan
            FROM (
                SELECT session, COUNT(*) as cnt, MAX(created_at) as last_scan
                FROM findings WHERE session IS NOT NULL AND session != ''
                GROUP BY session
                UNION ALL
                SELECT session, COUNT(*) as cnt, MAX(datetime(started_at, 'unixepoch')) as last_scan
                FROM operations WHERE session IS NOT NULL AND session != ''
                GROUP BY session
            )
            GROUP BY session ORDER BY last_scan DESC
        """).fetchall()
        con.close()
        return {
            "sessions": [
                {"name": r[0], "scan_count": r[1], "last_scan": r[2]}
                for r in rows
            ]
        }
    except Exception as e:
        logger.error(f"list_all_sessions failed: {e}")
        return {"sessions": []}

@app.get("/api/sessions/{session}")
async def get_session(session: str):
    return {"session": session, "findings": await get_session_findings(session)}


@app.get("/api/findings/recent")
async def get_recent_findings(limit: int = 50):
    """Return recent tool runs with findings across all sessions."""
    def _do():
        try:
            con = sqlite3.connect(str(DB_PATH))
            rows = con.execute(
                "SELECT session, tool, target, risk_score, findings_json, created_at "
                "FROM findings ORDER BY created_at DESC LIMIT ?",
                (limit,)
            ).fetchall()
            con.close()
            result = []
            for r in rows:
                try:
                    findings = json.loads(r[4]) if r[4] else []
                except Exception:
                    findings = []
                result.append({
                    "session": r[0], "tool": r[1], "target": r[2],
                    "risk_score": r[3], "findings_count": len(findings),
                    "created_at": r[5]
                })
            return result
        except Exception as e:
            logger.error(f"get_recent_findings failed: {e}")
            return []
    items = await asyncio.to_thread(_do)
    return {"items": items, "count": len(items)}


@app.get("/api/memory")
async def list_memory():
    try:
        ops = await asyncio.wait_for(get_all_operations(limit=100), timeout=5.0)
        grouped: Dict[str, list] = {}
        for op in ops:
            grouped.setdefault(op["mode"], []).append(op)
        return {"operations": ops, "by_mode": grouped}
    except Exception as e:
        logger.error(f"Memory API error: {e}")
        return {"operations": [], "by_mode": {}}


@app.post("/api/memory/learn")
async def api_save_learning(req: LearningRequest):
    """Record what worked for future hypothesis boosting."""
    await save_learning(
        vuln_type=req.vuln_type,
        success=req.success,
        tech_stack=req.tech_stack,
        endpoint_pattern=req.endpoint_pattern,
        payload=req.payload,
        tool=req.tool,
        notes=req.notes,
        target=req.target,
    )
    return {"status": "saved"}


@app.get("/api/memory/playbook/{tech}")
async def api_get_playbook(tech: str):
    """Return known vulns and tactics for a tech stack."""
    return await get_playbook(tech)


@app.get("/api/memory/learnings")
async def api_get_learnings(limit: int = 100):
    """Return all recorded learnings."""
    return await get_all_learnings(limit)


@app.get("/api/memory/{mode}")
async def list_memory_by_mode(mode: str):
    try:
        ops = await asyncio.wait_for(get_past_operations(mode, limit=50), timeout=5.0)
        return {"mode": mode, "operations": ops, "count": len(ops)}
    except Exception as e:
        logger.error(f"Memory by mode API error: {e}")
        return {"mode": mode, "operations": [], "count": 0}


def _generate_html_report(session: str, data: List[Dict]) -> str:
    total_findings = sum(len(d["findings"]) for d in data)
    max_risk = max((d["risk_score"] for d in data), default=0)
    risk_color = "#e63946" if max_risk >= 7 else "#f39c12" if max_risk >= 4 else "#2ecc71"

    rows = ""
    for d in data:
        if not d["findings"]:
            rows += f"""
            <tr>
                <td>{d['tool'].upper()}</td>
                <td>{d['target']}</td>
                <td style="color:#666"><em>No findings or execution error</em></td>
                <td style="color:#666">0.0/10</td>
                <td>{d['created_at'][:19]}</td>
            </tr>"""
        else:
            for f in d["findings"]:
                rows += f"""
                <tr>
                    <td>{d['tool'].upper()}</td>
                    <td>{d['target']}</td>
                    <td>{json.dumps(f)[:120]}</td>
                    <td style="color:{risk_color}">{d['risk_score']}/10</td>
                    <td>{d['created_at'][:19]}</td>
                </tr>"""

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>Mergen Report — {session}</title>
<style>
  body {{ font-family: 'JetBrains Mono', monospace; background: #0a0a0f; color: #e0e0e0; padding: 40px; }}
  h1 {{ color: #e63946; letter-spacing: 3px; }}
  .stats {{ display: flex; gap: 30px; margin: 20px 0; }}
  .stat {{ background: #111118; border: 1px solid #2a2a3a; padding: 15px 25px; border-radius: 8px; }}
  .stat-val {{ font-size: 28px; font-weight: 700; color: {risk_color}; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
  th {{ background: #1a1a24; color: #e63946; padding: 10px; text-align: left; border-bottom: 2px solid #e63946; }}
  td {{ padding: 8px 10px; border-bottom: 1px solid #2a2a3a; font-size: 12px; }}
  tr:hover {{ background: #111118; }}
</style></head>
<body>
<h1> Mergen — Pentest Report</h1>
<p style="color:#666">Session: {session} | Generated: {datetime.now(timezone.utc).isoformat()[:19]} UTC</p>
<div class="stats">
  <div class="stat"><div class="stat-val">{len(data)}</div><div>Tools Run</div></div>
  <div class="stat"><div class="stat-val">{total_findings}</div><div>Total Findings</div></div>
  <div class="stat"><div class="stat-val" style="color:{risk_color}">{max_risk}/10</div><div>Max Risk Score</div></div>
</div>
<table>
  <tr><th>Tool</th><th>Target</th><th>Finding</th><th>Risk</th><th>Time</th></tr>
  {rows if rows else '<tr><td colspan="5" style="color:#666;text-align:center">No findings recorded.</td></tr>'}
</table>
</body></html>"""


@mcp.tool()
async def run_tool(
    tool_name: str,
    target: str,
    options: Optional[str] = None,
    mode: str = "default",
    session: str = "default",
) -> Dict[str, Any]:
    """
    Run a single tool directly (e.g. 'nmap', 'whois', 'sqlmap').
    Options can be a JSON string or raw arguments.
    """
    opts: Dict[str, Any] = {"mode": mode}
    if options:
        try:
            opts.update(json.loads(options))
        except json.JSONDecodeError:
            opts["extra_args"] = options.split()

    plugin = PLUGINS.get(tool_name)
    if not plugin:
        return {"error": f"Unknown tool '{tool_name}'", "available": sorted(PLUGINS.keys())}
    if not plugin.is_available():
        return {"error": f"'{tool_name}' not installed on this system."}

    start_t = time.time()
    result: ToolResult = await plugin.run(target=target, options=opts)

    await save_finding(session, result)

    await save_operation(
        mode=mode,
        target=target,
        session=session,
        tools_used=[tool_name],
        findings_count=len(result.findings),
        risk_max=result.risk_score,
        summary=f"Single tool execution: {tool_name} (Success: {result.success})",
        errors=[result.error] if result.error else [],
        started_at=start_t
    )

    return result.to_dict()


@mcp.tool()
async def list_tools() -> Dict[str, Any]:
    """
    List all available plugins, their descriptions, and installation status.
    """
    by_cat: Dict[str, List] = {}
    for p in sorted(PLUGINS.values(), key=lambda x: x.category):
        by_cat.setdefault(p.category, []).append({
            "name": p.name,
            "description": p.description,
            "available": p.is_available(),
        })
    return {"categories": by_cat, "total": len(PLUGINS)}


@mcp.tool()
async def run_command(command: str, timeout: int = 120) -> Dict[str, Any]:
    """
    Execute a raw shell command on the server.
    Returns the output and status code. Use with caution.
    """
    job = await process_manager.run(
        tool="shell", target=command[:60],
        cmd=["bash", "-c", command], timeout=timeout,
    )
    # Wait for the job to finish so callers get actual output
    await process_manager.wait(job)
    return {
        "job_id": job.id,
        "command": command,
        "status": job.status.value,
        "output": "\n".join(job.output_lines),
        "return_code": job.return_code,
    }


@mcp.tool()
async def get_job_output(job_id: str) -> Dict[str, Any]:
    job = process_manager.get_job(job_id)
    if not job:
        return {"error": f"Job '{job_id}' not found."}
    return job.to_dict()


@mcp.tool()
async def kill_job_mcp(job_id: str) -> Dict[str, Any]:
    ok = await process_manager.kill_job(job_id)
    return {"killed": ok, "job_id": job_id}


@app.post("/api/workflows/execute")
async def execute_workflow_api(req: ToolRequest):
    if req.tool == "smart_recon":
        return await _run_smart_recon(req.target, req.mode, req.session)
    elif req.tool == "vuln_analysis":
        return await _run_vuln_analysis(req.target, req.mode, req.session)
    elif req.tool == "exploit_assist":
        service = req.options.get("service", "") if req.options else ""
        version = req.options.get("version", "") if req.options else ""
        return await exploit_assist(req.target, service, version, req.session)
    elif req.tool == "plan_attack":
        obj = req.options.get("objective", "full_compromise") if req.options else "full_compromise"
        ctx = req.options.get("context", "") if req.options else ""
        hint = req.options.get("target_type_hint", "") if req.options else ""
        return await plan_attack(req.target, req.mode, req.session, obj, hint, ctx)
    elif req.tool == "execute_plan":
        obj = req.options.get("objective", "full_compromise") if req.options else "full_compromise"
        ctx = req.options.get("context", "") if req.options else ""
        hint = req.options.get("target_type_hint", "") if req.options else ""
        return await execute_plan(req.target, req.mode, req.session, obj, hint, ctx)
    elif req.tool == "adaptive_attack":
        obj = req.options.get("objective", "full_compromise") if req.options else "full_compromise"
        ctx = req.options.get("context", "") if req.options else ""
        return await adaptive_attack(req.target, req.mode, req.session, obj, ctx)

    return JSONResponse({"error": f"Unknown workflow '{req.tool}'"}, status_code=404)



async def _run_smart_recon(target: str, mode: str, session: str) -> Dict[str, Any]:
    memory_hint = await generate_memory_hint(mode, target)
    if memory_hint:
        logger.info(f"Memory: {mode} hint loaded ({len(memory_hint)} chars)")

    results = []
    all_suggested = set()
    tools_used = []
    op_started = time.time()

    rustscan = PLUGINS.get("rustscan")
    nmap = PLUGINS.get("nmap")

    if rustscan and rustscan.is_available():
        # Using plugin.run natively so BaseTool._exec broadcasts live events to ProcessManager
        r = await rustscan.run(target, options={"mode": mode})
        results.append({"phase": "port_discovery", **r.to_dict()})
        all_suggested.update(r.suggested_next)
        tools_used.append("rustscan")
        await save_finding(session, r)

    if nmap and nmap.is_available():
        r = await nmap.run(target, options={"mode": mode})
        results.append({"phase": "service_detection", **r.to_dict()})
        all_suggested.update(r.suggested_next)
        tools_used.append("nmap")
        await save_finding(session, r)
        http_ports = [f for f in r.findings if isinstance(f, dict) and f.get("port") in [80, 443, 8080, 8443]]
        if http_ports:
                url = f"https://{target}" if any(f.get("port") == 443 for f in http_ports) else f"http://{target}"
                whatweb = PLUGINS.get("whatweb")
                if whatweb and whatweb.is_available():
                    wr = await whatweb.run(url, options={"mode": mode})
                    results.append({"phase": "web_fingerprint", **wr.to_dict()})
                    all_suggested.update(wr.suggested_next)
                    tools_used.append("whatweb")
                    await save_finding(session, wr)

    total_findings = sum(len(r.get("findings", [])) for r in results)
    risk_max = max((r.get("risk_score", 0.0) for r in results), default=0.0)
    await save_operation(
        mode=mode, target=target, session=session,
        tools_used=tools_used, findings_count=total_findings,
        risk_max=risk_max,
        summary=f"smart_recon: {len(results)} phases, {total_findings} findings",
        started_at=op_started,
    )

    return {
        "workflow": "smart_recon",
        "target": target,
        "mode": mode,
        "session": session,
        "memory_hint": memory_hint or None,
        "phases_completed": len(results),
        "results": results,
        "suggested_next": list(all_suggested),
        "report_url": f"/api/sessions/{session}/report",
    }


async def _run_vuln_analysis(target: str, mode: str, session: str) -> Dict[str, Any]:
    results = []
    all_findings = []

    nuclei = PLUGINS.get("nuclei")
    if nuclei and nuclei.is_available():
        r = await nuclei.run(target, options={"mode": mode})
        results.append(r.to_dict())
        all_findings.extend(r.findings)
        await save_finding(session, r)

    nikto = PLUGINS.get("nikto")
    if nikto and nikto.is_available():
        r = await nikto.run(target, options={"mode": mode})
        results.append(r.to_dict())
        all_findings.extend(r.findings)
        await save_finding(session, r)

    correlations = []
    searchsploit = PLUGINS.get("searchsploit")
    if searchsploit and searchsploit.is_available():
        search_terms = set()
        for f in all_findings:
            if isinstance(f, dict):
                name = f.get("name", "") or f.get("technology", "") or f.get("finding", "")
                if name and len(name) > 3:
                    search_terms.add(name[:40])
        for term in list(search_terms)[:5]:
            sr = await searchsploit.run(target=term, options={})
            if sr.findings:
                correlations.extend(sr.findings)

    all_findings_sorted = sorted(
        all_findings,
        key=lambda f: f.get("risk_score", 0) if isinstance(f, dict) else 0,
        reverse=True
    )

    tools_used = []
    if nuclei and nuclei.is_available(): tools_used.append("nuclei")
    if nikto and nikto.is_available(): tools_used.append("nikto")
    if searchsploit and searchsploit.is_available(): tools_used.append("searchsploit")

    await save_operation(
        mode=mode,
        target=target,
        session=session,
        tools_used=tools_used,
        findings_count=len(all_findings_sorted),
        risk_max=all_findings_sorted[0].get("risk_score", 0.0) if all_findings_sorted and isinstance(all_findings_sorted[0], dict) else 0.0,
        summary=f"vuln_analysis: {len(results)} phases, {len(all_findings_sorted)} findings, {len(correlations)} exploit matches",
        started_at=time.time() - 5,
    )

    return {
        "workflow": "vuln_analysis",
        "target": target,
        "mode": mode,
        "session": session,
        "tool_results": results,
        "top_findings": all_findings_sorted[:20],
        "exploit_correlations": correlations[:10],
        "report_url": f"/api/sessions/{session}/report",
    }






@mcp.tool()
async def smart_recon(
    target: str,
    mode: str = "default",
    session: str = "default",
) -> Dict[str, Any]:
    """
    Run an intelligent reconnaissance workflow.
    Combines RustScan (ports), Nmap (services), and WhatWeb (fingerprinting) + checks for WAF/CDN.
    """
    return await _run_smart_recon(target, mode, session)


@mcp.tool()
async def vuln_analysis(
    target: str,
    mode: str = "default",
    session: str = "default",
) -> Dict[str, Any]:
    """
    Run vulnerability analysis using Nuclei, Nikto, and SearchSploit.
    Best run AFTER recon is complete.
    """
    return await _run_vuln_analysis(target, mode, session)


@mcp.tool()
async def exploit_assist(
    target: str,
    service: str,
    version: str = "",
    session: str = "default",
) -> Dict[str, Any]:
    """
    Find exploits for a specific service version using SearchSploit.
    Returns ready-to-run commands (Metasploit/Python).
    """
    query = f"{service} {version}".strip()
    results = []

    searchsploit = PLUGINS.get("searchsploit")
    if searchsploit and searchsploit.is_available():
        r = await searchsploit.run(target=query, options={"exact": bool(version)})
        results = r.findings

    commands = []
    for exploit in results[:5]:
        title = exploit.get("title", "")
        path = exploit.get("path", "")
        edb_id = exploit.get("edb_id", "")
        etype = exploit.get("type", "remote")

        if etype == "remote":
            commands.append({
                "exploit": title,
                "edb_id": edb_id,
                "commands": [
                    f"searchsploit -m {edb_id}",
                    f"# Check for Metasploit module: search {service}",
                    f"python3 {path} {target}",
                ],
                "priority": "HIGH",
            })
        else:
            commands.append({
                "exploit": title,
                "edb_id": edb_id,
                "commands": [f"searchsploit -m {edb_id}"],
                "priority": "MEDIUM",
            })

    return {
        "workflow": "exploit_assist",
        "target": target,
        "query": query,
        "session": session,
        "exploits_found": len(results),
        "ready_commands": commands,
        "tip": f"Run: msfconsole -q -x 'search {service}; use 0; set RHOSTS {target}; run'",
    }


@mcp.tool()
async def get_session_report(session: str = "default") -> Dict[str, Any]:
    """
    Get a summary of findings, risk scores, and tool outputs for a session.
    """
    findings = await get_session_findings(session)
    sorted_findings = sorted(findings, key=lambda x: x["risk_score"], reverse=True)
    max_risk = max((f["risk_score"] for f in findings), default=0)

    return {
        "session": session,
        "total_scans": len(findings),
        "max_risk_score": max_risk,
        "findings": sorted_findings,
        "html_report_url": f"/api/sessions/{session}/report",
    }



@mcp.tool()
async def plan_attack(
    target: str,
    mode: str = "default",
    session: str = "default",
    objective: str = "full_compromise",
    target_type_hint: str = "",
    context: Optional[Union[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Generate a comprehensive attack plan for a given target.
    Analyzes the 'target_type' (web_app, network_host, etc.) and creates a phased list of tools to run.
    """
    hints = {}
    if target_type_hint:
        hints["type"] = target_type_hint
    if context:
        try:
            if isinstance(context, str):
                hints.update(json.loads(context))
            elif isinstance(context, dict):
                hints.update(context)
        except Exception:
            pass

    target_type = _profiler.classify(target, hints)

    surface = _profiler.build_surface_map(
        target, target_type,
        nmap_findings=hints.get("nmap_findings", []),
    )

    if hints.get("open_ports"):
        for port in hints["open_ports"]:
            surface["open_ports"].append(port)
            if port in [80, 443, 8080, 8443]:
                surface["has_web"] = True
                proto = "https" if port in [443, 8443] else "http"
                surface["web_urls"].append(f"{proto}://{target}")
            if port in [139, 445]:
                surface["has_smb"] = True
            if port == 22:
                surface["has_ssh"] = True

    plan = _chain_builder.build(
        target=target,
        target_type=target_type,
        surface=surface,
        mode=mode,
        session=session,
        objective=objective,
        memory_context=await generate_memory_hint(mode, target),
    )

    return {
        "status": "plan_ready",
        "plan": plan.to_dict(),
        "next_action": "Call execute_plan with the same parameters to run it, or adaptive_attack to plan+execute in one call.",
    }


@mcp.tool()
async def execute_plan(
    target: str,
    mode: str = "default",
    session: str = "default",
    objective: str = "full_compromise",
    target_type_hint: str = "",
    context: Optional[Union[str, Dict[str, Any]]] = None,
    max_steps: int = 15,
) -> Dict[str, Any]:
    """
    Execute a previously generated attack plan (or generate one on the fly).
    Runs tools in sequence, handles dependencies, and adapts to new findings (e.g. if port 80 found, run whatweb).
    """
    hints = {}
    if target_type_hint:
        hints["type"] = target_type_hint
    if context:
        try:
            if isinstance(context, str):
                hints.update(json.loads(context))
            elif isinstance(context, dict):
                hints.update(context)
        except Exception:
            pass

    target_type = _profiler.classify(target, hints)
    surface = _profiler.build_surface_map(target, target_type, nmap_findings=hints.get("nmap_findings", []))

    if hints.get("open_ports"):
        for port in hints["open_ports"]:
            surface["open_ports"].append(port)
            if port in [80, 443, 8080, 8443]:
                surface["has_web"] = True
                proto = "https" if port in [443, 8443] else "http"
                surface["web_urls"].append(f"{proto}://{target}")
            if port in [139, 445]:
                surface["has_smb"] = True
            if port == 22:
                surface["has_ssh"] = True

    plan = _chain_builder.build(
        target=target, target_type=target_type,
        surface=surface, mode=mode, session=session, objective=objective,
        memory_context=await generate_memory_hint(mode, target),
    )

    engine = AdaptiveExecutionEngine(
        plugins=PLUGINS,
        save_finding_fn=save_finding,
        process_manager=process_manager,
    )

    results = await engine.execute_plan(plan, max_steps=max_steps)

    # Mergen 2.0 — Memory Persistence (Vortex-hardened)
    try:
        ran = [r for r in results.get("results", []) if not r.get("skipped")]
        tools_ran: List[str]  = [r["tool"] for r in ran]
        f_count:   int        = sum(r.get("findings_count", 0) for r in ran)
        r_max:     float      = max((r.get("risk_score", 0.0) for r in ran), default=0.0)
        
        # Dispatch to background thread to avoid blocking the event loop
        await save_operation(
            mode=mode,
            target=target,
            session=session,
            tools_used=tools_ran,
            findings_count=f_count,
            risk_max=r_max,
            summary=results.get("attack_narrative", "")[:2000],
            errors=[],
        )
    except Exception as exc:
        sys.stderr.write(f"[Memory] save_operation failed: {exc}\n")

    results["report_url"] = f"/api/sessions/{session}/report"
    return results


@mcp.tool()
async def adaptive_attack(
    target: str,
    mode: str = "default",
    session: str = "default",
    objective: str = "full_compromise",
    context: Optional[Union[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Fully autonomous attack mode. Combines planning and execution in a loop.
    Use this for 'fire-and-forget' scanning.
    """
    return await execute_plan(
        target=target,
        mode=mode,
        session=session,
        objective=objective,
        context=context,
        max_steps=20,
    )




@app.post("/api/workflows/elite_hunt")
async def elite_hunt(req: EliteHuntRequest):
    """MERGEN 3.0 Elite Hunt — 6-layer autonomous attack pipeline."""
    job_id = process_manager.create_job(req.target, "elite_hunt", req.session)
    asyncio.create_task(_run_elite_hunt(job_id, req))
    return {"job_id": job_id, "status": "started"}


async def _run_elite_hunt(job_id: str, req: EliteHuntRequest):
    pm = process_manager
    pm.start_job(job_id)
    all_findings = []
    surface_map: Dict[str, Any] = {"target": req.target, "has_web": True}

    try:
        # Layer 0: Passive OSINT
        pm.broadcast(job_id, "[MERGEN-PROGRESS:5%] Layer 0: Passive OSINT...")
        for tool_name in ["crtsh", "gau", "waybackurls", "trufflehog"]:
            plugin = PLUGINS.get(tool_name)
            if plugin and plugin.is_available():
                result = await plugin.run(req.target, {"mode": req.mode})
                all_findings.extend(result.findings)
                await save_finding(req.session, result)

        # Layer 1: Attack Surface Mapping (runs FIRST to populate tech stack)
        pm.broadcast(job_id, "[MERGEN-PROGRESS:15%] Layer 1: Attack Surface Mapping...")
        surface_map = await _elite_surface_mapping(job_id, req, all_findings, surface_map, pm)

        # Layer 0.5: Web Intelligence (runs AFTER surface mapping — needs tech_list)
        pm.broadcast(job_id, "[MERGEN-PROGRESS:25%] Layer 0.5: Web Intelligence...")
        tech_list = _elite_extract_tech(surface_map)
        hints = await generate_priority_hints(tech_list, req.target)
        intel_bonuses = hints_to_playbook_bonus(hints)
        if hints:
            pm.broadcast(job_id, hints_summary(hints))

        # Defense Detection
        web_urls = surface_map.get("web_urls", [])
        if web_urls:
            pm.broadcast(job_id, "[MERGEN-PROGRESS:33%] Defense Detection Layer...")
            try:
                defense_profile = await detect_defenses(web_urls[0])
                surface_map.update(defense_to_surface_update(defense_profile))
                if defense_profile.waf_detected:
                    pm.broadcast(job_id, f"[DDL] WAF: {defense_profile.waf_vendor} → bypass: {defense_profile.bypass_strategies[:2]}")
            except Exception as e:
                pm.broadcast(job_id, f"[DDL] Detection skipped: {e}")

        # Layer 2: AI Playbook Selection
        pm.broadcast(job_id, "[MERGEN-PROGRESS:38%] Layer 2: AI Playbook Selection...")
        memory_bonuses = await _elite_memory_bonuses(req.mode)
        immediate, conditional, _ = select_playbooks(surface_map, req.mode, intel_bonuses, memory_bonuses)
        pm.broadcast(job_id, f"[Objective: {req.objective}] " + selection_summary(immediate, conditional))

        # Layer 3: Adaptive Execution
        pm.broadcast(job_id, "[MERGEN-PROGRESS:40%] Layer 3: Adaptive Execution...")
        exec_findings = await _elite_run_playbooks(job_id, req, immediate + conditional, pm)
        all_findings.extend(exec_findings)

        # Build coverage matrix from all findings
        coverage = build_matrix_from_findings(req.target, all_findings)
        pm.broadcast(job_id, f"\n{coverage.summary()}")

        # Layer 4: Correlation + Report
        pm.broadcast(job_id, "[MERGEN-PROGRESS:90%] Layer 4: Correlation + Report...")
        chains, deduped = correlate(all_findings, req.assets)

        report_cfg = ReportConfig(
            mode=req.mode,
            verbose=req.report_verbose,
            narrative=req.report_verbose,
            regulatory=req.report_verbose,
            format=req.report_format,
        )
        if req.report_format == "json":
            report = to_json(deduped, chains)
        elif req.report_format == "csv":
            report = to_csv(deduped)
        else:
            report = generate_report(deduped, chains, req.target, report_cfg, surface_map)

        pm.broadcast(job_id, "[MERGEN-PROGRESS:100%] Elite Hunt complete!")
        pm.broadcast(job_id, f"\n{report}")
        pm.finish_job(job_id, success=True, findings=deduped)

    except Exception as e:
        import traceback
        pm.broadcast(job_id, f"[ERROR] Elite Hunt: {e}\n{traceback.format_exc()}")
        pm.finish_job(job_id, success=False, findings=[])


def _elite_extract_tech(surface_map: Dict[str, Any]) -> List[str]:
    tech = []
    for key in ["cms", "web_server", "tech"]:
        val = surface_map.get(key)
        if val:
            if isinstance(val, list):
                tech.extend(val)
            else:
                tech.append(str(val))
    return [t for t in tech if t][:8]


async def _elite_surface_mapping(job_id: str, req, all_findings: List, surface_map: Dict, pm) -> Dict:
    for tool_name in ["subfinder", "httpx", "nmap", "whatweb", "wafw00f"]:
        plugin = PLUGINS.get(tool_name)
        if plugin and plugin.is_available():
            try:
                result = await plugin.run(req.target, {"mode": req.mode})
                all_findings.extend(result.findings)
                await save_finding(req.session, result)
                if tool_name == "whatweb":
                    for f in result.findings:
                        tech = f.get("technology", "")
                        if tech:
                            surface_map.setdefault("tech", [])
                            if isinstance(surface_map["tech"], list):
                                surface_map["tech"].append(tech)
                elif tool_name == "wafw00f":
                    for f in result.findings:
                        if f.get("waf"):
                            surface_map["waf"] = f["waf"]
                            surface_map["waf_detected"] = True
            except Exception as e:
                pm.broadcast(job_id, f"[Layer1] {tool_name} error: {e}")
    return surface_map


async def _elite_memory_bonuses(mode: str) -> Dict[str, int]:
    try:
        ops = await get_past_operations(mode, limit=10)
    except Exception:
        return {}
    bonuses: Dict[str, int] = {}
    kw_map = {
        "ssrf": "ssrf_full_chain", "jwt": "jwt_attack_chain",
        "graphql": "graphql_full_chain", "sqli": "rest_api_owasp",
        "xss": "xss_ato", "s3": "aws_full_chain",
    }
    for op in ops:
        summary = str(op.get("summary", "")).lower()
        for kw, pid in kw_map.items():
            if kw in summary:
                bonuses[pid] = bonuses.get(pid, 0) + 5
    return bonuses


async def _elite_run_playbooks(job_id: str, req, playbooks_to_run: List, pm) -> List[Dict]:
    findings: List[Dict] = []
    total = len(playbooks_to_run)
    for i, pb in enumerate(playbooks_to_run):
        pct = 40 + int((i / max(total, 1)) * 45)
        pm.broadcast(job_id, f"[MERGEN-PROGRESS:{pct}%] Playbook: {pb.name}...")
        for tool_name in pb.tools:
            plugin = PLUGINS.get(tool_name)
            if plugin and plugin.is_available():
                try:
                    result = await plugin.run(req.target, {"mode": req.mode})
                    findings.extend(result.findings)
                    await save_finding(req.session, result)
                except Exception as e:
                    pm.broadcast(job_id, f"[Layer3] {tool_name} error: {e}")
    return findings


_context_builder = StructuredContextBuilder()


@app.post("/api/plan/context")
async def api_plan_context(data: Dict[str, Any]):
    target    = data.get("target", "")
    logic_map = data.get("logic_map", {})
    mode      = data.get("mode", "default")
    session   = data.get("session", "default")
    objective = data.get("objective", "find_vulnerabilities")

    profile = get_profile(mode)

    attack_surface = {
        "open_ports": [],
        "services": {},
        "web_urls": [],
        "subdomains": [],
        "has_web": False,
        "has_ssh": False,
        "has_smb": False,
        "has_ftp": False,
        "has_db": False,
        "cms": None,
        "waf": None,
        "os_guess": None,
        "tech_stack": [],
    }

    already_run = []

    try:
        async with aiosqlite.connect(str(DB_PATH)) as db:
            async with db.execute(
                "SELECT tool, findings_json FROM findings WHERE session = ? ORDER BY created_at ASC",
                (session,)
            ) as cur:
                rows = await cur.fetchall()
        for tool, fj in rows:
            already_run.append(tool)
            try:
                findings = json.loads(fj) if fj else []
            except Exception:
                findings = []

            if tool == "nmap":
                for f in findings:
                    port = f.get("port", 0)
                    service = f.get("service", "")
                    product = f.get("product", "")
                    version = f.get("version", "")
                    ip = f.get("ip", target)
                    if port:
                        if port not in attack_surface["open_ports"]:
                            attack_surface["open_ports"].append(port)
                        svc_label = f"{product} {version}".strip() or service
                        attack_surface["services"][str(port)] = svc_label
                    if port in [80, 8080, 443, 8443, 8000, 8888] or service in ["http", "https", "http-alt"]:
                        attack_surface["has_web"] = True
                        scheme = "https" if (port == 443 or service == "https") else "http"
                        url = f"{scheme}://{ip}" if port in [80, 443] else f"{scheme}://{ip}:{port}"
                        if url not in attack_surface["web_urls"]:
                            attack_surface["web_urls"].append(url)
                    if port == 22 or service == "ssh":
                        attack_surface["has_ssh"] = True
                    if port in [139, 445] or service in ["smb", "microsoft-ds", "netbios-ssn"]:
                        attack_surface["has_smb"] = True
                    if port == 21 or service == "ftp":
                        attack_surface["has_ftp"] = True
                    if port in [3306, 5432, 1433, 1521, 27017] or service in ["mysql", "postgresql", "ms-sql", "oracle", "mongodb"]:
                        attack_surface["has_db"] = True

            elif tool == "httpx":
                for f in findings:
                    url = f.get("url", "")
                    if url and url not in attack_surface["web_urls"]:
                        attack_surface["web_urls"].append(url)
                        attack_surface["has_web"] = True
                    tech = f.get("tech", [])
                    if isinstance(tech, list):
                        for t in tech:
                            if t and t not in attack_surface["tech_stack"]:
                                attack_surface["tech_stack"].append(t)
                            tl = t.lower() if t else ""
                            if "wordpress" in tl and not attack_surface["cms"]:
                                attack_surface["cms"] = "WordPress"
                            elif "drupal" in tl and not attack_surface["cms"]:
                                attack_surface["cms"] = "Drupal"
                            elif "joomla" in tl and not attack_surface["cms"]:
                                attack_surface["cms"] = "Joomla"
                    webserver = f.get("webserver", "")
                    if webserver and not attack_surface["os_guess"]:
                        wl = webserver.lower()
                        if "ubuntu" in wl or "debian" in wl:
                            attack_surface["os_guess"] = "Linux"
                        elif "win" in wl or "iis" in wl:
                            attack_surface["os_guess"] = "Windows"

            elif tool == "whatweb":
                for f in findings:
                    tech = f.get("technology", "")
                    version = f.get("version", "")
                    if tech and tech not in attack_surface["tech_stack"]:
                        attack_surface["tech_stack"].append(f"{tech} {version}".strip() if version else tech)
                    if tech:
                        tl = tech.lower()
                        if "wordpress" in tl:
                            attack_surface["cms"] = f"WordPress {version}".strip()
                        elif "drupal" in tl:
                            attack_surface["cms"] = f"Drupal {version}".strip()

            elif tool == "subfinder":
                for f in findings:
                    sd = f.get("subdomain", "")
                    if sd and sd not in attack_surface["subdomains"]:
                        attack_surface["subdomains"].append(sd)

            elif tool == "wafw00f":
                for f in findings:
                    waf = f.get("waf", "") or f.get("firewall", "")
                    if waf and waf.lower() not in ["none", "no waf", ""]:
                        attack_surface["waf"] = waf

    except Exception as e:
        logger.warning(f"get_attack_context DB read error: {e}")

    for t in logic_map.get("technologies", []):
        if t not in attack_surface["tech_stack"]:
            attack_surface["tech_stack"].append(t)

    suggested_next = []
    already_run_set = set(already_run)
    priority_tools  = profile["priority_tools"]

    def _suggest(tool, target_val, reason, priority=2):
        if tool not in already_run_set:
            suggested_next.append({"tool": tool, "target": target_val, "reason": reason, "priority": priority})

    if "nmap" not in already_run_set and "rustscan" not in already_run_set:
        init_tool = "rustscan" if mode == "ctf" else "nmap"
        _suggest(init_tool, target, "Initial port scan — discover open services", 1)

    if attack_surface["has_web"]:
        web_target = attack_surface["web_urls"][0] if attack_surface["web_urls"] else f"http://{target}"
        _suggest("httpx",    target,     "Probe web services — get status, title, tech stack", 1)
        _suggest("whatweb",  web_target, "Fingerprint web technologies and CMS", 2)
        _suggest("gobuster", web_target, "Directory enumeration — find hidden paths", 2)
        _suggest("nuclei",   web_target, "Vulnerability scanning — check CVEs and misconfigs", 1)
        _suggest("nikto",    web_target, "Web server misconfiguration checks", 3)
        if attack_surface["cms"] and "wordpress" in attack_surface["cms"].lower():
            _suggest("wpscan", web_target, "WordPress: enumerate users, plugins, themes", 1)
        if mode == "bb":
            _suggest("subfinder",   target,     "Subdomain enumeration for bug bounty scope", 1)
            _suggest("katana",      web_target, "Deep crawl for parameter and endpoint discovery", 2)
            _suggest("arjun",       web_target, "HTTP parameter discovery", 2)
            _suggest("gau",         target,     "Fetch known URLs from Wayback Machine", 3)
            _suggest("trufflehog",  web_target, "Scan for secrets and exposed credentials", 3)

    if attack_surface["has_smb"]:
        _suggest("enum4linux", target, "SMB enumeration — users, shares, policies", 1)
        _suggest("smbmap",     target, "List accessible SMB shares", 2)

    if attack_surface["has_ssh"]:
        ssh_version = attack_surface["services"].get("22", "OpenSSH")
        _suggest("searchsploit", ssh_version, f"Check exploit DB for {ssh_version}", 2)
        if mode in ["ctf", "pentest"]:
            _suggest("hydra", target, "Brute-force SSH with common credentials", 3)

    if attack_surface["has_ftp"]:
        _suggest("hydra", f"ftp://{target}", "Brute-force FTP with common credentials", 2)

    if attack_surface["has_db"] and attack_surface["web_urls"]:
        _suggest("sqlmap", attack_surface["web_urls"][0], "Test for SQL injection via web interface", 2)

    for tech in attack_surface["tech_stack"][:3]:
        _suggest("searchsploit", tech, f"Check exploit DB for {tech} vulnerabilities", 3)

    suggested_next.sort(key=lambda x: x["priority"])

    def _mode_sort(s):
        try:
            return priority_tools.index(s["tool"])
        except ValueError:
            return 999

    top_suggestions = sorted(suggested_next[:10], key=_mode_sort)

    parts = []
    if attack_surface["open_ports"]:
        parts.append(f"Open ports: {', '.join(str(p) for p in sorted(attack_surface['open_ports']))}")
    if attack_surface["services"]:
        parts.append("Services: " + ", ".join(f"{p}/{v}" for p, v in list(attack_surface["services"].items())[:5]))
    if attack_surface["web_urls"]:
        parts.append(f"Web: {', '.join(attack_surface['web_urls'][:3])}")
    if attack_surface["cms"]:
        parts.append(f"CMS: {attack_surface['cms']}")
    if attack_surface["tech_stack"]:
        parts.append(f"Tech: {', '.join(attack_surface['tech_stack'][:4])}")
    if attack_surface["subdomains"]:
        parts.append(f"Subdomains: {len(attack_surface['subdomains'])} found")
    findings_summary = ". ".join(parts) if parts else "No findings yet — run initial reconnaissance."

    tech_str = ", ".join(attack_surface["tech_stack"][:5])
    playbook = await get_playbook(tech_str) if tech_str else {}
    memory_hints = []
    for tech in attack_surface["tech_stack"][:5]:
        pb = playbook.get(tech, {})
        if pb.get("known_vulns") or pb.get("best_tools"):
            memory_hints.append({
                "tech":       tech,
                "known_vulns": pb.get("known_vulns", [])[:3],
                "best_tools":  pb.get("best_tools", [])[:3],
            })

    return {
        "target":          target,
        "session":         session,
        "mode":            mode,
        "mode_label":      profile["label"],
        "objective":       objective,
        "attack_surface":  attack_surface,
        "already_run":     list(dict.fromkeys(already_run)),
        "findings_summary": findings_summary,
        "suggested_next":  top_suggestions,
        "memory_hints":    memory_hints,
        "mode_guidance":   profile["guidance"],
        "instructions": (
            f"You are a senior penetration tester operating in {profile['label']} mode.\n"
            f"Strategy: {profile['strategy']}.\n"
            "Based on this context:\n"
            "1. Review attack_surface and already_run tools\n"
            "2. Pick from suggested_next — highest priority first\n"
            "3. After each tool: call get_attack_context again to get updated suggestions\n"
            "4. Use write_and_exec for custom exploit scripts\n"
            "5. Call save_learning() after each confirmed vulnerability\n"
            f"6. Avoid in this mode: {profile['avoid']}"
        ),
    }


@app.post("/api/mode/set")
async def api_set_mode(data: Dict[str, Any]):
    mode    = data.get("mode", "default")
    target  = data.get("target", "")
    session = data.get("session", "default")

    profile = get_profile(mode)

    return {
        "mode":           mode,
        "label":          profile["label"],
        "color":          profile["color"],
        "target":         target,
        "session":        session,
        "strategy":       profile["strategy"],
        "description":    profile["description"],
        "priority_tools": profile["priority_tools"],
        "avoid":          profile["avoid"],
        "nuclei_severity": profile["nuclei_severity"],
        "nmap_flags":     profile["nmap_flags"],
        "guidance":       profile["guidance"],
        "mission": (
            f"MISSION BRIEFING — {profile['label'].upper()} MODE\n"
            f"Target: {target}\n"
            f"Strategy: {profile['strategy']}\n"
            f"{profile['guidance']}\n\n"
            "Next steps:\n"
            "1. Call get_attack_context to see what is already known about this target\n"
            "2. Proceed with suggested_next tools in priority order\n"
            "3. After each tool completes, call get_attack_context again for updated suggestions"
        ),
    }


def _get_kali_ip() -> str:
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        pass
    raw = os.popen("hostname -I 2>/dev/null").read().strip()
    return raw.split()[0] if raw else "127.0.0.1"


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Mergen Server v2")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--mcp", action="store_true", help="Run in legacy MCP stdio mode")
    args = parser.parse_args()

    kali_ip = _get_kali_ip()

    if args.mcp:
        init_db()
        PLUGINS = discover_plugins()
        sys.stderr.write(f"[Mergen] MCP mode active. {len(PLUGINS)} plugins loaded.\n")
        
        mcp.run()
    else:
        print(f"""
\033[32m
         Mergen  v2.0                    

  Kali IP:     {kali_ip:<46} 
                                                              
   Dashboard:  http://{kali_ip}:{args.port}/dashboard          
   API Docs:    http://{kali_ip}:{args.port}/docs               
                                                              
   MCP Config:  http://{kali_ip}:{args.port}

\033[0m
        """)
        uvicorn.run(app, host=args.host, port=args.port, log_level="warning")

