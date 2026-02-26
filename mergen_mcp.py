#!/usr/bin/env python3
"""
Mergen MCP Client Adapter
Connects the local MCP server interface to the remote (or local) Mergen FastAPI server.
Avoids blocking the asyncio event loop with MCP stdio streams, allowing live data to flow perfectly.
"""

import sys
import os
import time
import requests
import json
from urllib.parse import quote
from typing import Dict, Any, Optional, Union
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("mergen-client")

import argparse
parser = argparse.ArgumentParser(description="Mergen MCP Client")
parser.add_argument("--server", default=os.environ.get("MERGEN_SERVER_URL", "http://127.0.0.1:8000"), help="URL of the Mergen Server")
args, unknown = parser.parse_known_args()
SERVER_URL = args.server.rstrip("/")
TIMEOUT = 300  # 5 minutes for long-running endpoints

def _post(endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
    url = f"{SERVER_URL}/{endpoint}"
    try:
        response = requests.post(url, json=data, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {str(e)}", "success": False}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}", "success": False}

def _get(endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    url = f"{SERVER_URL}/{endpoint}"
    try:
        response = requests.get(url, params=params or {}, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {str(e)}", "success": False}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}", "success": False}

def _delete(endpoint: str) -> Dict[str, Any]:
    url = f"{SERVER_URL}/{endpoint}"
    try:
        response = requests.delete(url, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {str(e)}", "success": False}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}", "success": False}


# -------------------------------------------------------------
# Base Tools
# -------------------------------------------------------------

@mcp.tool()
def list_tools() -> Dict[str, Any]:
    """List all available plugins, their descriptions, and installation status."""
    return _get("api/plugins")

@mcp.tool()
def run_tool(
    tool_name: str,
    target: str,
    options: Optional[Union[str, Dict[str, Any]]] = None,
    mode: str = "default",
    session: str = "default",
) -> Dict[str, Any]:
    """
    Run a single tool directly (e.g. 'nmap', 'whois', 'sqlmap').
    Returns a job_id immediately — tool runs in background to avoid MCP timeouts.
    Use get_job_output(job_id) to poll until status='done'.
    Options: JSON string '{"level":5}' or dict {"level": 5}.
    """
    opts: Dict[str, Any] = {}
    if options:
        if isinstance(options, dict):
            opts = options
        else:
            try:
                opts = json.loads(options)
            except json.JSONDecodeError:
                opts = {"extra_args": options.split()}

    payload = {
        "tool": tool_name,
        "target": target,
        "options": opts,
        "mode": mode,
        "session": session,
    }
    return _post("api/tools/execute_async", payload)

@mcp.tool()
def run_command(command: str, timeout: int = 120) -> Dict[str, Any]:
    """
    Execute a raw shell command on the server.
    Returns the output and status code. Use with caution.
    """
    return _post("api/command", {"command": command, "timeout": timeout})

@mcp.tool()
def get_job_output(job_id: str) -> Dict[str, Any]:
    """Get the live status and output of a specific job ID."""
    return _get(f"api/jobs/{job_id}")

@mcp.tool()
def kill_job_mcp(job_id: str) -> Dict[str, Any]:
    """Kill a currently running background job by ID."""
    return _delete(f"api/jobs/{job_id}")

@mcp.tool()
def get_session_report(session: str = "default") -> Dict[str, Any]:
    """Get a summary of findings, risk scores, and tool outputs for a session."""
    return _get(f"api/sessions/{session}")


# -------------------------------------------------------------
# Workflows
# -------------------------------------------------------------

@mcp.tool()
def smart_recon(target: str, mode: str = "default", session: str = "default") -> Dict[str, Any]:
    """Run an intelligent reconnaissance workflow (ports, services, HTTP)."""
    return _post("api/workflows/execute", {
        "tool": "smart_recon", "target": target, "mode": mode, "session": session
    })

@mcp.tool()
def vuln_analysis(target: str, mode: str = "default", session: str = "default") -> Dict[str, Any]:
    """Run vulnerability analysis using Nuclei, Nikto, and SearchSploit. Best run AFTER recon."""
    return _post("api/workflows/execute", {
        "tool": "vuln_analysis", "target": target, "mode": mode, "session": session
    })

@mcp.tool()
def exploit_assist(target: str, service: str, version: str = "", session: str = "default") -> Dict[str, Any]:
    """Find exploits for a specific service version using SearchSploit. Returns ready-to-run commands."""
    return _post("api/workflows/execute", {
        "tool": "exploit_assist", "target": target, "mode": "default", "session": session,
        "options": {"service": service, "version": version}
    })

@mcp.tool()
def plan_attack(
    target: str, mode: str = "default", session: str = "default", 
    objective: str = "full_compromise", target_type_hint: str = "", context: Optional[str] = None
) -> Dict[str, Any]:
    """Generate a comprehensive attack plan for a given target without executing it."""
    return _post("api/workflows/execute", {
        "tool": "plan_attack", "target": target, "mode": mode, "session": session,
        "options": {"objective": objective, "target_type_hint": target_type_hint, "context": context}
    })

@mcp.tool()
def execute_plan(
    target: str, mode: str = "default", session: str = "default", 
    objective: str = "full_compromise", target_type_hint: str = "", context: Optional[str] = None, max_steps: int = 15
) -> Dict[str, Any]:
    """Execute a previously generated attack plan (or generate one on the fly)."""
    return _post("api/workflows/execute", {
        "tool": "execute_plan", "target": target, "mode": mode, "session": session,
        "options": {"objective": objective, "target_type_hint": target_type_hint, "context": context, "max_steps": max_steps}
    })

@mcp.tool()
def adaptive_attack(
    target: str, mode: str = "default", session: str = "default",
    objective: str = "full_compromise", context: Optional[str] = None
) -> Dict[str, Any]:
    """Fully autonomous attack mode. Combines planning and execution in a loop."""
    return _post("api/workflows/execute", {
        "tool": "adaptive_attack", "target": target, "mode": mode, "session": session,
        "options": {"objective": objective, "context": context}
    })

@mcp.tool()
def elite_hunt(
    target: str,
    mode: str = "bb",
    session: str = "default",
    report_verbose: bool = False,
    report_format: str = "markdown",
    assets: str = "",
) -> Dict[str, Any]:
    """
    MERGEN 3.0 Elite Hunt — 6-layer autonomous red team pipeline.
    41 kill chains, AI playbook selection, correlation engine, dual reporting.

    Args:
        target: Target domain/IP/URL
        mode: "bb" (bug bounty) | "pentest" | "ctf"
        report_verbose: True = narrative + regulatory mapping (more tokens)
        report_format: "markdown" | "json" | "csv"
        assets: Comma-separated asset types e.g. "payment,api_gateway"
    """
    assets_list = [a.strip() for a in assets.split(",") if a.strip()] if assets else []
    return _post("api/workflows/elite_hunt", {
        "target": target,
        "mode": mode,
        "session": session,
        "report_verbose": report_verbose,
        "report_format": report_format,
        "assets": assets_list,
    })


@mcp.tool()
def save_learning(
    vuln_type: str,
    success: bool = True,
    tech_stack: str = "",
    endpoint_pattern: str = "",
    payload: str = "",
    tool: str = "",
    notes: str = "",
    target: str = "",
) -> Dict[str, Any]:
    """Record what worked or didn't for future operations. Call after each confirmed finding."""
    return _post("api/memory/learn", {
        "vuln_type": vuln_type, "success": success, "tech_stack": tech_stack,
        "endpoint_pattern": endpoint_pattern, "payload": payload,
        "tool": tool, "notes": notes, "target": target,
    })


@mcp.tool()
def get_memory(tech_stack: str) -> Dict[str, Any]:
    """Get known vulns, bypasses, and best tools for a detected tech stack. Call before hypothesis generation.
    tech_stack can be a comma-separated string like 'Laravel,PHP' — multi-stack lookups are supported."""
    return _get(f"api/memory/playbook/{quote(tech_stack, safe='')}")


@mcp.tool()
def write_and_exec(
    command: str,
    filename: str = "",
    content: str = "",
    timeout: int = 60,
    workdir: str = "/tmp/mergen_exploits",
) -> Dict[str, Any]:
    """
    Write exploit script to Kali disk and execute a command.
    Use for custom exploitation: write Python/bash exploit then run it.

    Examples:
      - Write Python PoC: filename="idor.py", content="import requests...", command="python3 idor.py"
      - Just run command: command="sqlmap -u 'http://t.com/?id=1' --dbs --batch"
      - Shell one-liner: command="curl -sv 'http://target/admin'"
    """
    return _post("api/write_and_exec", {
        "command": command,
        "filename": filename,
        "content": content,
        "timeout": timeout,
        "workdir": workdir,
    })


@mcp.tool()
def get_attack_context(
    target: str,
    logic_map: Optional[Dict[str, Any]] = None,
    mode: str = "default",
    objective: str = "find_vulnerabilities",
) -> Dict[str, Any]:
    """
    Get structured attack context combining Logic Map + Memory for LLM hypothesis generation.
    Call after app_map, before planning your attack. Returns token-efficient JSON with
    high-value targets, memory hints, and instructions for generating hypotheses.
    """
    return _post("api/plan/context", {
        "target":     target,
        "logic_map":  logic_map or {},
        "mode":       mode,
        "objective":  objective,
    })


@mcp.tool()
def set_attack_mode(
    mode: str,
    target: str,
    session: str = "default",
) -> dict:
    """Set attack mode (ctf/pentest/bb/default) for a session. Returns mission briefing with strategy, tools, and step-by-step guidance. Call at session start."""
    return _post("api/mode/set", {
        "mode":    mode,
        "target":  target,
        "session": session,
    })


if __name__ == "__main__":
    import logging
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(asctime)s [%(levelname)s] mergen_mcp: %(message)s")
    logger = logging.getLogger("mergen_mcp")
    
    # Check if the server is accessible before fully committing to the standard run
    logger.info("Starting Mergen MCP Adapter...")
    try:
        r = requests.get(f"{SERVER_URL}/api/plugins", timeout=3)
        logger.info(f"Connected to Mergen Master Node at {SERVER_URL}")
    except Exception as e:
        logger.warning(f"Mergen Master Node at {SERVER_URL} is currently unreachable. Start it with `python server.py`.")

    # Start FastMCP on stdio
    mcp.run()
