import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class TargetType(str, Enum):
    WEB_APP      = "web_app"       # HTTP/HTTPS service
    NETWORK_HOST = "network_host"  # IP with unknown services
    DOMAIN       = "domain"        # Domain name (needs DNS recon first)
    CTF_BOX      = "ctf_box"       # CTF machine (HackTheBox, TryHackMe style)
    WINDOWS_HOST = "windows_host"  # Windows (SMB, RDP, WinRM)
    LINUX_HOST   = "linux_host"    # Linux (SSH, web, databases)
    API_ENDPOINT = "api_endpoint"  # REST/GraphQL API
    UNKNOWN      = "unknown"

class AttackPhase(str, Enum):
    RECON        = "recon"
    ENUMERATION  = "enumeration"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"

@dataclass
class AttackStep:
    phase: AttackPhase
    tool: str
    target: str
    options: Dict[str, Any]
    reason: str                    # WHY this step was chosen
    priority: int = 5              # 1=critical, 10=optional
    depends_on: List[str] = field(default_factory=list)  # tool names that must run first
    condition: Optional[str] = None  # e.g. "port_445_open"

@dataclass
class AttackPlan:
    target: str
    target_type: TargetType
    mode: str
    session: str
    steps: List[AttackStep]
    surface_map: Dict[str, Any]    # what we know about the target
    kill_chain: List[str]          # ordered tool names
    objective: str                 # what we're trying to achieve
    estimated_time: int            # seconds
    memory_context: str = ""       # HINT from past operations

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type.value,
            "mode": self.mode,
            "session": self.session,
            "memory_context": self.memory_context,
            "objective": self.objective,
            "kill_chain": self.kill_chain,
            "estimated_time_seconds": self.estimated_time,
            "surface_map": self.surface_map,
            "steps": [
                {
                    "phase": s.phase.value,
                    "tool": s.tool,
                    "target": s.target,
                    "options": s.options,
                    "reason": s.reason,
                    "priority": s.priority,
                }
                for s in sorted(self.steps, key=lambda x: x.priority)
            ],
        }



class TargetProfiler:

    def classify(self, target: str, initial_hints: Dict[str, Any] = None) -> TargetType:
        hints = initial_hints or {}

        if hints.get("type"):
            return TargetType(hints["type"])

        if target.startswith(("http://", "https://")):
            return TargetType.WEB_APP

        if re.match(r"^[a-zA-Z][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$", target) and not self._is_ip(target):
            return TargetType.DOMAIN

        if self._is_ip(target):
            return TargetType.NETWORK_HOST

        return TargetType.UNKNOWN

    def _is_ip(self, s: str) -> bool:
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s))

    def build_surface_map(self, target: str, target_type: TargetType, nmap_findings: List[Dict]) -> Dict[str, Any]:
        surface = {
            "target": target,
            "type": target_type.value,
            "open_ports": [],
            "services": {},
            "os_guess": "unknown",
            "has_web": False,
            "has_smb": False,
            "has_ssh": False,
            "has_rdp": False,
            "has_ftp": False,
            "has_db": False,
            "web_urls": [],
            "cms": None,
            "waf": None,
        }

        for f in nmap_findings:
            port = f.get("port", 0)
            service = f.get("service", "").lower()
            product = f.get("product", "").lower()
            version = f.get("version", "")

            surface["open_ports"].append(port)
            surface["services"][port] = {
                "service": service,
                "product": product,
                "version": version,
            }

            if port in [80, 443, 8080, 8443, 8000, 8888] or service in ["http", "https"]:
                surface["has_web"] = True
                proto = "https" if port in [443, 8443] else "http"
                surface["web_urls"].append(f"{proto}://{target}:{port}" if port not in [80, 443] else f"{proto}://{target}")

            if port in [139, 445] or service == "smb":
                surface["has_smb"] = True

            if port == 22 or service == "ssh":
                surface["has_ssh"] = True

            if port == 3389 or service in ["ms-wbt-server", "rdp"]:
                surface["has_rdp"] = True

            if port == 21 or service == "ftp":
                surface["has_ftp"] = True

            if port in [3306, 5432, 1433, 27017, 6379] or service in ["mysql", "postgresql", "mssql", "mongodb", "redis"]:
                surface["has_db"] = True
                surface["services"][port]["category"] = "database"

            if "windows" in product or port in [135, 139, 445, 3389]:
                surface["os_guess"] = "windows"
            elif "linux" in product or "ubuntu" in product or "debian" in product:
                surface["os_guess"] = "linux"

        return surface



class KillChainBuilder:

    def build(
        self,
        target: str,
        target_type: TargetType,
        surface: Dict[str, Any],
        mode: str,
        session: str,
        objective: str,
        memory_context: str = "",
    ) -> AttackPlan:
        steps = []
        kill_chain = []


        if target_type == TargetType.DOMAIN:
            steps += self._domain_recon(target, mode)
        elif target_type in [TargetType.NETWORK_HOST, TargetType.CTF_BOX, TargetType.WINDOWS_HOST, TargetType.LINUX_HOST]:
            steps += self._host_recon(target, mode, surface)
        elif target_type == TargetType.WEB_APP:
            steps += self._host_recon(target, mode, surface)
            steps += self._web_recon(target, mode, surface)


        if surface.get("has_web"):
            for url in surface.get("web_urls", [target]):
                steps += self._web_enum(url, mode, surface)

        if surface.get("has_smb"):
            steps += self._smb_enum(target, mode)

        if surface.get("has_ssh"):
            steps += self._ssh_enum(target, mode)

        if surface.get("has_ftp"):
            steps += self._ftp_enum(target, mode)

        if surface.get("has_db"):
            steps += self._db_enum(target, mode, surface)


        if surface.get("has_web"):
            for url in surface.get("web_urls", [target]):
                steps += self._web_exploit(url, mode, surface)

        if surface.get("has_smb") and surface.get("os_guess") == "windows":
            steps += self._windows_exploit(target, mode)

        if surface.get("has_ssh"):
            steps += self._ssh_exploit(target, mode)

        steps.sort(key=lambda s: s.priority)
        kill_chain = list(dict.fromkeys(s.tool for s in steps))  # ordered unique tools

        time_map = {
            "rustscan": 30, "nmap": 120, "masscan": 60,
            "gobuster": 180, "ffuf": 300, "feroxbuster": 300, "dirsearch": 180,
            "nuclei": 300, "nikto": 180, "dalfox": 120, "sqlmap": 300,
            "enum4linux": 60, "smbmap": 30, "netexec": 60,
            "hydra": 300, "wpscan": 120, "whatweb": 30,
            "subfinder": 60, "amass": 180, "httpx": 30,
        }
        estimated = sum(time_map.get(s.tool, 60) for s in steps)

        return AttackPlan(
            target=target,
            target_type=target_type,
            mode=mode,
            session=session,
            memory_context=memory_context,
            steps=steps,
            surface_map=surface,
            kill_chain=kill_chain,
            objective=objective,
            estimated_time=estimated,
        )


    def _domain_recon(self, target: str, mode: str) -> List[AttackStep]:
        return [
            AttackStep(AttackPhase.RECON, "subfinder", target, {"mode": mode},
                       "Domain target: passive subdomain discovery first to map attack surface", 1),
            AttackStep(AttackPhase.RECON, "amass", target, {"mode": mode},
                       "Active subdomain enumeration to find hidden assets", 2),
            AttackStep(AttackPhase.RECON, "dnsenum", target, {"mode": mode},
                       "DNS enumeration: zone transfer attempt, MX records, NS records", 2),
            AttackStep(AttackPhase.RECON, "fierce", target, {"mode": mode},
                       "Locate non-contiguous IP space owned by the domain", 3),
            AttackStep(AttackPhase.RECON, "httpx", target, {"mode": mode},
                       "Probe discovered subdomains for live HTTP services", 4),
        ]

    def _host_recon(self, target: str, mode: str, surface: Dict) -> List[AttackStep]:
        steps = []
        if not surface.get("open_ports"):
            steps.append(AttackStep(
                AttackPhase.RECON, "rustscan", target, {"mode": mode},
                "Fast initial port discovery before detailed service scan", 1,
            ))
            steps.append(AttackStep(
                AttackPhase.RECON, "nmap", target, {"mode": mode},
                "Detailed service/version detection on discovered ports", 2,
                depends_on=["rustscan"],
            ))
        return steps

    def _web_recon(self, target: str, mode: str, surface: Dict) -> List[AttackStep]:
        return [
            AttackStep(AttackPhase.RECON, "whatweb", target, {"mode": mode},
                       "Fingerprint web technology stack before choosing attack vectors", 1),
            AttackStep(AttackPhase.RECON, "wafw00f", target, {"mode": mode},
                       "Detect WAF presence — determines stealth requirements for subsequent tools", 2),
        ]


    def _web_enum(self, url: str, mode: str, surface: Dict) -> List[AttackStep]:
        steps = []
        cms = surface.get("cms")

        if mode == "ctf":
            steps.append(AttackStep(
                AttackPhase.ENUMERATION, "feroxbuster", url, {"mode": mode, "depth": 4},
                "CTF mode: recursive directory discovery with auto-recursion for deep paths", 3,
            ))
        else:
            steps.append(AttackStep(
                AttackPhase.ENUMERATION, "gobuster", url, {"mode": mode},
                "Directory brute-force with mode-appropriate wordlist and thread count", 3,
            ))

        steps.append(AttackStep(
            AttackPhase.ENUMERATION, "gau", url, {"mode": mode},
            "Passive URL discovery from Wayback Machine — finds forgotten endpoints without touching target", 3,
        ))
        steps.append(AttackStep(
            AttackPhase.ENUMERATION, "katana", url, {"mode": mode},
            "JS-aware crawling to discover dynamically loaded endpoints and forms", 4,
        ))

        steps.append(AttackStep(
            AttackPhase.ENUMERATION, "arjun", url, {"mode": mode},
            "Discover hidden GET/POST parameters — prerequisite for SQLi and XSS testing", 5,
            depends_on=["katana"],
        ))

        if cms == "WordPress":
            steps.append(AttackStep(
                AttackPhase.ENUMERATION, "wpscan", url, {"mode": mode},
                "WordPress detected: enumerate plugins, themes, and users for known CVEs", 2,
            ))

        return steps

    def _smb_enum(self, target: str, mode: str) -> List[AttackStep]:
        return [
            AttackStep(AttackPhase.ENUMERATION, "enum4linux", target, {"mode": mode},
                       "SMB open: enumerate users, groups, shares, and password policies", 2),
            AttackStep(AttackPhase.ENUMERATION, "smbmap", target, {"mode": mode},
                       "Test SMB share access — READ access may reveal credentials or sensitive files", 3,
                       depends_on=["enum4linux"]),
        ]

    def _ssh_enum(self, target: str, mode: str) -> List[AttackStep]:
        return [
            AttackStep(AttackPhase.ENUMERATION, "nmap", target,
                       {"mode": mode, "extra_args": ["-p", "22", "--script", "ssh-auth-methods,ssh-hostkey"]},
                       "SSH open: check auth methods (password vs key) and grab host key for fingerprinting", 4),
        ]

    def _ftp_enum(self, target: str, mode: str) -> List[AttackStep]:
        return [
            AttackStep(AttackPhase.ENUMERATION, "nmap", target,
                       {"mode": mode, "extra_args": ["-p", "21", "--script", "ftp-anon,ftp-bounce,ftp-syst"]},
                       "FTP open: check for anonymous login and directory listing", 3),
        ]

    def _db_enum(self, target: str, mode: str, surface: Dict) -> List[AttackStep]:
        steps = []
        for port, svc in surface.get("services", {}).items():
            if svc.get("category") == "database":
                steps.append(AttackStep(
                    AttackPhase.ENUMERATION, "nmap", target,
                    {"mode": mode, "extra_args": ["-p", str(port), "--script", "mysql-info,mysql-databases,ms-sql-info"]},
                    f"Database port {port} open: enumerate version and accessible databases", 3,
                ))
        return steps


    def _web_exploit(self, url: str, mode: str, surface: Dict) -> List[AttackStep]:
        return [
            AttackStep(AttackPhase.EXPLOITATION, "nuclei", url, {"mode": mode},
                       "Template-based vulnerability scan: CVEs, misconfigs, exposed panels, default creds", 3,
                       depends_on=["whatweb"]),
            AttackStep(AttackPhase.EXPLOITATION, "nikto", url, {"mode": mode},
                       "Web server vulnerability scan: dangerous files, outdated software, headers", 4),
            AttackStep(AttackPhase.EXPLOITATION, "dalfox", url, {"mode": mode},
                       "XSS parameter testing on discovered endpoints", 5,
                       depends_on=["arjun"]),
            AttackStep(AttackPhase.EXPLOITATION, "sqlmap", url, {"mode": mode},
                       "SQL injection testing on discovered parameters", 5,
                       depends_on=["arjun"]),
        ]

    def _windows_exploit(self, target: str, mode: str) -> List[AttackStep]:
        return [
            AttackStep(AttackPhase.EXPLOITATION, "netexec", target, {"mode": mode, "protocol": "smb"},
                       "Windows SMB: test for null sessions, default credentials, and Pwn3d! access", 3),
            AttackStep(AttackPhase.EXPLOITATION, "searchsploit", target,
                       {"mode": mode},
                       "Search ExploitDB for Windows/SMB exploits matching discovered service versions", 4),
        ]

    def _ssh_exploit(self, target: str, mode: str) -> List[AttackStep]:
        return [
            AttackStep(AttackPhase.EXPLOITATION, "hydra", target,
                       {"mode": mode, "service": "ssh"},
                       "SSH brute-force with mode-appropriate wordlist (only if password auth confirmed)", 6),
        ]



class AdaptiveExecutionEngine:

    def __init__(self, plugins: Dict, save_finding_fn, process_manager):
        self.plugins = plugins
        self.save_finding = save_finding_fn
        self.pm = process_manager

    async def execute_plan(
        self,
        plan: AttackPlan,
        max_steps: int = 20,
        on_step_complete=None,
    ) -> Dict[str, Any]:
        results = []
        completed_tools = set()
        surface = plan.surface_map.copy()
        steps_run = 0
        
        is_ouroboros = (plan.objective.lower() == "endless")
        loop_limit = max_steps if not is_ouroboros else 999999

        # Convert list to a manageable tracking pool
        pending_steps = plan.steps.copy()
        running_steps = set()

        while pending_steps and steps_run < loop_limit:
            # Find all steps whose dependencies are met
            ready_batch = []
            for step in pending_steps:
                if step.depends_on and not all(d in completed_tools for d in step.depends_on):
                    continue
                # For ouroboros loops, avoid running same tool on same target multiple times
                if any(r.get("tool") == step.tool and r.get("target") == step.target and r.get("success") for r in results):
                    continue
                ready_batch.append(step)

            if not ready_batch:
                # If we have pending steps but none are ready, we have a circular or unfulfillable dependency
                # We can either skip them or wait. Since we run batch by batch, if ready_batch is empty, we are deadlocked.
                sys.stderr.write("[Ouroboros:Engine] Deadlock or missing dependencies detected. Clearing remaining queue.\n")
                if is_ouroboros:
                    pending_steps.clear()
                else:
                    break

            # Limit concurrency to 5 tools at once to avoid overloading system/network
            batch_to_run = ready_batch[:5]
            for s in batch_to_run:
                pending_steps.remove(s)
            
            sys.stderr.write(f"[Ouroboros:Engine] Orchestrating multi-agent batch execution of {len(batch_to_run)} tools...\n")

            async def _run_single_step(step: AttackStep):
                plugin = self.plugins.get(step.tool)
                if not plugin or not plugin.is_available():
                    return step, None, {"step": step.tool, "skipped": True, "reason": f"Tool '{step.tool}' not available"}
                
                res = await plugin.run(target=step.target, options=step.options)
                if res.findings:
                    await self.save_finding(plan.session, res)
                    
                s_res = {
                    "phase": step.phase.value,
                    "tool": step.tool,
                    "target": step.target,
                    "reason": step.reason,
                    "success": res.success,
                    "findings_count": len(res.findings),
                    "risk_score": res.risk_score,
                    "findings": res.findings[:10],
                    "suggested_next": res.suggested_next,
                }
                return step, res, s_res

            # Run the batch concurrently
            batch_results = await asyncio.gather(*[_run_single_step(s) for s in batch_to_run])

            # Process sequentially after gathering to adapt the plan safely
            for step, raw_res, step_res in batch_results:
                results.append(step_res)
                completed_tools.add(step.tool)
                steps_run += 1
                
                if on_step_complete:
                    await on_step_complete(step_res)

                sys.stderr.write(f"[Ouroboros:Engine] [{steps_run}/{loop_limit}] Executed {step.tool.upper()} against {step.target} | Success: {step_res.get('success', False)} | Findings: {step_res.get('findings_count', 0)}\n")

                if raw_res:
                    self._update_surface(surface, step.tool, raw_res.findings)
                    
                    # Prevent adapting endlessly if it's the exact same tool + target loop
                    plan.steps = pending_steps # To let is_planned work accurately
                    new_steps = self._adapt(step, raw_res, surface, plan)
                    if new_steps:
                        pending_steps.extend(new_steps)
                        sys.stderr.write(f"[Ouroboros:Adaptive] Injected {len(new_steps)} new execution pathways into the chain based on dynamic findings.\n")

            # Sort queue again by priority
            pending_steps.sort(key=lambda s: s.priority)
            
            # Ouroboros continuous injection fallback
            if is_ouroboros and not pending_steps:
                sys.stderr.write("[Ouroboros:Loop] Endless objective reached end of plan. Re-oxygenating the attack chain with deep recursive scans...\n")
                if surface.get("web_urls"):
                    for url in surface.get("web_urls", []):
                        pending_steps.append(AttackStep(
                            AttackPhase.ENUMERATION, "katana", url, {"mode": plan.mode, "depth": 5},
                            "OUROBOROS: Endless loop triggered deep Katana crawl to maintain momentum.", 10
                        ))
                else:
                    pending_steps.append(AttackStep(
                        AttackPhase.RECON, "nmap", plan.target, {"mode": plan.mode, "extra_args": ["-p-", "-T4", "-A"]},
                        "OUROBOROS: Endless loop triggered full deep port scan as fallback.", 10
                    ))
        
        # Sync back the final state of steps to the plan variable so the summary is accurate
        plan.steps = pending_steps

        return {
            "plan_summary": plan.to_dict(),
            "steps_executed": steps_run,
            "results": results,
            "final_surface": surface,
            "attack_narrative": self._generate_narrative(results, surface),
        }

    def _adapt(self, step: AttackStep, result, surface: Dict, plan: AttackPlan) -> List[AttackStep]:
        new_steps = []
        mode = plan.mode
        
        # Helper to avoid adding the exact same tool+target combo to the plan multiple times
        def is_planned(t_tool, t_target):
            return any(s.tool == t_tool and s.target == t_target for s in plan.steps)

        if step.tool == "nmap":
            for f in result.findings:
                port = f.get("port", 0)
                service = f.get("service", "")
                version = f.get("version", "")
                
                if port in [139, 445] and not is_planned("enum4linux", plan.target):
                    new_steps.append(AttackStep(
                        AttackPhase.ENUMERATION, "enum4linux", plan.target, {"mode": mode},
                        "ADAPTIVE: Nmap found SMB — injecting SMB enumeration", 2,
                    ))
                if port == 3306 and not is_planned("sqlmap", f"http://{plan.target}"):
                    new_steps.append(AttackStep(
                        AttackPhase.EXPLOITATION, "sqlmap", f"http://{plan.target}", {"mode": mode},
                        "ADAPTIVE: MySQL found — injecting SQLi testing on web interface", 4,
                    ))
                
                # ADAPTIVE: Automatically query searchsploit for specific service versions found
                if version and len(version) > 2 and not is_planned("searchsploit", f"{service} {version}"):
                    new_steps.append(AttackStep(
                        AttackPhase.ENUMERATION, "searchsploit", f"{service} {version}", {"exact": True},
                        f"ADAPTIVE: Nmap found {service} {version} — querying exploit database", 3,
                    ))


        if step.tool == "whatweb":
            for f in result.findings:
                tech = str(f.get("technology", "")).lower()
                version = str(f.get("version", ""))
                if "wordpress" in tech:
                    if not is_planned("wpscan", step.target):
                        new_steps.append(AttackStep(
                            AttackPhase.ENUMERATION, "wpscan", step.target, {"mode": mode},
                            "ADAPTIVE: WordPress detected by WhatWeb — injecting WPScan", 2,
                        ))
                if tech and version and len(version) > 1 and not is_planned("searchsploit", f"{tech} {version}"):
                     new_steps.append(AttackStep(
                        AttackPhase.ENUMERATION, "searchsploit", f"{tech} {version}", {"exact": True},
                        f"ADAPTIVE: WhatWeb found {tech} {version} — querying exploit database", 3,
                    ))


        if step.tool in ["gobuster", "feroxbuster", "dirsearch"]:
            for f in result.findings:
                path = f.get("path", "") or f.get("url", "")
                if any(x in path for x in ["/admin", "/login", "/wp-admin", "/phpmyadmin"]):
                    if not is_planned("hydra", step.target):
                        new_steps.append(AttackStep(
                            AttackPhase.EXPLOITATION, "hydra", step.target,
                            {"mode": mode, "service": "http-post-form"},
                            f"ADAPTIVE: Admin panel found at {path} — injecting credential brute-force", 3,
                        ))

        if step.tool == "nuclei":
            for f in result.findings:
                name = str(f.get("name", "")).lower()
                if "sql" in name:
                    if not is_planned("sqlmap", step.target):
                        new_steps.append(AttackStep(
                            AttackPhase.EXPLOITATION, "sqlmap", step.target, {"mode": mode},
                            "ADAPTIVE: Nuclei found SQLi indicator — injecting sqlmap for exploitation", 2,
                        ))
                if "rce" in name or "remote code execution" in name:
                     if not is_planned("metasploit", step.target): # Mock handler for Metasploit integration
                        new_steps.append(AttackStep(
                            AttackPhase.POST_EXPLOIT, "metasploit", step.target, {"mode": mode, "exploit": name},
                            "ADAPTIVE: Nuclei found RCE indicator — preparing Metasploit payload delivery", 1,
                        ))
                
        if step.tool == "enum4linux":
            users = [f.get("username") for f in result.findings if f.get("type") == "user"]
            if users:
                if not is_planned("hydra", plan.target):
                    new_steps.append(AttackStep(
                        AttackPhase.EXPLOITATION, "hydra", plan.target,
                        {"mode": mode, "service": "smb", "username": users[0]},
                        f"ADAPTIVE: Enum4linux found users {users[:3]} — injecting targeted SMB brute-force", 3,
                    ))

        if step.tool == "searchsploit":
            remote = [f for f in result.findings if f.get("type") == "remote"]
            if remote:
                cmd = f"msfconsole -q -x 'search {remote[0].get('title', '')}; exit'"
                if not is_planned("run_command", cmd):
                    new_steps.append(AttackStep(
                        AttackPhase.EXPLOITATION, "run_command", cmd,
                        {"mode": mode},
                        f"ADAPTIVE: Remote exploit found — generating Metasploit search command", 3,
                    ))

        if step.tool == "nmap":
            http_findings = [f for f in result.findings
                             if f.get("port") in [80, 8080, 443, 8443, 8000, 8888]
                             or f.get("service") in ["http", "https", "http-alt"]]
            if http_findings and not is_planned("httpx", plan.target):
                new_steps.append(AttackStep(
                    AttackPhase.ENUMERATION, "httpx", plan.target, {"mode": mode},
                    "ADAPTIVE: Nmap found HTTP port(s) — probing web services with httpx", 2,
                ))
            ssh_findings = [f for f in result.findings
                            if f.get("port") == 22 or f.get("service") == "ssh"]
            if ssh_findings and not is_planned("hydra", plan.target) and mode in ["ctf", "pentest"]:
                new_steps.append(AttackStep(
                    AttackPhase.EXPLOITATION, "hydra", plan.target,
                    {"mode": mode, "service": "ssh"},
                    "ADAPTIVE: Nmap found SSH — injecting SSH brute-force", 4,
                ))
            ftp_findings = [f for f in result.findings
                            if f.get("port") == 21 or f.get("service") == "ftp"]
            if ftp_findings and not is_planned("hydra", f"ftp://{plan.target}"):
                new_steps.append(AttackStep(
                    AttackPhase.EXPLOITATION, "hydra", f"ftp://{plan.target}",
                    {"mode": mode, "service": "ftp"},
                    "ADAPTIVE: Nmap found FTP — injecting FTP brute-force", 4,
                ))

        if step.tool == "httpx":
            live = [f.get("url", "") for f in result.findings
                    if f.get("status") in [200, 301, 302, 403] and f.get("url")]
            for url in live[:2]:
                if not is_planned("gobuster", url):
                    new_steps.append(AttackStep(
                        AttackPhase.ENUMERATION, "gobuster", url, {"mode": mode},
                        f"ADAPTIVE: httpx found live URL {url} — directory enumeration", 2,
                    ))
                if not is_planned("nuclei", url):
                    new_steps.append(AttackStep(
                        AttackPhase.ENUMERATION, "nuclei", url, {"mode": mode},
                        f"ADAPTIVE: httpx found live URL {url} — vulnerability scanning", 2,
                    ))
            for f in result.findings:
                tech = f.get("tech", [])
                if isinstance(tech, list) and any("wordpress" in t.lower() for t in tech if t):
                    url = f.get("url", step.target)
                    if not is_planned("wpscan", url):
                        new_steps.append(AttackStep(
                            AttackPhase.ENUMERATION, "wpscan", url, {"mode": mode},
                            "ADAPTIVE: httpx detected WordPress — injecting WPScan", 1,
                        ))

        if step.tool == "subfinder":
            subdomains = [f.get("subdomain", "") for f in result.findings if f.get("subdomain")]
            if subdomains and not is_planned("httpx", plan.target):
                new_steps.append(AttackStep(
                    AttackPhase.ENUMERATION, "httpx", plan.target, {"mode": mode},
                    f"ADAPTIVE: subfinder found {len(subdomains)} subdomains — probing with httpx", 2,
                ))

        if step.tool == "nuclei":
            for f in result.findings:
                name = str(f.get("name", "")).lower()
                if "xss" in name and not is_planned("dalfox", step.target):
                    new_steps.append(AttackStep(
                        AttackPhase.EXPLOITATION, "dalfox",
                        f.get("matched_at", step.target), {"mode": mode},
                        "ADAPTIVE: Nuclei found XSS indicator — injecting dalfox for deep XSS testing", 2,
                    ))

        if step.tool == "sqlmap":
            injections = [f for f in result.findings
                          if f.get("injectable") or f.get("type") == "sql_injection"]
            if injections and not is_planned("exploit_synth", step.target):
                new_steps.append(AttackStep(
                    AttackPhase.POST_EXPLOIT, "exploit_synth", step.target,
                    {"mode": mode, "vuln_type": "sqli"},
                    "ADAPTIVE: sqlmap confirmed SQL injection — generating PoC exploit", 2,
                ))

        return new_steps

    def _update_surface(self, surface: Dict, tool: str, findings: List[Dict]):
        if tool == "nmap":
            for f in findings:
                port = f.get("port")
                if port and port not in surface.get("open_ports", []):
                    surface.setdefault("open_ports", []).append(port)
        elif tool == "whatweb":
            for f in findings:
                tech = f.get("technology", "")
                if "wordpress" in tech.lower():
                    surface["cms"] = "WordPress"
                elif "joomla" in tech.lower():
                    surface["cms"] = "Joomla"
        elif tool == "wafw00f":
            for f in findings:
                if f.get("waf"):
                    surface["waf"] = f["waf"]

    def _generate_narrative(self, results: List[Dict], surface: Dict) -> str:
        lines = ["## Attack Narrative\n"]
        total_findings = sum(r.get("findings_count", 0) for r in results)
        max_risk = max((r.get("risk_score", 0) for r in results), default=0)

        lines.append(f"**Target Profile:** {surface.get('type', 'unknown')} | OS: {surface.get('os_guess', 'unknown')}")
        lines.append(f"**Open Ports:** {surface.get('open_ports', [])}")
        lines.append(f"**Total Findings:** {total_findings} | **Max Risk:** {max_risk}/10")
        if surface.get("cms"):
            lines.append(f"**CMS:** {surface['cms']}")
        if surface.get("waf"):
            lines.append(f"**WAF:** {surface['waf']} (stealth required)")
        lines.append("")

        for r in results:
            if r.get("skipped"):
                continue
            status = "[OK]" if r.get("success") else "[FAIL]"
            lines.append(f"{status} **{r['tool'].upper()}** → {r['findings_count']} findings (risk: {r['risk_score']}/10)")
            lines.append(f"   *{r['reason']}*")
            if r.get("findings"):
                for f in r["findings"][:3]:
                    lines.append(f"   - {json.dumps(f)[:100]}")

        return "\n".join(lines)


class StructuredContextBuilder:
    """
    Replaces the static KillChainBuilder rule engine with a data-rich context
    object that any LLM can use to generate specific, hypothesis-driven attack plans.

    Instead of: static rules → fixed tool list
    Now:        rich context → LLM → ranked hypotheses → targeted tools only
    """

    def build_context(
        self,
        target: str,
        logic_map: Dict[str, Any],
        playbook: Dict[str, Any],
        mode: str = "default",
        objective: str = "find_vulnerabilities",
    ) -> Dict[str, Any]:
        """
        Build a structured context dict for LLM consumption.
        Returns a compact, token-efficient summary of everything known about the target.
        """
        tech_stack = logic_map.get("technologies", [])
        endpoints  = logic_map.get("endpoints", [])
        interesting= logic_map.get("interesting", {})

        # Extract high-value targets for the LLM to focus on
        high_value = []
        for ep in interesting.get("idor_candidates", [])[:5]:
            high_value.append({"type": "IDOR_candidate", "endpoint": ep, "confidence": "HIGH",
                                "reason": "Numeric/UUID ID in REST path — test ownership check"})
        for ep in interesting.get("upload_endpoints", [])[:3]:
            high_value.append({"type": "upload_bypass", "endpoint": ep, "confidence": "MEDIUM",
                                "reason": "File upload endpoint — test extension bypass, type confusion"})
        for ep in interesting.get("admin_panels", [])[:3]:
            high_value.append({"type": "admin_exposure", "endpoint": ep, "confidence": "HIGH",
                                "reason": "Admin panel — test auth bypass, default creds, brute force"})

        # Build playbook hints from memory
        memory_hints = []
        for tech in tech_stack:
            pb = playbook.get(tech, {})
            if pb.get("known_vulns"):
                memory_hints.append({
                    "tech":       tech,
                    "known_vulns":pb["known_vulns"][:5],
                    "bypasses":   pb.get("bypasses", [])[:3],
                    "best_tools": pb.get("best_tools", [])[:3],
                })

        # Token-efficient endpoint summary (cap at 15)
        ep_summary = []
        for ep in endpoints[:15]:
            ep_summary.append({
                "path":   ep.get("path", ""),
                "params": ep.get("params", [])[:5],
            })

        return {
            "target":             target,
            "mode":               mode,
            "objective":          objective,
            "tech_stack":         tech_stack,
            "endpoint_count":     len(endpoints),
            "endpoint_sample":    ep_summary,
            "high_value_targets": high_value,
            "memory_hints":       memory_hints,
            "recent_successes":   playbook.get("_recent_successes", [])[:5],
            "js_secrets_found":   len(logic_map.get("js_files", [])),
            "auth_endpoints":     interesting.get("auth_endpoints", [])[:5],
            "api_endpoints":      interesting.get("api_endpoints", [])[:5],
            "instructions": (
                "You are a senior penetration tester. Based on this context:\n"
                "1. Generate 3-7 specific hypotheses ranked by confidence (HIGH/MEDIUM/LOW)\n"
                "2. Each hypothesis: type, endpoint, test_method, tool_to_use\n"
                "3. Start with HIGH confidence hypotheses from memory_hints\n"
                "4. Use write_and_exec for custom exploit scripts\n"
                "5. Call save_learning() after each confirmed/denied hypothesis\n"
                f"6. Mode is '{mode}' — {'be stealthy, respect rate limits' if mode == 'bugbounty' else 'maximize coverage'}"
            ),
        }
