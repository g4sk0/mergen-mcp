MODE_PROFILES = {
    "ctf": {
        "label": "CTF",
        "color": "#f97316",
        "strategy": "exploit-first",
        "description": "Capture The Flag mode. Aggressive enumeration. Prioritize RCE, binary exploitation, weak creds, flags.",
        "priority_tools": ["rustscan", "nmap", "gobuster", "searchsploit", "hydra", "sqlmap", "pwntools", "ghidra", "hashcat", "john"],
        "avoid": [],
        "nuclei_severity": "critical,high",
        "nmap_flags": "-T4 -A --min-rate=2000",
        "gobuster_wordlist": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "guidance": (
            "CTF MODE: Be aggressive. Speed matters.\n"
            "1. Start with rustscan for fast port discovery, then nmap -A for service details.\n"
            "2. For web: gobuster aggressive wordlist, then nuclei critical+high.\n"
            "3. For login pages: immediately try default/common creds with hydra.\n"
            "4. Check versions against searchsploit for known exploits.\n"
            "5. For binaries: checksec -> ghidra -> pwntools.\n"
            "6. Look for flags in: /root, /home, /etc, /var/www, database tables.\n"
            "7. Chain: nmap -> searchsploit (versions) -> exploit_synth -> write_and_exec"
        ),
    },
    "pentest": {
        "label": "Pentest",
        "color": "#ef4444",
        "strategy": "methodical",
        "description": "Professional penetration test. Thorough enumeration before exploitation. Document everything.",
        "priority_tools": ["nmap", "httpx", "whatweb", "gobuster", "nuclei", "sqlmap", "dalfox", "enum4linux", "smbmap", "hydra", "searchsploit"],
        "avoid": [],
        "nuclei_severity": "critical,high,medium",
        "nmap_flags": "-T4 -sV -sC -O --min-rate=1000",
        "gobuster_wordlist": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "guidance": (
            "PENTEST MODE: Methodical coverage.\n"
            "1. Full port scan (nmap -sV -sC -O). Enumerate EVERY service.\n"
            "2. For web: httpx -> whatweb -> gobuster -> nuclei -> sqlmap/dalfox.\n"
            "3. For SMB: enum4linux -> smbmap -> check shares -> hydra if user list found.\n"
            "4. For SSH: check version with searchsploit, try hydra with common creds.\n"
            "5. For DB ports (3306, 5432, 1433): test default creds, check for SQLi via web.\n"
            "6. Call get_attack_context after each phase to get suggested next steps.\n"
            "7. Use save_learning() to record confirmed vulns for reporting.\n"
            "8. Chain: nmap -> httpx -> gobuster -> nuclei -> exploit_synth -> write_and_exec"
        ),
    },
    "bb": {
        "label": "Bug Bounty",
        "color": "#3b82f6",
        "strategy": "passive-first",
        "description": "Bug bounty hunting. Passive recon first. OWASP Top 10. Respect scope and rate limits.",
        "priority_tools": ["subfinder", "httpx", "katana", "arjun", "nuclei", "dalfox", "sqlmap", "trufflehog", "gau", "waybackurls"],
        "avoid": ["hydra", "masscan", "responder", "netexec"],
        "nuclei_severity": "critical,high,medium,low",
        "nmap_flags": "-T3 -sV --top-ports 1000",
        "gobuster_wordlist": "/usr/share/wordlists/dirb/common.txt",
        "guidance": (
            "BUG BOUNTY MODE: Passive first, respect scope.\n"
            "1. Start with subfinder for subdomain enumeration.\n"
            "2. httpx to probe all subdomains for live hosts.\n"
            "3. katana for deep crawling, arjun for parameter discovery.\n"
            "4. nuclei with all severity levels including info.\n"
            "5. dalfox for XSS on every parameter found.\n"
            "6. sqlmap on forms/params (NOT aggressive, respect rate limits).\n"
            "7. trufflehog/gau for secrets and historical exposure.\n"
            "8. NO brute force tools (hydra, masscan).\n"
            "9. Chain: subfinder -> httpx -> katana -> arjun -> nuclei/dalfox/sqlmap"
        ),
    },
    "default": {
        "label": "Default",
        "color": "#6b7280",
        "strategy": "balanced",
        "description": "Balanced mode. General-purpose scanning.",
        "priority_tools": ["nmap", "httpx", "nuclei", "gobuster", "searchsploit"],
        "avoid": [],
        "nuclei_severity": "critical,high,medium",
        "nmap_flags": "-T4 -sV --top-ports 1000",
        "gobuster_wordlist": "/usr/share/wordlists/dirb/common.txt",
        "guidance": (
            "DEFAULT MODE: Balanced approach.\n"
            "1. nmap for port scan and service detection.\n"
            "2. httpx for web probing if HTTP ports found.\n"
            "3. nuclei for vulnerability scanning.\n"
            "4. gobuster for directory enumeration.\n"
            "5. Call get_attack_context for suggested next steps."
        ),
    },
}


def get_profile(mode: str) -> dict:
    """Return mode profile, fallback to default."""
    return MODE_PROFILES.get(mode, MODE_PROFILES["default"])


def get_all_modes() -> list:
    """Return list of available mode names."""
    return list(MODE_PROFILES.keys())
