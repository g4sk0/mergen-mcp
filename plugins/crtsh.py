import json
import asyncio
from typing import Any, Dict, List
import urllib.request
import urllib.error

from plugins import register
from plugins.base import BaseTool, ToolResult

@register
class CrtshPlugin(BaseTool):
    name = "crtsh"
    description = "Passive subdomain enumeration via Certificate Transparency logs (crt.sh). No API key required."
    category = "recon"
    requires = []  # Native Python HTTP request
    
    def is_available(self) -> bool:
        return True
        
    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        # Provide base domain
        url = f"https://crt.sh/?q=%.{target}&output=json"
        
        loop = asyncio.get_event_loop()
        try:
            # We use run_in_executor to avoid blocking the asyncio thread with urllib
            req = urllib.request.Request(url, headers={'User-Agent': 'Mergen-Security-Scanner/2.0'})
            response = await loop.run_in_executor(None, lambda: urllib.request.urlopen(req, timeout=30))
            data = response.read().decode('utf-8')
            findings = self._parse(data, target)
            return ToolResult(
                tool=self.name,
                target=target,
                success=True,
                raw_output=data[:5000],  # Truncate to save db space
                findings=findings,
                suggested_next=["subfinder", "httpx"] if findings else [],
                risk_score=0.0,
                metadata={"domain": target, "count": len(findings)},
            )
        except Exception as e:
            return ToolResult(
                tool=self.name,
                target=target,
                success=False,
                raw_output=str(e),
                error=f"Failed to fetch from crt.sh: {e}",
            )

    def _parse(self, output: str, target: str) -> List[Dict]:
        findings = []
        subdomains = set()
        try:
            data = json.loads(output)
            for cert in data:
                name = cert.get("name_value", "")
                for domain in name.split("\\n"):
                    domain = domain.strip().lower()
                    if domain.endswith(target) and not domain.startswith("*"):
                        subdomains.add(domain)
            
            for sub in sorted(subdomains):
                findings.append({"subdomain": sub})
        except Exception:
            pass
        return findings
