import re
import xml.etree.ElementTree as ET
import os
import tempfile
from typing import Any, Dict, List

from plugins import register
from plugins.base import BaseTool, ToolResult


MODE_FLAGS = {
    "ctf":       ["-T5", "--top-ports", "1000", "-sV", "--open"],
    "bugbounty": ["-T2", "-sS", "--randomize-hosts", "-sV", "--open", "-Pn"],
    "internal":  ["-T4", "-A", "-sV", "-sC", "--script=vuln", "--open"],
    "stealth":   ["-T1", "-sS", "-f", "--data-length", "24", "--open", "-Pn"],
    "default":   ["-T4", "-sV", "-sC", "--open", "--top-ports", "1000"],
}

PORT_SUGGESTIONS = {
    21:   ["hydra"],
    22:   ["hydra"],
    23:   ["hydra"],
    25:   ["smtp-user-enum"],
    53:   ["dnsenum", "fierce"],
    80:   ["gobuster", "nuclei", "whatweb"],
    110:  ["hydra"],
    139:  ["enum4linux", "smbmap"],
    143:  ["hydra"],
    443:  ["gobuster", "nuclei", "whatweb"],
    445:  ["enum4linux", "smbmap", "crackmapexec"],
    1433: ["hydra"],
    3306: ["hydra"],
    3389: ["hydra"],
    5432: ["hydra"],
    6379: ["redis-cli"],
    8080: ["gobuster", "nuclei"],
    8443: ["gobuster", "nuclei"],
    27017:["mongodump"],
}


@register
class NmapPlugin(BaseTool):
    name = "nmap"
    description = "Context-aware port scanner. Adapts intensity based on mode (ctf/bugbounty/internal/stealth)."
    category = "recon"
    requires = ["nmap"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        mode = options.get("mode", "default")
        extra = options.get("extra_args", [])
        flags = MODE_FLAGS.get(mode, MODE_FLAGS["default"])

        with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as tmp:
            xml_path = tmp.name

        try:
            cmd = ["nmap"] + flags + ["-oX", xml_path, "--stats-every", "3s", target]
            
            stdout, stderr, rc = await self._exec(cmd, timeout=300)

            if rc == -1:
                return ToolResult(
                    tool=self.name, target=target, success=False,
                    error=stderr, raw_output=stderr,
                )

            try:
                with open(xml_path, "r", encoding="utf-8") as f:
                    xml_content = f.read()
            except Exception as e:
                xml_content = ""
                stderr += f"\n[!] Failed to read XML output: {e}"

            findings, suggested = self._parse_xml(xml_content)
            risk = self._calc_risk(findings)

            display_output = stdout if stdout.strip() else stderr

            # Prevent empty findings array from looking like a failure if ports were closed
            if rc == 0 and not findings:
                findings.append({
                    "ip": target,
                    "port": 0,
                    "service": "None",
                    "product": "All scanned ports closed or filtered",
                    "version": ""
                })

            return ToolResult(
                tool=self.name,
                target=target,
                success=rc == 0,
                raw_output=display_output,
                findings=findings,
                suggested_next=suggested,
                risk_score=risk,
                metadata={"mode": mode, "flags": flags},
            )
        finally:
            if os.path.exists(xml_path):
                os.remove(xml_path)

    def _parse_xml(self, xml_str: str):
        findings = []
        suggested = set()
        try:
            root = ET.fromstring(xml_str)
            for host in root.findall("host"):
                addr = host.find("address")
                ip = addr.get("addr", "?") if addr is not None else "?"
                for port_el in host.findall(".//port"):
                    port_num = int(port_el.get("portid", 0))
                    state = port_el.find("state")
                    if state is None or state.get("state") != "open":
                        continue
                    svc = port_el.find("service")
                    service_name = svc.get("name", "unknown") if svc is not None else "unknown"
                    product = svc.get("product", "") if svc is not None else ""
                    version = svc.get("version", "") if svc is not None else ""
                    findings.append({
                        "ip": ip,
                        "port": port_num,
                        "service": service_name,
                        "product": product,
                        "version": version,
                    })
                    for s in PORT_SUGGESTIONS.get(port_num, []):
                        suggested.add(s)
        except ET.ParseError:
            for line in xml_str.splitlines():
                m = re.match(r"(\d+)/tcp\s+open\s+(\S+)", line)
                if m:
                    findings.append({"port": int(m.group(1)), "service": m.group(2)})
        return findings, list(suggested)

    def _calc_risk(self, findings: List[Dict]) -> float:
        high_risk_ports = {21, 22, 23, 25, 445, 3389, 5900}
        score = min(len(findings) * 0.5, 5.0)
        for f in findings:
            if f.get("port") in high_risk_ports:
                score += 1.0
        return min(round(score, 1), 10.0)
