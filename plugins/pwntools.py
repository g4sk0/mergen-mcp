from typing import Any, Dict, List
from plugins import register
from plugins.base import BaseTool, ToolResult

TEMPLATE = '''#!/usr/bin/env python3
from pwn import *

binary = ELF("{binary}")
context.binary = binary
context.log_level = "info"

if args.REMOTE:
    p = remote("{host}", {port})
else:
    p = process(binary.path)

if args.GDB:
    gdb.attach(p, """
        break main
        continue
    """)

payload = flat(
    b"A" * {offset},  # padding
)

p.sendlineafter(b":", payload)
p.interactive()
'''

@register
class PwntoolsPlugin(BaseTool):
    name = "pwntools"
    description = "CTF exploit development: generates exploit templates and runs pwntools scripts."
    category = "binary"
    requires = ["python3"]

    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        action = options.get("action", "template")
        if action == "template":
            host = options.get("host", "127.0.0.1")
            port = options.get("port", 1337)
            offset = options.get("offset", 64)
            code = TEMPLATE.format(binary=target, host=host, port=port, offset=offset)
            return ToolResult(
                tool=self.name, target=target, success=True,
                raw_output=code,
                findings=[{"type": "template", "code": code}],
                suggested_next=["checksec", "ghidra"],
                risk_score=0.0,
                metadata={"action": action},
            )
        elif action == "cyclic":
            length = options.get("length", 200)
            cmd = ["python3", "-c", f"from pwn import *; print(cyclic({length}).decode())"]
            stdout, _, rc = await self._exec(cmd, timeout=10)
            return ToolResult(
                tool=self.name, target=target, success=(rc != -1),
                raw_output=stdout,
                findings=[{"cyclic_pattern": stdout.strip()}],
                suggested_next=[],
                risk_score=0.0,
                metadata={"length": length},
            )
        return ToolResult(tool=self.name, target=target, success=False, error="Unknown action")
