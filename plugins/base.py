from __future__ import annotations

import asyncio
import shutil
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any, ClassVar, Dict, List, Optional, Tuple

from server.process_manager import process_manager, JobStatus


@dataclass
class ToolResult:

    tool: str
    target: str
    success: bool
    raw_output: str = ""
    findings: List[Dict[str, Any]] = field(default_factory=list)
    suggested_next: List[str] = field(default_factory=list)
    risk_score: float = 0.0  # 0–10
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_llm_summary(self) -> str:
        lines = [
            f"[{self.tool.upper()}] Target: {self.target} | "
            f"Risk: {self.risk_score}/10 | Success: {self.success}",
        ]
        for finding in self.findings[:10]:  # cap at 10 to save tokens
            lines.append(f"  • {finding}")
        if self.suggested_next:
            lines.append(f"  → Suggested next: {', '.join(self.suggested_next)}")
        if self.error:
            lines.append(f"   Error: {self.error}")
        return "\n".join(lines)


class BaseTool(ABC):

    name: ClassVar[str] = "base"
    description: ClassVar[str] = "Base tool"
    category: ClassVar[str] = "misc"  # recon | web | exploit | enum | binary | misc
    requires: ClassVar[List[str]] = []  # system binaries required (e.g. ["nmap"])

    def is_available(self) -> bool:
        return all(shutil.which(binary) is not None for binary in self.requires)

    @abstractmethod
    async def run(self, target: str, options: Dict[str, Any]) -> ToolResult:
        ...

    async def _exec(
        self,
        cmd: List[str],
        timeout: int = 300,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        simulate_progress: bool = True,
    ) -> Tuple[str, str, int]:
        import math
        try:
            # run() returns immediately after spawning the asyncio task
            job = await process_manager.run(
                tool=self.name,
                target=" ".join(cmd[:3]) + "...",
                cmd=cmd,
                timeout=timeout,
            )
            
            sim_task = None
            if simulate_progress:
                async def progress_simulator():
                    start_time = time.time()
                    while job.status == JobStatus.RUNNING:
                        await asyncio.sleep(1.5)
                        if job.status != JobStatus.RUNNING: 
                            break
                        elapsed = time.time() - start_time
                        # Pct approaches ~99% over ~60 seconds (scaled)
                        pct = 99.0 * (1.0 - math.exp(-elapsed / 25.0))
                        pm_broadcast = getattr(process_manager, "_broadcast", None)
                        if pm_broadcast:
                            line = f"[MERGEN-PROGRESS:{pct:.1f}%]"
                            pm_broadcast({"event": "output", "job_id": job.id, "line": line})

                sim_task = asyncio.create_task(progress_simulator())

            await process_manager.wait(job)
            
            if sim_task:
                sim_task.cancel()

            stdout = "\n".join(job.output_lines)
            return stdout, "", job.return_code or 0

        except Exception as e:
            return "", f"[ERROR] ProcessManager failure: {e}", -1
