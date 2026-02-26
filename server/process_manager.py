from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


MAX_OUTPUT_LINES = 5_000


class JobStatus(str, Enum):
    QUEUED  = "queued"
    RUNNING = "running"
    DONE    = "done"
    FAILED  = "failed"
    KILLED  = "killed"


@dataclass
class Job:
    id: str
    tool: str
    target: str
    cmd: List[str]
    session: str = "default"
    status: JobStatus = JobStatus.QUEUED
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    output_lines: List[str] = field(default_factory=list)
    pid: Optional[int] = None
    return_code: Optional[int] = None
    _proc: Optional[asyncio.subprocess.Process] = field(default=None, repr=False, compare=False)
    _done_event: asyncio.Event = field(default=None, repr=False, compare=False)  # type: ignore[assignment]

    def __post_init__(self):
        self._done_event = asyncio.Event()

    def elapsed(self) -> float:
        if self.started_at is None:
            return 0.0
        end = self.finished_at or time.time()
        return round(end - self.started_at, 1)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id":           self.id,
            "tool":         self.tool,
            "target":       self.target,
            "status":       self.status.value,
            "elapsed":      self.elapsed(),
            "pid":          self.pid,
            "return_code":  self.return_code,
            "output_lines": self.output_lines[-200:],
        }


class _Subscriber:
    """
    Wraps a WebSocket send coroutine with a private queue so that
    _execute never blocks on WS I/O and concurrent sends never race.
    """
    def __init__(self, send_coro_fn):
        self._fn = send_coro_fn
        self._queue: asyncio.Queue = asyncio.Queue()
        self._task: asyncio.Task = asyncio.ensure_future(self._drain())
        self.dead = False

    async def _drain(self):
        while True:
            event = await self._queue.get()
            if event is None:          # sentinel → stop
                break
            try:
                await self._fn(event)
            except asyncio.CancelledError:
                self.dead = True
                break
            except Exception as e:
                # Log error but don't assume connection is definitively dead 
                # unless it's a specific websocket closure
                print(f"[WS] Send error: {e}")
                self.dead = True
                break                  # WS closed; stop draining

    def push(self, event: Dict[str, Any]):
        if not self.dead:
            try:
                self._queue.put_nowait(event)
            except Exception:
                pass

    def close(self):
        self._queue.put_nowait(None)   # send sentinel


class ProcessManager:

    def __init__(self, max_concurrent: int = 5) -> None:
        self._jobs: Dict[str, Job] = {}
        self._tasks: Dict[str, asyncio.Task] = {}
        self._subscribers: Set[_Subscriber] = set()
        self._semaphore = asyncio.Semaphore(max_concurrent)

    # ------------------------------------------------------------------ #
    # Subscription management
    # ------------------------------------------------------------------ #

    def subscribe(self, send_fn) -> _Subscriber:
        sub = _Subscriber(send_fn)
        self._subscribers.add(sub)
        return sub

    def unsubscribe(self, sub: _Subscriber) -> None:
        sub.close()
        self._subscribers.discard(sub)

    # ------------------------------------------------------------------ #
    # Broadcasting — push to every subscriber queue, never awaits
    # ------------------------------------------------------------------ #

    def _broadcast(self, event: Dict[str, Any]) -> None:
        dead = set()
        for sub in list(self._subscribers):
            if sub.dead:
                dead.add(sub)
            else:
                sub.push(event)
        self._subscribers -= dead

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def list_jobs(self) -> List[Dict[str, Any]]:
        return [j.to_dict() for j in self._jobs.values()]

    def get_job(self, job_id: str) -> Optional[Job]:
        return self._jobs.get(job_id)

    async def kill_job(self, job_id: str) -> bool:
        job = self._jobs.get(job_id)
        if not job or job.status not in (JobStatus.RUNNING, JobStatus.QUEUED):
            return False

        if job._proc is not None:
            try:
                job._proc.kill()
            except (ProcessLookupError, OSError):
                pass

        task = self._tasks.get(job_id)
        if task and not task.done():
            task.cancel()

        job.status = JobStatus.KILLED
        job.finished_at = time.time()
        job._done_event.set()
        self._broadcast({"event": "job_killed", "job": job.to_dict()})
        return True

    def create_job(self, target: str, tool: str, session: str = "default") -> str:
        job_id = str(uuid.uuid4())[:8]
        job = Job(id=job_id, tool=tool, target=target, cmd=[], session=session)
        self._jobs[job_id] = job
        self._broadcast({"event": "job_queued", "job": job.to_dict()})
        return job_id

    def start_job(self, job_id: str) -> None:
        job = self.get_job(job_id)
        if job:
            job.status = JobStatus.RUNNING
            job.started_at = time.time()
            self._broadcast({"event": "job_started", "job": job.to_dict()})

    def finish_job(self, job_id: str, success: bool, findings: List[Dict] = None) -> None:
        job = self.get_job(job_id)
        if job:
            job.status = JobStatus.DONE if success else JobStatus.FAILED
            job.finished_at = time.time()
            job._done_event.set()
            self._broadcast({
                "event": "job_done", 
                "job": job.to_dict(),
                "findings_count": len(findings) if findings else 0
            })

    def broadcast(self, job_id: str, message: str) -> None:
        job = self.get_job(job_id)
        if job:
            if len(job.output_lines) < MAX_OUTPUT_LINES:
                job.output_lines.append(message)
            self._broadcast({
                "event": "output",
                "job_id": job_id,
                "line": message
            })


    async def run(
        self,
        tool: str,
        target: str,
        cmd: List[str],
        timeout: int = 600,
    ) -> "Job":
        job = Job(id=str(uuid.uuid4())[:8], tool=tool, target=target, cmd=cmd)
        self._jobs[job.id] = job

        task = asyncio.ensure_future(self._execute(job, timeout))
        self._tasks[job.id] = task

        # Yield several ticks so _execute runs past job_started broadcast
        # before the caller begins waiting.
        for _ in range(8):
            await asyncio.sleep(0)

        return job

    async def wait(self, job: "Job") -> "Job":
        await job._done_event.wait()
        return job

    # ------------------------------------------------------------------ #
    # Internal execution
    # ------------------------------------------------------------------ #

    async def _execute(self, job: Job, timeout: int) -> None:
        job.status = JobStatus.QUEUED
        self._broadcast({"event": "job_queued", "job": job.to_dict()})

        # Wait for an available slot in the semaphore before starting the process
        async with self._semaphore:
            job.status = JobStatus.RUNNING
            job.started_at = time.time()
            self._broadcast({"event": "job_started", "job": job.to_dict()})

            proc: Optional[asyncio.subprocess.Process] = None
            try:
                proc = await asyncio.create_subprocess_exec(
                    *job.cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                job._proc = proc
                job.pid = proc.pid
                self._broadcast({"event": "job_started", "job": job.to_dict()})

                async def _stream_stdout() -> None:
                    assert proc.stdout is not None
                    buffer = bytearray()
                    while True:
                        try:
                            chunk = await proc.stdout.read(1024)
                        except ValueError:
                            break
                        if not chunk:
                            if buffer:
                                line = buffer.decode("utf-8", errors="replace").strip()
                                if line and len(job.output_lines) < MAX_OUTPUT_LINES:
                                    job.output_lines.append(line)
                                    self._broadcast({"event": "output", "job_id": job.id, "line": line})
                            break

                        buffer.extend(chunk)
                        while True:
                            rn = buffer.find(b'\r\n')
                            r = buffer.find(b'\r')
                            n = buffer.find(b'\n')
                            
                            # Find the earliest newline character
                            idxs = [i for i in (rn, r, n) if i != -1]
                            if not idxs:
                                break
                            min_idx = min(idxs)
                            
                            if min_idx == rn:
                                line_bytes = buffer[:min_idx]
                                del buffer[:min_idx+2]
                            else:
                                line_bytes = buffer[:min_idx]
                                del buffer[:min_idx+1]
                                
                            line = line_bytes.decode("utf-8", errors="replace").strip()
                            if line:
                                if len(job.output_lines) < MAX_OUTPUT_LINES:
                                    job.output_lines.append(line)
                                self._broadcast({
                                    "event": "output",
                                    "job_id": job.id,
                                    "line": line,
                                })

                await asyncio.wait_for(_stream_stdout(), timeout=timeout)
                await proc.wait()
                job.return_code = proc.returncode
                # Security tools often return non-zero exit codes even on success.
                # We consider the job DONE if it completed without timing out or crashing.
                job.status = JobStatus.DONE

            except asyncio.TimeoutError:
                job.status = JobStatus.FAILED
                job.output_lines.append(f"[TIMEOUT] Job exceeded {timeout}s — process killed")
                if proc is not None:
                    try:
                        proc.kill()
                        await proc.wait()
                    except (ProcessLookupError, OSError):
                        pass

            except asyncio.CancelledError:
                job.status = JobStatus.KILLED
                if proc is not None:
                    try:
                        proc.kill()
                        await proc.wait()
                    except (ProcessLookupError, OSError):
                        pass
                raise

            except Exception as exc:  # noqa: BLE001
                job.status = JobStatus.FAILED
                job.output_lines.append(f"[ERROR] {exc}")

            finally:
                job.finished_at = time.time()
                job._proc = None
                self._tasks.pop(job.id, None)
                job._done_event.set()
                self._broadcast({"event": "job_done", "job": job.to_dict()})


process_manager = ProcessManager()
