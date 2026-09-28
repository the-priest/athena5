"""
unblock — tell SLOW apart from STUCK, and never throw away work.

WHY THIS EXISTS
===============
Everything in this codebase that could hang was wearing a wall-clock timeout.
A wall clock cannot tell the difference between these two processes:

    nmap -p- 10.0.0.0/24     # 25 minutes of real work, silent for stretches
    curl https://dead.host   # 25 minutes of nothing, waiting on a socket

So it killed both at the same number, and — worse — `tool_run_command` threw
away everything the first one had produced:

    except subprocess.TimeoutExpired:
        return {"ok": False, "rc": 124, "timed_out": True, "error": ...}

`TimeoutExpired.stdout` is populated by CPython and holds every byte the
process wrote. That handler never reads it. A scan that found 200 hosts and
then stalled on the last one reported NOTHING, so the agent started over and
paid for the whole scan again. That is the "it times out and it's back on 0"
failure, and it is a discarded-data bug wearing a timeout costume.

WHAT REPLACES IT
================
Supervision by PROGRESS, not by elapsed time:

  * A process writing output is working. Don't touch it.
  * A process burning CPU is working even in total silence — that is a
    compile, a hash crack, a crypto operation. Don't touch it.
  * A process that is silent AND has flat CPU is the only candidate for being
    stuck, and even then it usually isn't: DNS retries, TCP backoff and rate
    limiters all look exactly like that for tens of seconds.

There is NO wall-clock limit here. A job may run for a week if it keeps making
progress. The only clock is the STALL clock, and any sign of life resets it.

When something really has stalled, the response is a ladder that tries to
UNSTICK it before it ever considers stopping it:

  1. NOTICE   — record the stall, keep waiting. Most resolve themselves.
  2. UNBLOCK  — diagnose it. The commonest real stall is a process blocked
                reading stdin: a tool hit an interactive prompt the agent never
                anticipated ("Continue? [y/N]", a passphrase, `less`). That is
                not a timeout, it is a question nobody answered, and closing
                stdin or answering it lets the job finish. THIS is the actual
                unblocking, and a timeout can never do it.
  3. HARVEST  — if it is still stuck, take everything captured so far and hand
                it back marked `partial`, with a diagnosis of what stalled and
                where. The agent gets the 200 hosts AND is told the last one
                hung. It never restarts from zero.

Only after all three does the process get stopped, and even then the output
goes back in full. Stopping is bookkeeping at that point, not the answer.

DESIGN CONTRACT
===============
Same as the rest of basilisk_ext: imports nothing from basilisk.py,
basilisk_core.py or basilisk_persona.py. Pure stdlib. Linux-native (this is a
GTK4 Linux app) but every /proc read degrades to "unknown" rather than raising,
so it still runs where /proc is absent — it simply falls back to output-only
progress detection.
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from typing import Any, Callable, Dict, List, Optional

# How long a process may be COMPLETELY quiet — no output, no CPU — before we
# start treating it as possibly stuck. Generous: DNS retry, TCP backoff and
# server-side rate limiting all look identical to a stall for this long, and
# intervening in those cases would break correct behaviour.
STALL_NOTICE_S = 45.0

# After this much continuous silence we try to UNBLOCK it (see _diagnose).
STALL_UNBLOCK_S = 90.0

# After this much, harvest whatever we have and stop waiting. This is NOT a
# task timeout — the clock only ever advances while nothing at all is
# happening, so a job that keeps working never reaches it.
STALL_HARVEST_S = 240.0

# Poll interval for the supervisor loop. Cheap: two small /proc reads.
POLL_S = 0.5

# Ceiling on captured output so a runaway `yes` can't exhaust RAM. Generous,
# and when it trips we keep the HEAD and the TAIL — the head has the context
# and the tail has whatever it was doing when it went wrong.
MAX_CAPTURE_BYTES = 8 * 1024 * 1024


def _read_cpu_jiffies(pid: int) -> Optional[int]:
    """utime+stime for one pid, or None when /proc is unreadable.

    This is the measurement that makes silent-but-working distinguishable from
    silent-and-dead, which is the whole basis for not needing a wall clock.
    """
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            data = f.read()
        # The comm field is parenthesised and may itself contain spaces or
        # parentheses, so split on the LAST ')' rather than tokenising blind.
        rest = data[data.rindex(b")") + 2:].split()
        return int(rest[11]) + int(rest[12])       # utime, stime
    except Exception:
        return None


def _pids_in_group(pgid: int) -> List[int]:
    """Every pid in the process group.

    A shell command is usually a tree — `make` spawns compilers, a pipeline
    spawns each stage. Measuring only the direct child would call a busy build
    'stalled' the moment the shell itself went idle waiting on its children.
    """
    out = []
    try:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                if os.getpgid(int(entry)) == pgid:
                    out.append(int(entry))
            except Exception:
                continue
    except Exception:
        return out
    return out


def _group_cpu(pgid: int, fallback_pid: int) -> Optional[int]:
    pids = _pids_in_group(pgid) or [fallback_pid]
    total = 0
    seen = False
    for pid in pids:
        j = _read_cpu_jiffies(pid)
        if j is not None:
            total += j
            seen = True
    return total if seen else None


def _proc_state(pid: int) -> str:
    """R/S/D/Z/T, or '?' — the kernel's own view of what this process is doing."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            data = f.read()
        return data[data.rindex(b")") + 2:].split()[0].decode()
    except Exception:
        return "?"


def _waiting_on_stdin(pid: int) -> bool:
    """True when this process is blocked READING ITS STDIN.

    The single most valuable thing this module detects. An interactive prompt
    the agent didn't anticipate — `apt` asking to continue, ssh asking to trust
    a host key, a passphrase, a pager — presents as a process that produced
    some output and then went silent forever. A timeout kills it and reports
    failure. What it actually needed was an answer.
    """
    try:
        # fd 0 still open and pointing at our pipe, and the task is in an
        # interruptible sleep inside a read.
        if _proc_state(pid) not in ("S", "D"):
            return False
        wchan = ""
        try:
            with open(f"/proc/{pid}/wchan", "rb") as f:
                wchan = f.read().decode("ascii", "replace")
        except Exception:
            pass
        if any(k in wchan for k in ("pipe_read", "pipe_wait", "wait_woken",
                                    "do_select", "read")):
            return True
        # Fall back to the syscall number: 0 is read(2) on x86-64/arm64.
        try:
            with open(f"/proc/{pid}/syscall", "rb") as f:
                parts = f.read().split()
            if parts and parts[0].isdigit() and int(parts[0]) == 0:
                # arg0 == fd; 0 means stdin
                return len(parts) > 1 and parts[1] in (b"0x0", b"0")
        except Exception:
            pass
    except Exception:
        pass
    return False


class Capture:
    """Accumulates output continuously so it is never lost.

    The entire point: whatever happens to the process, every byte it managed to
    write is already here and goes back to the model.
    """

    def __init__(self, limit: int = MAX_CAPTURE_BYTES) -> None:
        self._buf: List[bytes] = []
        self._n = 0
        self._limit = max(64 * 1024, limit)
        self._truncated = False
        self._tail: List[bytes] = []
        self.bytes_seen = 0
        self._lock = threading.Lock()

    def feed(self, chunk: bytes) -> None:
        if not chunk:
            return
        with self._lock:
            self.bytes_seen += len(chunk)
            if self._n < self._limit:
                self._buf.append(chunk)
                self._n += len(chunk)
            else:
                # Past the cap: keep a rolling TAIL. The head explains what the
                # command was doing; the tail shows where it got to.
                self._truncated = True
                self._tail.append(chunk)
                tl = sum(len(c) for c in self._tail)
                while tl > 256 * 1024 and len(self._tail) > 1:
                    tl -= len(self._tail.pop(0))

    def text(self) -> str:
        with self._lock:
            head = b"".join(self._buf)
            tail = b"".join(self._tail)
            trunc = self._truncated
        s = head.decode("utf-8", "replace")
        if trunc:
            s += ("\n\n[... output exceeded the capture cap; middle omitted, "
                  "end follows ...]\n\n") + tail.decode("utf-8", "replace")
        return s


class SupervisedResult(dict):
    """A dict so callers can treat it exactly like tool_run_command's result."""


def run_supervised(
    command: str,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    stdin_data: Optional[str] = None,
    on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    stall_notice_s: float = STALL_NOTICE_S,
    stall_unblock_s: float = STALL_UNBLOCK_S,
    stall_harvest_s: float = STALL_HARVEST_S,
    max_wall_s: Optional[float] = None,
) -> SupervisedResult:
    """Run a shell command under progress supervision.

    There is deliberately no default wall-clock limit. `max_wall_s` exists only
    so a caller with a genuine external deadline can impose one; leave it None
    and a job that keeps making progress runs to completion however long that
    takes, which is the correct behaviour for a scan or a build.

    Always returns output, whatever happened. Keys:
        ok, rc, stdout, stderr, command
        partial      - True when we stopped waiting before it exited
        stalled      - True when it went quiet and stayed quiet
        unblocked    - what intervention was applied, if any
        diagnosis    - plain text for the model: what happened and what to do
        elapsed_s, cpu_moved, bytes_out
    """
    def emit(kind: str, **kw):
        if on_event:
            try:
                on_event(kind, kw)
            except Exception:
                pass

    out_cap, err_cap = Capture(), Capture()
    started = time.monotonic()

    try:
        proc = subprocess.Popen(
            command, shell=True,
            cwd=cwd or os.path.expanduser("~"),
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,        # own process group: see _pids_in_group
        )
    except Exception as e:
        return SupervisedResult(
            ok=False, command=command, rc=None, stdout="", stderr="",
            error=f"{type(e).__name__}: {e}", partial=False, stalled=False,
            diagnosis=f"the command could not be started: {e}")

    try:
        pgid = os.getpgid(proc.pid)
    except Exception:
        pgid = proc.pid

    if stdin_data:
        def _feed_stdin():
            try:
                proc.stdin.write(stdin_data.encode())
                proc.stdin.flush()
            except Exception:
                pass
            finally:
                try:
                    proc.stdin.close()
                except Exception:
                    pass
        threading.Thread(target=_feed_stdin, daemon=True).start()

    def _pump(stream, cap):
        # read1(), NOT read(). BufferedReader.read(n) blocks until it has all n
        # bytes or hits EOF, so output only landed when the process EXITED —
        # which made bytes_seen flat for the whole run and defeated the entire
        # progress detector. read1() returns whatever is available now, which is
        # what "is it still producing output?" actually needs.
        reader = getattr(stream, "read1", None) or stream.read
        try:
            while True:
                chunk = reader(65536)
                if not chunk:
                    break
                cap.feed(chunk)
        except Exception:
            pass
        finally:
            try:
                stream.close()
            except Exception:
                pass

    t_out = threading.Thread(target=_pump, args=(proc.stdout, out_cap), daemon=True)
    t_err = threading.Thread(target=_pump, args=(proc.stderr, err_cap), daemon=True)
    t_out.start()
    t_err.start()

    last_bytes = 0
    last_cpu = _group_cpu(pgid, proc.pid)
    last_progress = time.monotonic()
    cpu_ever_moved = False
    noticed = unblocked_at = False
    intervention = None
    stalled = False

    while True:
        rc = proc.poll()
        if rc is not None:
            break

        time.sleep(POLL_S)
        now = time.monotonic()

        # ── progress detection ──
        moved = False
        cur_bytes = out_cap.bytes_seen + err_cap.bytes_seen
        if cur_bytes != last_bytes:
            last_bytes = cur_bytes
            moved = True
        cur_cpu = _group_cpu(pgid, proc.pid)
        if cur_cpu is not None and last_cpu is not None and cur_cpu != last_cpu:
            moved = True
            cpu_ever_moved = True
        if cur_cpu is not None:
            last_cpu = cur_cpu

        if moved:
            # ANY sign of life resets the stall clock completely. This is the
            # difference between supervision and a timeout.
            if stalled:
                emit("resumed", after_s=round(now - last_progress, 1))
            last_progress = now
            noticed = False
            stalled = False
            continue

        quiet_for = now - last_progress
        if max_wall_s and (now - started) > max_wall_s:
            intervention = intervention or "wall limit reached"
            break

        # ── tier 1: NOTICE ──
        if quiet_for >= stall_notice_s and not noticed:
            noticed = True
            stalled = True
            emit("stalled", quiet_for_s=round(quiet_for, 1),
                 state=_proc_state(proc.pid))

        # ── tier 2: UNBLOCK ──
        if quiet_for >= stall_unblock_s and not unblocked_at:
            unblocked_at = True
            if _waiting_on_stdin(proc.pid):
                # It is asking a question nobody answered. Close stdin so the
                # read returns EOF — most tools then take their default or
                # abort cleanly, and either way the job MOVES. A timeout could
                # only ever have killed it.
                intervention = ("process was blocked reading stdin (an "
                                "interactive prompt); stdin was closed to "
                                "release it")
                emit("unblocking", how="close-stdin")
                try:
                    proc.stdin.close()
                except Exception:
                    pass
                last_progress = time.monotonic()   # give it a fresh chance
                continue
            emit("unblock_failed", state=_proc_state(proc.pid))

        # ── tier 3: HARVEST ──
        if quiet_for >= stall_harvest_s:
            intervention = intervention or "no progress; harvested and stopped"
            emit("harvesting", quiet_for_s=round(quiet_for, 1))
            break

    # If we broke out while it was still running, stop the whole group — but
    # the output is already captured, so nothing is lost either way.
    partial = proc.poll() is None
    if partial:
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(pgid, sig)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            try:
                proc.wait(timeout=3)
                break
            except Exception:
                continue

    t_out.join(timeout=2)
    t_err.join(timeout=2)
    rc = proc.poll()
    elapsed = time.monotonic() - started

    stdout, stderr = out_cap.text(), err_cap.text()
    diagnosis = _diagnose(command, partial, stalled, intervention, elapsed,
                          out_cap.bytes_seen + err_cap.bytes_seen,
                          cpu_ever_moved, stdout)

    return SupervisedResult(
        ok=(not partial and rc == 0),
        command=command, rc=rc, stdout=stdout, stderr=stderr,
        partial=partial, stalled=stalled, unblocked=intervention,
        diagnosis=diagnosis, elapsed_s=round(elapsed, 1),
        cpu_moved=cpu_ever_moved,
        bytes_out=out_cap.bytes_seen + err_cap.bytes_seen)


def _diagnose(command: str, partial: bool, stalled: bool,
              intervention: Optional[str], elapsed: float, nbytes: int,
              cpu_moved: bool, stdout: str) -> str:
    """Explain the outcome to the MODEL, in terms it can act on.

    "Timed out" tells it nothing except to give up or retry identically, which
    is how a run ends up repeating a twenty-minute scan. What it needs is:
    what came back, what stalled, and what specifically to do differently.
    """
    if not partial:
        return ""
    lines = [f"The command was STOPPED after {elapsed:.0f}s because it stopped "
             f"making progress. This is NOT a clean failure and NOT a timeout "
             f"on the work itself."]
    if nbytes:
        lines.append(
            f"IMPORTANT: {nbytes} bytes of real output were produced BEFORE it "
            f"stalled and are included above. That work is done — use it. Do "
            f"NOT re-run this command from the start.")
    else:
        lines.append("It produced no output at all before stalling.")
    if intervention:
        lines.append(f"Intervention attempted: {intervention}.")
    if cpu_moved:
        lines.append("It was using CPU earlier, so it was doing real work and "
                     "then got stuck — most likely on one specific item.")
    else:
        lines.append("It never used measurable CPU, so it was almost certainly "
                     "waiting on something external: a host that never "
                     "answered, a DNS lookup, or a prompt.")
    lines.append(
        "Next move: narrow the scope so the stuck part is excluded (a smaller "
        "range, a shorter list, one target at a time), or add the tool's own "
        "timeout/retry flag, or pick up from where the output above ends. "
        "Re-issuing the identical command will stall in the identical place.")
    return "\n".join(lines)


def salvage_timeout(exc, command: str, timeout: float) -> Dict[str, Any]:
    """Rescue output from a subprocess.TimeoutExpired instead of binning it.

    CPython populates TimeoutExpired.stdout/.stderr with everything the process
    wrote. The old handler in tool_run_command never looked, so a scan that
    found two hundred hosts and then hung reported nothing at all and the agent
    started over. This is the minimal fix for any caller still using
    subprocess.run — run_supervised is the real answer, but no output should be
    thrown away anywhere.
    """
    def _dec(v):
        if v is None:
            return ""
        if isinstance(v, bytes):
            return v.decode("utf-8", "replace")
        return str(v)

    out, err = _dec(getattr(exc, "stdout", None)), _dec(getattr(exc, "stderr", None))
    n = len(out) + len(err)
    note = [f"The command was stopped after {timeout:.0f}s without finishing."]
    if n:
        note.append(f"{n} characters of output HAD already been produced and "
                    f"are included — that work is done, use it rather than "
                    f"re-running from the start.")
    else:
        note.append("It produced no output before it was stopped.")
    note.append("Narrow the scope or pick up from where the output ends; the "
                "identical command will stall in the identical place.")
    return {"ok": False, "command": command, "rc": 124, "timed_out": True,
            "partial": True, "stdout": out, "stderr": err,
            "bytes_out": n, "diagnosis": "\n".join(note)}
