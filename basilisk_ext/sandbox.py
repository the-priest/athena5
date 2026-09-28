"""
sandbox — run untrusted, agent-written Python out-of-process under the
strongest isolation available on the box.

READ THIS, it is the whole point of the feature:

  In-process execution of model-written code is NOT containable.  A stripped
  __builtins__ / "RestrictedPython" sandbox in the same interpreter is theatre
  — CPython has too many escape hatches (object graph walks, gc, frame
  introspection, c-extension reentry).  Anyone who tells you otherwise is
  wrong.  So this module never exec()s skill code in Basilisk's process.  It
  always spawns a fresh `python3 -I -S` child and isolates THAT.

Isolation tiers, best first; we use the best one present:

  1. bubblewrap (`bwrap`) — user namespaces.  Read-only bind of the python
     runtime, a fresh tmpfs /tmp, a single writable scratch dir, NO network
     (--unshare-net), no access to $HOME / .ssh / the rest of the FS.  This is
     the real boundary and it needs no root on a modern kernel.
  2. `unshare -n -m` + setrlimit — network namespace off, mount namespace,
     plus hard resource caps.  Weaker FS isolation than bwrap but still no
     network and still capped.
  3. setrlimit only (last resort) — CPU/mem/file-size/open-files caps and a
     scrubbed env in a throwaway cwd.  This bounds damage; it does NOT confine
     the filesystem.  If you are on a box where only this is available, treat
     skills as "code you'd run yourself", i.e. still gate every save.

Every tier adds: wall-clock timeout (parent-enforced kill), scrubbed
environment, CPU + address-space + file-size + open-file rlimits, and
stdin closed.  Network is OFF unless the skill was approved with the "net"
capability AND the host passes allow_net=True.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

# `resource`, os.setsid, os.killpg and os.getpgid are all POSIX-only.  This was
# a bare `import resource` at module scope, and the consequence was much larger
# than this file: skills.py imports sandbox, extman.py imports skills, and
# basilisk_ext/__init__ imports extman — so on Windows the ImportError took out
# the ENTIRE sidecar package.  Workspace, recall, memory, oracle, bench and
# headroom all vanished, silently, because basilisk.py's ext import is
# (correctly) guarded and just leaves self._ext = None.
#
# CI publishes a Windows EXE, so that platform is not hypothetical.
try:
    import resource                      # type: ignore
    _POSIX_LIMITS = True
except ImportError:                      # pragma: no cover - Windows
    resource = None                      # type: ignore
    _POSIX_LIMITS = False


DEFAULT_TIMEOUT = 20
DEFAULT_MEM_MB = 256
DEFAULT_FSIZE_MB = 16
DEFAULT_NOFILE = 64


def _have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _rlimit_preexec(mem_mb: int, fsize_mb: int, nofile: int,
                    cpu_seconds: int = DEFAULT_TIMEOUT):
    """Build the pre-exec hook that caps the child's resources.

    `cpu_seconds` is passed in rather than read from DEFAULT_TIMEOUT, which is
    what it used to do: a caller asking for `run_python(..., timeout=60)` still
    got a 20-second CPU rlimit, so a legitimately long skill was killed by
    SIGXCPU at a third of its allowance and reported as a skill failure rather
    than as a limit being hit.  The wall-clock timeout and the CPU limit are
    now the same number by construction.
    """
    def _apply():
        # New session so we can kill the whole group on timeout.
        os.setsid()
        if not _POSIX_LIMITS:            # pragma: no cover - Windows
            return
        soft = mem_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (soft, soft))
        resource.setrlimit(resource.RLIMIT_CPU,
                           (cpu_seconds, cpu_seconds + 2))
        fz = fsize_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_FSIZE, (fz, fz))
        resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, nofile))
        try:
            resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
        except (ValueError, OSError):
            pass
    return _apply


def _scrubbed_env(scratch: str, allow_net: bool) -> Dict[str, str]:
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": scratch,
        "TMPDIR": scratch,
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    }
    if not allow_net:
        # Belt-and-braces for the rlimit-only tier where we can't drop the
        # net namespace: most libs honour these.  Real enforcement is the
        # namespace in tiers 1/2.
        env["http_proxy"] = env["https_proxy"] = "http://127.0.0.1:1"
        env["no_proxy"] = ""
    return env


def _bwrap_argv(scratch: str, allow_net: bool) -> List[str]:
    py = sys.executable or "/usr/bin/python3"
    argv = [
        "bwrap",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind", "/bin", "/bin",
        "--ro-bind", "/lib", "/lib",
        "--symlink", "usr/lib64", "/lib64",
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
        "--bind", scratch, scratch,
        "--chdir", scratch,
        "--unshare-pid",
        "--unshare-uts",
        "--unshare-ipc",
        "--die-with-parent",
        "--new-session",
    ]
    # The interpreter may live outside /usr (a venv, pyenv, or /opt build).  If
    # so, the ro-binds above don't cover it and the sandbox can't find python at
    # all — the child dies before running a line.  Bind its install prefix
    # read-only when it isn't already on one of the bound roots.  Dedup so we
    # never hand bwrap the same path twice.
    seen = set()
    for root in (os.path.dirname(py), getattr(sys, "base_prefix", ""),
                 sys.prefix):
        if (root and root not in seen and os.path.isdir(root)
                and not root.startswith(("/usr", "/bin", "/lib"))):
            seen.add(root)
            argv += ["--ro-bind", root, root]
    if not allow_net:
        argv.append("--unshare-net")
    argv += [py, "-I", "-S"]
    return argv


def run_python(code_path: str,
               args_json: str = "{}",
               timeout: int = DEFAULT_TIMEOUT,
               allow_net: bool = False,
               mem_mb: int = DEFAULT_MEM_MB,
               fsize_mb: int = DEFAULT_FSIZE_MB) -> Dict[str, Any]:
    """Execute the script at code_path in isolation.

    The script receives its arguments as a JSON string on argv[1] and should
    print its result to stdout (JSON encouraged).  Returns:
        {ok, tier, rc, stdout, stderr, timed_out, duration}
    """
    code_path = os.path.abspath(code_path)
    scratch = tempfile.mkdtemp(prefix="basilisk-skill-")
    tier = "rlimit"
    try:
        # The ONLY directory bound writable into the bwrap sandbox is `scratch`.
        # The caller's script lives elsewhere (under the skills dir), which is
        # NOT mounted inside the namespace — so under bwrap the child could
        # never open it and every skill failed with "No such file or directory".
        # Stage the script INTO scratch and execute the in-scratch copy; that
        # path is valid both outside and inside every isolation tier.
        run_target = os.path.join(scratch, "skill_main.py")
        try:
            shutil.copyfile(code_path, run_target)
        except OSError as e:
            return {"ok": False, "tier": tier, "rc": -1, "stdout": "",
                    "stderr": f"could not stage skill: {e}",
                    "timed_out": False, "duration": 0.0}
        py = sys.executable or "/usr/bin/python3"
        if not _POSIX_LIMITS:            # pragma: no cover - Windows
            # No rlimits, no setsid, no killpg, and neither bwrap nor unshare
            # exists here.  There is no isolation available AT ALL, and the one
            # thing this module must never do is run model-written code with
            # nothing around it — the module docstring is explicit that
            # in-process/unconfined execution is not containable.  Refuse
            # loudly instead of silently downgrading to "just run it".
            return {"ok": False, "tier": "none", "rc": -1, "stdout": "",
                    "stderr": ("sandbox: this platform provides no isolation "
                               "primitives (no resource limits, no namespaces) "
                               "— refusing to execute agent-written code "
                               "unconfined"),
                    "timed_out": False, "duration": 0.0}
        # RLIMITS ON EVERY TIER, including bwrap.
        # bwrap used to run with preexec=None, so the STRONGEST isolation tier
        # was the only one with no resource caps: it confines the filesystem
        # and the network but does nothing about memory, CPU or file size, so a
        # runaway skill could exhaust the box precisely when the operator had
        # the best sandbox installed.  The module docstring promised "every
        # tier adds ... rlimits"; now it is true.
        preexec = _rlimit_preexec(mem_mb, fsize_mb, DEFAULT_NOFILE,
                                  cpu_seconds=max(1, int(timeout)))
        if _have("bwrap"):
            tier = "bwrap"
            argv = _bwrap_argv(scratch, allow_net) + [run_target, args_json]
        elif _have("unshare"):
            tier = "unshare"
            net = [] if allow_net else ["-n"]
            argv = (["unshare", "-m", *net, py,
                     "-I", "-S", run_target, args_json])
        else:
            tier = "rlimit"
            argv = [py, "-I", "-S", run_target, args_json]

        import time as _t
        t0 = _t.time()
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_scrubbed_env(scratch, allow_net),
            cwd=scratch,
            preexec_fn=preexec,
            # setsid() happens inside the preexec hook (which every tier now
            # has), and it must happen exactly ONCE.  Do not "simplify" this to
            # True: CPython runs start_new_session's setsid BEFORE preexec_fn,
            # so the hook's own setsid would then fail with EPERM — already a
            # session leader — and the child would die before exec.  The old
            # `preexec is None` here was load-bearing for the same reason.
            start_new_session=False,
            text=True,
        )
        timed_out = False
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                proc.kill()
            # Bound the post-kill drain. killpg normally reaps the whole
            # session, but if that fell through to proc.kill() a grandchild
            # can still hold the pipes open and an unbounded communicate()
            # would block this worker thread forever.
            try:
                out, err = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                out, err = "", "sandbox: process did not exit after kill"
        dur = round(_t.time() - t0, 3)
        return {
            "ok": (proc.returncode == 0 and not timed_out),
            "tier": tier,
            "rc": proc.returncode,
            "stdout": (out or "")[:20000],
            "stderr": (err or "")[:8000],
            "timed_out": timed_out,
            "duration": dur,
        }
    except Exception as e:
        return {"ok": False, "tier": tier, "rc": -1, "stdout": "",
                "stderr": f"{type(e).__name__}: {e}", "timed_out": False,
                "duration": 0.0}
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def capabilities_report() -> Dict[str, Any]:
    """What isolation this box can actually give a skill."""
    if _have("bwrap"):
        tier = "bwrap (namespaces, fs-confined, net-off)"
    elif _have("unshare"):
        tier = "unshare (net-off, rlimits, weak fs)"
    else:
        tier = "rlimit-only (bounded, NOT fs-confined)"
    try:
        from basilisk_core import install_hint as _ih
        _bwrap_cmd = _ih("bubblewrap")
    except Exception:
        _bwrap_cmd = "sudo apt install bubblewrap"
    return {"tier": tier,
            "bwrap": _have("bwrap"),
            "unshare": _have("unshare"),
            "advice": f"install bubblewrap for real isolation: {_bwrap_cmd}"}
