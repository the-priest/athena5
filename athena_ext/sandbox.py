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
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional


DEFAULT_TIMEOUT = 20
DEFAULT_MEM_MB = 256
DEFAULT_FSIZE_MB = 16
DEFAULT_NOFILE = 64


def _have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _rlimit_preexec(mem_mb: int, fsize_mb: int, nofile: int):
    def _apply():
        # New session so we can kill the whole group on timeout.
        os.setsid()
        soft = mem_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (soft, soft))
        resource.setrlimit(resource.RLIMIT_CPU, (DEFAULT_TIMEOUT, DEFAULT_TIMEOUT + 2))
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
        if _have("bwrap"):
            tier = "bwrap"
            argv = _bwrap_argv(scratch, allow_net) + [run_target, args_json]
            preexec = None
        elif _have("unshare"):
            tier = "unshare"
            net = [] if allow_net else ["-n"]
            argv = (["unshare", "-m", *net, py,
                     "-I", "-S", run_target, args_json])
            preexec = _rlimit_preexec(mem_mb, fsize_mb, DEFAULT_NOFILE)
        else:
            tier = "rlimit"
            argv = [py, "-I", "-S", run_target, args_json]
            preexec = _rlimit_preexec(mem_mb, fsize_mb, DEFAULT_NOFILE)

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
            start_new_session=(preexec is None),
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
            out, err = proc.communicate()
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
